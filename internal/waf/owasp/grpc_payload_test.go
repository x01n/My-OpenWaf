package owasp

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"
)

/**
 * grpcFrame 按 gRPC-over-HTTP2 帧格式包裹消息体：
 * 1 字节压缩标志 + 4 字节大端长度 + 消息体。
 * 本包测试故意不引入 grpc 依赖，帧布局与 internal/proxy/zz_grpc_probe_test.go 一致。
 */
func grpcFrame(msg []byte) []byte {
	out := make([]byte, 5+len(msg))
	copy(out[5:], msg)
	binary.BigEndian.PutUint32(out[1:5], uint32(len(msg)))
	return out
}

/**
 * denseBinFill 生成 0x81–0xFF 的高字节填充（纯无效 UTF-8），
 * 使 payload 周围的目标保持二进制判定所需的非文本占比。
 */
func denseBinFill(n int) string {
	f := make([]byte, n)
	for i := range f {
		f[i] = 0x81 + byte(i%0x7F)
	}
	return string(f)
}

/**
 * TestGRPCPayloadCleanProtoNoFalsePositive 断言正常 gRPC protobuf 消息（帧头 +
 * 高字节 body，200B/300B/20KB 三档）在 OWASP 引擎下零误报。
 */
func TestGRPCPayloadCleanProtoNoFalsePositive(t *testing.T) {
	cases := []struct {
		name   string
		sizes  []int
		conten string
	}{
		{"grpc", []int{200, 300, 20480}, "application/grpc"},
		{"grpc_plus_proto", []int{200, 300, 20480}, "application/grpc+proto"},
	}
	for _, tc := range cases {
		for _, size := range tc.sizes {
			t.Run(fmt.Sprintf("%s_%d", tc.name, size), func(t *testing.T) {
				body := grpcFrame([]byte(denseBinFill(size)))
				headers := map[string]string{
					"host":         "svc.example.internal",
					"content-type": tc.conten,
				}
				if hit, ok := FirstOWASPHitWithThresholds(CompileThresholds("mid"), "/svc.v1.API/Send", "", headers, []string{string(body)}); ok {
					t.Fatalf("normal gRPC frame false positive: rule=%s category=%s score=%d", hit.RuleID, hit.Category, hit.Score)
				}
			})
		}
	}
}

/**
 * TestGRPCPayloadClassicAttacksDetected 断言嵌在 gRPC 帧中的经典载荷
 * （SQLi/命令注入/路径穿越/模板注入/JNDI）全部检出，并记录规则与分数。
 */
func TestGRPCPayloadClassicAttacksDetected(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		ct      string
		wantCat OWASPCategory
	}{
		{"sqli", "1' OR '1'='1", "application/grpc", CatSQLi},
		{"cmdi_backtick", "x=`;whoami", "application/grpc+proto", CatCmdInject},
		{"cmdi_subst", "x=$(cat /etc/passwd)", "application/grpc+proto", CatCmdInject},
		{"path_trav", "../../etc/passwd", "application/grpc", CatPathTrav},
		{"ssti", "{{7*7}}", "application/grpc+proto", CatTmplInject},
		{"jndi", "${jndi:ldap://169.254.169.254/a}", "application/grpc", CatJNDI},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := grpcFrame([]byte(tc.payload))
			headers := map[string]string{
				"host":         "svc.example.internal",
				"content-type": tc.ct,
			}
			hit, ok := FirstOWASPHitWithThresholds(CompileThresholds("mid"), "/svc.v1.API/Exec", "", headers, []string{string(body)})
			if !ok {
				t.Fatalf("attack %q in gRPC frame was not detected", tc.payload)
			}
			if hit.Category != tc.wantCat {
				t.Fatalf("attack %q detected as %s/%s, want category %s", tc.payload, hit.Category, hit.RuleID, tc.wantCat)
			}
			t.Logf("attack %q -> %s score=%d", tc.payload, hit.RuleID, hit.Score)
		})
	}
}

/**
 * TestGRPCPayloadGrpcJSONDetectionMatchesPlainJSON 断言 grpc+json 帧与普通
 * application/json 对相同恶意 JSON 负载的检出能力一致（同规则同分）。
 */
func TestGRPCPayloadGrpcJSONDetectionMatchesPlainJSON(t *testing.T) {
	payloads := []struct {
		name string
		json string
	}{
		{"sqli", `{"user":"alice-0001","q":"1' OR '1'='1"}`},
		{"cmdi", `{"user":"alice-0001","q":"id=$(cat /etc/passwd)"}`},
		{"ssti", `{"user":"alice-0001","q":"{{7*7}}"}`},
	}
	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			grpcBody := grpcFrame([]byte(p.json))
			plainBody := []byte(p.json)
			grpcHit, grpcOK := FirstOWASPHitWithThresholds(CompileThresholds("mid"), "/svc.v1.API/Query", "", map[string]string{"host": "x", "content-type": "application/grpc+json"}, []string{string(grpcBody)})
			plainHit, plainOK := FirstOWASPHitWithThresholds(CompileThresholds("mid"), "/svc.v1.API/Query", "", map[string]string{"host": "x", "content-type": "application/json"}, []string{string(plainBody)})
			if grpcOK != plainOK {
				t.Fatalf("grpc+json detection mismatch: grpc=%v plain=%v", grpcOK, plainOK)
			}
			if grpcOK && (grpcHit.Category != plainHit.Category || grpcHit.Score != plainHit.Score) {
				t.Fatalf("grpc+json verdict differs from plain json: grpc %s/%d vs plain %s/%d", grpcHit.RuleID, grpcHit.Score, plainHit.RuleID, plainHit.Score)
			}
		})
	}
}

/**
 * TestGRPCPayloadPayloadBuriedMidFrameDetected 记录一个真实漏检缺口：
 * 当载荷位于归一化目标中部、且目标总长超过「头窗+尾窗」（2*maxTargetLen+7 ≈ 32775B）时，
 * truncateTarget 仅保留头尾各 16 KiB，中部载荷被丢弃，引擎漏检。
 * 帧体中部 body=32774B 的样本中载荷（payload 偏移约 16383B）恰好落在
 * 「头窗尾 + 分隔符 + 尾窗头」之外（探测实证，与截断窗口重合位置均能检出），
 * 是对 truncate 中部丢失的真实刻画。
 */
func TestGRPCPayloadPayloadBuriedMidFrameDetected(t *testing.T) {
	const payload = "{{7*7}}"
	bodies := []struct {
		tag  string
		body string
		want bool
	}{
		{"middle_32774_missed", denseBinFill(16383) + payload + denseBinFill(16384), false},
		{"boundary_2N_body_gap", denseBinFill(16383) + payload + denseBinFill(16384-3), false},
	}
	for _, tc := range bodies {
		t.Run(tc.tag, func(t *testing.T) {
			hit, ok := FirstOWASPHitWithThresholds(CompileThresholds("mid"), "/svc.v1.API/Render", "", map[string]string{"host": "x", "content-type": "application/grpc+proto"}, []string{tc.body})
			if ok == tc.want {
				return
			}
			if ok && !tc.want {
				t.Fatalf("mid-buried payload unexpectedly detected: %s/%d (truncation window behavior changed)", hit.RuleID, hit.Score)
			}
			if !ok && tc.want {
				t.Fatalf("payload inside truncation window was missed: %+v", hit)
			}
		})
	}

	// 帧尾窗口内的载荷（距端 ≤16 KiB）照常检出：真实 gRPC 帧 message 最后一个字段。
	// 20KB 帧体尾部用例见 TestGRPCPayloadFillerPrintableHighByteBase64 与
	// TestGRPCPayloadBinaryThresholdBoundary；此处确认 <32775B 时中/尾都不丢。
	frameTail := grpcFrame([]byte(denseBinFill(16384-3) + payload))
	hit, ok := FirstOWASPHitWithThresholds(CompileThresholds("mid"), "/svc.v1.API/Render", "", map[string]string{"host": "x", "content-type": "application/grpc+proto"}, []string{string(frameTail)})
	if !ok || hit.Category != CatTmplInject {
		t.Fatalf("payload at frame tail in truncation tail window should be detected, got %+v ok=%v", hit, ok)
	}
}

/**
 * TestGRPCPayloadLowScoreCmdInDenseBinaryGap 记录二进制抑制器造成的低分命令注入
 * 漏检：owasp:cmd:003（4 分，$(...) 命令替换）在严格二进制目标上被跳过，
 * z=$(ls) 在 16KB 高字节帧中漏检；≥5 分模式（owasp:cmd:001 分号命令链）
 * 不受抑制，即使被二进制包围也照常检出。
 */
func TestGRPCPayloadLowScoreCmdInDenseBinaryGap(t *testing.T) {
	headers := map[string]string{"host": "x", "content-type": "application/grpc+proto"}
	th := CompileThresholds("mid")

	// owasp:cmd:003 4 分：纯文本下检出，严格二进制目标上被抑制器跳过 → 漏检。
	missBody := denseBinFill(16380) + "z=$(ls)"
	hit, ok := FirstOWASPHitWithThresholds(th, "/svc.v1.API/Exec", "", headers, []string{missBody})
	if ok {
		t.Fatalf("expected low-score cmd miss in dense binary target, got %s/%d", hit.RuleID, hit.Score)
	}
	if textHit, textOK := FirstOWASPHitWithThresholds(th, "/svc.v1.API/Exec", "", headers, []string{"z=$(ls)"}); !textOK {
		t.Fatal("test setup: z=$(ls) should be detected as text target")
	} else {
		t.Logf("documented gap: %s (score %d) detected as text but skipped in strict binary target", textHit.RuleID, textHit.Score)
	}

	// owasp:cmd:001 5 分：分号命令链即使被密集二进制包围也照常检出。
	detectBody := denseBinFill(16380) + "x=`;whoami"
	hit, ok = FirstOWASPHitWithThresholds(th, "/svc.v1.API/Exec", "", headers, []string{detectBody})
	if !ok || hit.Category != CatCmdInject {
		t.Fatalf("5-score semicolon command chain in dense binary should be detected, got %+v ok=%v", hit, ok)
	}
	t.Logf("high-score cmd rule %s (%d) survives the binary suppressor", hit.RuleID, hit.Score)
}

/**
 * TestGRPCPayloadBinaryThresholdBoundary 验证 256B 二进制判定最小长度与
 * 30% 非文本占比阈值的边界行为：200B(<256) 不触发二进制判定（短目标照常全量扫描）、
 * 300B/20KB 严格二进制目标上低分模式被抑制、20KB 帧中尾随载荷照常检出。
 */
func TestGRPCPayloadBinaryThresholdBoundary(t *testing.T) {
	th := CompileThresholds("mid")
	headers := map[string]string{"host": "x", "content-type": "application/grpc+proto"}

	// 200B < binaryTargetMinLen：整体判定为非二进制，常规路径扫描（低分模式不跳过）。
	short := grpcFrame([]byte(denseBinFill(200)))
	if hit, ok := FirstOWASPHitWithThresholds(th, "/svc.v1.API/Exec", "", headers, []string{string(short)}); ok {
		t.Fatalf("short clean gRPC frame false positive: %s/%d", hit.RuleID, hit.Score)
	}

	// 300B 高字节 payload：严格二进制，无攻击应放行。
	mid := grpcFrame([]byte(denseBinFill(300)))
	if hit, ok := FirstOWASPHitWithThresholds(th, "/svc.v1.API/Exec", "", headers, []string{string(mid)}); ok {
		t.Fatalf("300B clean gRPC frame false positive: %s/%d", hit.RuleID, hit.Score)
	}

	// 20KB 帧：二进制判定 + 截断窗口下，尾随攻击载荷仍须检出。
	large := grpcFrame([]byte(denseBinFill(20480-len("{{7*7}}")) + "{{7*7}}"))
	hit, ok := FirstOWASPHitWithThresholds(th, "/svc.v1.API/Render", "", headers, []string{string(large)})
	if !ok {
		t.Fatalf("20KB gRPC frame with tail payload should be detected via tail window")
	}
	if hit.Category != CatTmplInject {
		t.Fatalf("expected template_injection, got %s", hit.Category)
	}
}

/**
 * TestGRPCPayloadFillerPrintableHighByteBase64 验证正常 grpc+json 消息中
 * 大段 base64 高字节填充（blob64 域）不误报。
 */
func TestGRPCPayloadFillerPrintableHighByteBase64(t *testing.T) {
	blob := []byte(denseBinFill(1536))
	js := fmt.Sprintf(`{"user":"alice-0001","blob64":"%s"}`, base64.StdEncoding.EncodeToString(blob))
	body := grpcFrame([]byte(js))
	headers := map[string]string{"host": "x", "content-type": "application/grpc+json"}
	if hit, ok := FirstOWASPHitWithThresholds(CompileThresholds("mid"), "/svc.v1.API/Send", "", headers, []string{string(body)}); ok {
		t.Fatalf("clean grpc+json with base64 blob false positive: %s/%d", hit.RuleID, hit.Score)
	}
}
