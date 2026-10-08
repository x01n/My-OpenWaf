package dataplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/glebarez/sqlite"
	"github.com/klauspost/compress/zstd"
	"gorm.io/gorm"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/observability"
	"My-OpenWaf/internal/proxy"
	"My-OpenWaf/internal/store"
)

// 本文件锁定 H-6 第二轮的验收点：偷读窗口扩到 64 KiB 之后四种编码的大流式
// 压缩请求体都必须被检测层看见，并覆盖压缩体大小的三档边界、压缩炸弹降级、
// 以及降级必须留下审计事件。

// encodeZstdTest 用 zstd 压缩测试载荷。
func encodeZstdTest(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return buf.Bytes()
}

// decodeZstdTest 解开 zstd 载荷，用于断言上游收到的是可解码的原始压缩字节。
func decodeZstdTest(t *testing.T, body []byte) []byte {
	t.Helper()
	reader, err := zstd.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("zstd reader: %v", err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("zstd decompress: %v", err)
	}
	return decoded
}

// encodeBrotliTest 用 brotli 压缩测试载荷。
func encodeBrotliTest(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := brotli.NewWriter(&buf)
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}

// largeAttackPayload 构造「攻击载荷 + 不可压缩填充」的明文。
//
// attackAtTail 决定攻击落在最前还是最后：偷读前缀只覆盖压缩体开头，落在末尾
// 的攻击在「只解压内存前缀」的实现下必然不可见，两种位置都要覆盖。
func largeAttackPayload(t *testing.T, padBytes int, attackAtTail bool) (payload, attack []byte) {
	t.Helper()
	attack = []byte(`{"note":"<script>alert(1)</script>"}`)
	pad := make([]byte, padBytes)
	if _, err := rand.Read(pad); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if attackAtTail {
		payload = append(append([]byte{}, pad...), attack...)
	} else {
		payload = append(append([]byte{}, attack...), pad...)
	}
	return payload, attack
}

// compressedBodyEncoders 是四种受支持内容编码的测试编码器。
func compressedBodyEncoders() []struct {
	encoding string
	encode   func(*testing.T, []byte) []byte
} {
	return []struct {
		encoding string
		encode   func(*testing.T, []byte) []byte
	}{
		{encoding: "gzip", encode: encodeGzip},
		{encoding: "br", encode: encodeBrotliTest},
		{encoding: "deflate", encode: encodeZlib},
		{encoding: "zstd", encode: encodeZstdTest},
	}
}

/**
 * TestHandlerLargeCompressedBodyDetectedForAllEncodings 是本轮核心验收点：
 * 四种编码的大流式请求体（**压缩体落在 48 KiB 与 64 KiB 之间**，攻击在最前）
 * 都必须被拦截。
 *
 * 这个区间是本轮修的东西：压缩体超过旧的 48 KiB 窗口但仍在新的 64 KiB 窗口内
 * 时，gzip/br/deflate 在旧窗口下已能解出前缀（因此旧实现也拦得住），zstd 却
 * 因为「读到帧尾才吐数据」而一个字节都解不出来——正是被放行的那一个。窗口扩到
 * 64 KiB 后 zstd 也能解出前缀，四种编码在本区间内应当一致拦截。
 *
 * 填充必须不可压缩（crypto/rand）：可压缩填充会让压缩体远离窗口，测不到这条
 * 边界；132 KiB 那种「明确超窗」的形态另有 TestHandlerOverWindowCompressedBodyDegradesAndForwardsRaw 覆盖。
 */
func TestHandlerLargeCompressedBodyDetectedForAllEncodings(t *testing.T) {
	// 60 KiB 不可压缩填充：四种编码的压缩体都落在 61.4–61.5 KiB，即
	// (48 KiB, 64 KiB) 区间内。
	payload, _ := largeAttackPayload(t, 60*1024, false)

	for _, tc := range compressedBodyEncoders() {
		t.Run(tc.encoding, func(t *testing.T) {
			compressed := tc.encode(t, payload)
			if len(compressed) <= requestInspectionBodyLimit {
				t.Fatalf("测试前提不成立：压缩体 %d 字节未超过旧窗口 %d",
					len(compressed), requestInspectionBodyLimit)
			}
			if len(compressed) > requestBodySnapshotReadMaxSize {
				t.Fatalf("测试前提不成立：压缩体 %d 字节超出新窗口 %d",
					len(compressed), requestBodySnapshotReadMaxSize)
			}

			h := newCompressedBodyHarness(t)
			ctx := h.newRequest(t, compressed, tc.encoding)
			h.handler(context.Background(), ctx)

			got := ctx.Response.StatusCode()
			hits := h.upstreamHits()
			t.Logf("明文 %d → %s 压缩 %d 字节（旧窗 %d / 新窗 %d）→ 状态码 %d，上游命中 %d，上游收到 %d 字节",
				len(payload), tc.encoding, len(compressed), requestInspectionBodyLimit, requestBodySnapshotReadMaxSize,
				got, hits, len(h.upstreamBody()))

			if got != http.StatusForbidden {
				t.Fatalf("状态码 = %d，want %d（%s 的大压缩体不得绕过检测）",
					got, http.StatusForbidden, tc.encoding)
			}
			if hits != 0 {
				t.Fatalf("上游收到 %d 次请求，want 0（拦截不得触达上游）", hits)
			}
		})
	}
}

/**
 * TestHandlerOverWindowCompressedBodyDegradesAndForwardsRaw 锁定用户裁定的
 * 「超窗降级」语义：压缩体超过采样窗后，
 *
 *   - 不拒绝（既不是 403 也不是 502）；
 *   - 按原始压缩字节转发，Content-Encoding 原样保留（上游自行解压）；
 *   - 留下一条 not_inspected 审计事件。
 *
 * 同时断言「窗口内可解部分照常送检」不成立时的真实形态：zstd 在超窗时解不出
 * 任何前缀，因此攻击落在末尾的载荷必然放行——这正是需要事件留痕的原因。
 */
func TestHandlerOverWindowCompressedBodyDegradesAndForwardsRaw(t *testing.T) {
	payload, _ := largeAttackPayload(t, 132*1024, true)
	compressed := encodeZstdTest(t, payload)
	if len(compressed) <= requestBodySnapshotReadMaxSize {
		t.Fatalf("测试前提不成立：压缩体 %d 字节未超过偷读窗口 %d", len(compressed), requestBodySnapshotReadMaxSize)
	}

	h := newCompressedBodyHarnessWithWriter(t)
	ctx := h.newRequest(t, compressed, "zstd")
	h.handler(context.Background(), ctx)

	got := ctx.Response.StatusCode()
	t.Logf("压缩 %d 字节（窗口 %d）→ 状态码 %d，上游命中 %d",
		len(compressed), requestBodySnapshotReadMaxSize, got, h.upstreamHits())

	if got != http.StatusOK {
		t.Fatalf("状态码 = %d，want %d（超窗采样必须降级放行而不是拒绝）", got, http.StatusOK)
	}
	if h.upstreamHits() != 1 {
		t.Fatalf("上游命中 %d 次，want 1", h.upstreamHits())
	}
	if enc := h.upstreamEncoding(); enc != "zstd" {
		t.Fatalf("上游 Content-Encoding = %q，want %q（降级必须保留原声明）", enc, "zstd")
	}
	if body := h.upstreamBody(); !bytes.Equal(body, compressed) {
		t.Fatalf("上游收到 %d 字节，want 原始压缩字节 %d 字节", len(body), len(compressed))
	}

	h.assertEvent(t, compressionRuleUninspected, string(action.Observe))
}

/**
 * TestHandlerCompressedBodyWindowBoundary 覆盖压缩体的三档边界：
 *
 *   - 压缩体 ≤ 64 KiB：采样解出明文前缀，攻击在最前必被检出（403、不触达上游）；
 *   - 压缩体略超 64 KiB / 远超 64 KiB：请求照常通过。
 *
 * 超窗档刻意不断言「攻击是否被拦」：zstd 超过窗口时解不出前缀，落在窗口内的
 * 攻击必然不可见，用户裁定接受这一点（降级 + 记事件）。因此超窗档只断言
 * 「不被误判为攻击」这一条，攻击可见性由 TestHandlerLargeCompressedBodyDetectedForAllEncodings
 * 在窗口内的形态上覆盖。
 */
func TestHandlerCompressedBodyWindowBoundary(t *testing.T) {
	cases := []struct {
		name     string
		padBytes int
	}{
		{name: "压缩体在窗口内", padBytes: 8 * 1024},
		{name: "压缩体略超窗口", padBytes: 70 * 1024},
		{name: "压缩体远超窗口", padBytes: 256 * 1024},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload, _ := largeAttackPayload(t, tc.padBytes, false)
			compressed := encodeZstdTest(t, payload)

			h := newCompressedBodyHarness(t)
			ctx := h.newRequest(t, compressed, "zstd")
			h.handler(context.Background(), ctx)

			got := ctx.Response.StatusCode()
			t.Logf("压缩体 %d 字节（窗口 %d）→ 状态码 %d，上游命中 %d，上游收到 %d 字节",
				len(compressed), requestBodySnapshotReadMaxSize, got, h.upstreamHits(), len(h.upstreamBody()))

			if len(compressed) <= requestBodySnapshotReadMaxSize {
				if got != http.StatusForbidden {
					t.Fatalf("窗口内压缩体状态码 = %d，want %d", got, http.StatusForbidden)
				}
				if h.upstreamHits() != 0 {
					t.Fatalf("窗口内压缩体上游命中 %d 次，want 0", h.upstreamHits())
				}
				return
			}

			if got != http.StatusOK {
				t.Fatalf("超窗压缩体状态码 = %d，want %d（降级放行，不得误判）", got, http.StatusOK)
			}
			if h.upstreamHits() != 1 {
				t.Fatalf("超窗压缩体上游命中 %d 次，want 1（降级要把请求交给上游）", h.upstreamHits())
			}
		})
	}
}

/**
 * TestHandlerDecompressionBombDegradesInsteadOfInflating 锁定压缩炸弹的端到端
 * 处置：把解压上限压到 1 MiB，发来 8 MiB 明文压成约 900 字节的 zstd 载荷，
 *
 *   - 请求照常通过（不拒绝），按原始压缩字节转发（上游自行解压）；
 *   - 留下一条 decompression_degraded 审计事件。
 *
 * 上游侧断言刻意只校验「收到的字节能被 zstd 解开且与原文一致」，不逐字节比对
 * 压缩流：压缩器对同一输入不保证逐字节复现，锁定压缩产物会让用例变成对压缩器
 * 版本的断言。
 *
 * 事件规则标识不断言具体是 limit_exceeded 还是 not_inspected：8 MiB 全 'A'
 * 的 zstd 载荷压成 899 字节，采样只偷读到其中 899 字节（完整帧），解码器在解出
 * 1 MiB 时被上限中断——但采样产出上限只有 48 KiB，48 KiB 的产出小于 1 MiB 的
 * 炸弹预算，所以中断信号来自解码器的窗口/内存限额而非外层计数器。两条路径都
 * 归为「压缩体未被完整检测」，因此这里锁定的是类别与触发事实，而非具体来源。
 */
func TestHandlerDecompressionBombDegradesInsteadOfInflating(t *testing.T) {
	const budget = 1 << 20
	previousRequest := proxy.RequestDecompressionMaxBytes()
	previousResponse := proxy.ResponseDecompressionMaxBytes()
	proxy.SetRequestDecompressionMaxBytes(budget)
	proxy.SetResponseDecompressionMaxBytes(budget)
	t.Cleanup(func() {
		proxy.SetRequestDecompressionMaxBytes(previousRequest)
		proxy.SetResponseDecompressionMaxBytes(previousResponse)
	})

	plaintext := bytes.Repeat([]byte("A"), 8<<20)
	compressed := encodeZstdTest(t, plaintext)
	if len(compressed) >= budget {
		t.Fatalf("测试前提不成立：压缩体 %d 字节未低于解压上限 %d", len(compressed), budget)
	}

	h := newCompressedBodyHarnessWithWriter(t)
	ctx := h.newRequest(t, compressed, "zstd")
	h.handler(context.Background(), ctx)

	got := ctx.Response.StatusCode()
	t.Logf("炸弹载荷：明文 %d → 压缩 %d 字节 → 状态码 %d，上游命中 %d，上游收到 %d 字节",
		len(plaintext), len(compressed), got, h.upstreamHits(), len(h.upstreamBody()))
	if got != http.StatusOK {
		t.Fatalf("状态码 = %d，want %d（炸弹只降级，不拒绝）", got, http.StatusOK)
	}
	if h.upstreamHits() != 1 {
		t.Fatalf("上游命中 %d 次，want 1", h.upstreamHits())
	}
	decoded := decodeZstdTest(t, h.upstreamBody())
	if !bytes.Equal(decoded, plaintext) {
		t.Fatalf("上游收到的字节解出 %d 字节明文，want %d（降级必须原样转发压缩体）", len(decoded), len(plaintext))
	}

	ev := h.assertAnyDegradedEvent(t)
	if ev.Action != string(action.Observe) {
		t.Fatalf("降级事件 action = %q，want %q（观察型，不是裁决）", ev.Action, action.Observe)
	}
	if !strings.Contains(ev.MatchDesc, "content_encoding=zstd") {
		t.Fatalf("降级事件 MatchDesc = %q，want 含 content_encoding=zstd", ev.MatchDesc)
	}
}

/**
 * TestHandlerWithinWindowCompressedBodyRecordsNoDegradedEvent 是对照组：
 * 窗口内能解出明文的压缩请求体不得产生任何降级事件，否则审计会被噪声淹没。
 */
func TestHandlerWithinWindowCompressedBodyRecordsNoDegradedEvent(t *testing.T) {
	payload, _ := largeAttackPayload(t, 8*1024, false)
	compressed := encodeGzip(t, payload)

	h := newCompressedBodyHarnessWithWriter(t)
	ctx := h.newRequest(t, compressed, "gzip")
	h.handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("状态码 = %d，want %d", got, http.StatusForbidden)
	}
	h.assertNoDegradedEvent(t)
}

/**
 * TestHandlerPlainRequestBodyRecordsNoDegradedEvent 锁定无编码路径零开销：
 * 不带 Content-Encoding 的普通请求不得产生任何降级事件。
 */
func TestHandlerPlainRequestBodyRecordsNoDegradedEvent(t *testing.T) {
	h := newCompressedBodyHarnessWithWriter(t)
	ctx := h.newRequest(t, []byte(`{"note":"<script>alert(1)</script>"}`), "")
	h.handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("状态码 = %d，want %d", got, http.StatusForbidden)
	}
	h.assertNoDegradedEvent(t)
}

// compressedBodyWriterHarness 在 compressedBodyHarness 之上挂一个落库的
// UnifiedWriter，用于断言降级事件真的写进了 security_events。
type compressedBodyWriterHarness struct {
	*compressedBodyHarness
	db     *gorm.DB
	writer *observability.UnifiedWriter
}

// newCompressedBodyHarnessWithWriter 装配带事件写入器的站点环境。
func newCompressedBodyHarnessWithWriter(t *testing.T) *compressedBodyWriterHarness {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate logs: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))

	h := &compressedBodyWriterHarness{
		compressedBodyHarness: newCompressedBodyHarness(t),
		db:                    db,
		writer:                writer,
	}
	// 重建 handler，把写入器接进去：事件只在 Writer 非 nil 时产生。
	h.compressedBodyHarness.handler = Handler(Options{
		Holder: h.holder,
		Engine: h.engine,
		Log:    slog.Default(),
		Bind:   ":80",
		Writer: writer,
	})
	t.Cleanup(func() { writer.Close() })
	return h
}

// assertEvent 断言落库的安全事件里存在指定规则标识与 action 的那一条。
func (h *compressedBodyWriterHarness) assertEvent(t *testing.T, ruleID, wantAction string) store.SecurityEvent {
	t.Helper()
	h.writer.Close()

	var ev store.SecurityEvent
	if err := h.db.Where("rule_id_str = ? AND category = ?", ruleID, compressionEventCategory).First(&ev).Error; err != nil {
		var all []store.SecurityEvent
		_ = h.db.Find(&all).Error
		t.Fatalf("read security event %s: %v（已落库事件 %d 条：%+v）", ruleID, err, len(all), all)
	}
	if ev.Action != wantAction {
		t.Fatalf("action = %q, want %q", ev.Action, wantAction)
	}
	if ev.Phase != "request_decode" {
		t.Fatalf("phase = %q, want %q", ev.Phase, "request_decode")
	}
	if ev.ClientIP == "" || ev.Host == "" || ev.RequestID == "" {
		t.Fatalf("降级事件缺少归属信息: %+v", ev)
	}
	return ev
}

// assertAnyDegradedEvent 断言落库了一条降级类别的事件并返回它。
func (h *compressedBodyWriterHarness) assertAnyDegradedEvent(t *testing.T) store.SecurityEvent {
	t.Helper()
	h.writer.Close()

	var events []store.SecurityEvent
	if err := h.db.Where("category = ?", compressionEventCategory).Find(&events).Error; err != nil {
		t.Fatalf("read degraded events: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("压缩炸弹降级必须留下安全事件")
	}
	return events[0]
}

// assertNoDegradedEvent 断言没有任何降级类别的事件落库。
func (h *compressedBodyWriterHarness) assertNoDegradedEvent(t *testing.T) {
	t.Helper()
	h.writer.Close()

	var count int64
	if err := h.db.Model(&store.SecurityEvent{}).Where("category = ?", compressionEventCategory).Count(&count).Error; err != nil {
		t.Fatalf("count degraded events: %v", err)
	}
	if count != 0 {
		var all []store.SecurityEvent
		_ = h.db.Where("category = ?", compressionEventCategory).Find(&all).Error
		t.Fatalf("不应产生降级事件，实际 %d 条: %+v", count, all)
	}
}

/**
 * TestRequestBodySampleReadWindowSplitsOnContentEncoding 锁定本轮的分档规则：
 * 偷读上限按「是否声明内容编码」分成两档——
 *
 *   - 未压缩请求：requestInspectionBodyLimit + 1（只要够填采样窗）；
 *   - 压缩请求：requestBodySnapshotReadMaxSize（需要够解码器吐出帧尾）。
 *
 * 分档是为了同时满足两个互相冲突的约束：压缩体需要 64 KiB 才能让 zstd 解出
 * 前缀，而未压缩请求多读的每一个字节都是在 bodyStream 的「凑满 n 字节才返回」
 * 上白担挂起风险（internal/app 有一批 pacing 用例锁定这条边界）。
 */
func TestRequestBodySampleReadWindowSplitsOnContentEncoding(t *testing.T) {
	// 明文体量取两档上限之间：未压缩档截断、压缩档不截断。
	bodySize := (requestInspectionBodyLimit + requestBodySnapshotReadMaxSize) / 2
	body := pseudoRandomBody(t, bodySize, 77)

	t.Run("未压缩请求只偷读到采样窗", func(t *testing.T) {
		ctx := newStreamRequestBodyContext(body, "")
		snap := ensureRequestBodySnapshot(ctx)

		if len(snap.prefetched) != requestBodySnapshotReadMaxSizeUncompressed {
			t.Fatalf("未压缩偷读 = %d 字节，want %d", len(snap.prefetched), requestBodySnapshotReadMaxSizeUncompressed)
		}
		if !snap.hasMore {
			t.Fatal("超过采样窗的未压缩体必须标记 hasMore")
		}
	})

	t.Run("压缩请求偷读到压缩档上限", func(t *testing.T) {
		compressed := encodeZstdTest(t, pseudoRandomBody(t, requestBodySnapshotReadMaxSize, 78))
		ctx := newStreamRequestBodyContext(compressed, "zstd")
		snap := ensureRequestBodySnapshot(ctx)

		want := requestBodySnapshotReadMaxSize
		if len(compressed) < want {
			want = len(compressed)
		}
		if len(snap.prefetched) != want {
			t.Fatalf("压缩偷读 = %d 字节，want %d（压缩档上限 %d）", len(snap.prefetched), want, requestBodySnapshotReadMaxSize)
		}
		if len(snap.prefetched) <= requestBodySnapshotReadMaxSizeUncompressed {
			t.Fatalf("压缩档不得退化成未压缩档：偷读 %d 字节 ≤ %d", len(snap.prefetched), requestBodySnapshotReadMaxSizeUncompressed)
		}
	})
}
