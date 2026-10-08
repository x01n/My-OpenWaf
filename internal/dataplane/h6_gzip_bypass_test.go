package dataplane

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

/**
 * TestHandlerCompressedRequestBodyBypassesOWASP 是 H-6 的端到端回归用例。
 *
 * 同一份 OWASP 必然拦截的载荷（`<script>alert(1)</script>`）用 gzip 压缩后
 * 声明 `Content-Encoding: gzip` 发出，检测必须在解压后的明文上完成：明文与
 * 压缩体都必须 403，且都不得触达上游。
 */
func TestHandlerCompressedRequestBodyBypassesOWASP(t *testing.T) {
	// 载荷必须足够长且前段可压缩，否则 gzip 的固定开销会让短载荷「越压越大」，
	// 明文原样留在压缩体里，测试前提不成立。
	pad := bytes.Repeat([]byte(`{"field":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},`), 100)
	payload := append(pad, []byte(`{"note":"<script>alert(1)</script>"}`)...)

	compressed := encodeGzip(t, payload)
	if bytes.Contains(compressed, []byte("script")) {
		t.Fatalf("压缩体不应含明文 script，测试前提不成立（压缩后 %d 字节）", len(compressed))
	}
	t.Logf("载荷 %d 字节 → 压缩后 %d 字节", len(payload), len(compressed))

	tests := []struct {
		name            string
		body            []byte
		contentEncoding string
	}{
		{name: "对照：明文请求体", body: payload, contentEncoding: ""},
		{name: "gzip 压缩请求体", body: compressed, contentEncoding: "gzip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newCompressedBodyHarness(t)
			ctx := h.newRequest(t, tt.body, tt.contentEncoding)

			h.handler(context.Background(), ctx)

			got := ctx.Response.StatusCode()
			upstreamHit := h.upstreamHits()
			t.Logf("请求体 %d 字节 → 状态码 %d，上游收到 %d 次", len(tt.body), got, upstreamHit)
			if got != http.StatusForbidden {
				t.Fatalf("状态码 = %d，want %d（压缩不得成为绕过检测的通道）", got, http.StatusForbidden)
			}
			if upstreamHit != 0 {
				t.Fatalf("上游收到 %d 次请求，want 0（拦截的请求不得触达上游）", upstreamHit)
			}
		})
	}
}

/**
 * TestHandlerCompressedRequestBodyForwardsDecodedPlaintext 锁定转发语义不变：
 * 通过检测的压缩请求，上游收到的仍是解压后的明文，且 Content-Encoding 已被
 * 剥离，避免上游对明文再解压一次。
 */
func TestHandlerCompressedRequestBodyForwardsDecodedPlaintext(t *testing.T) {
	payload := bytes.Repeat([]byte(`{"field":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},`), 100)
	payload = append(payload, []byte(`{"note":"benign payload"}`)...)
	compressed := encodeGzip(t, payload)
	if len(compressed) >= len(payload) {
		t.Fatalf("测试前提不成立：压缩后 %d 字节不小于明文 %d 字节", len(compressed), len(payload))
	}

	h := newCompressedBodyHarness(t)
	ctx := h.newRequest(t, compressed, "gzip")

	h.handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("状态码 = %d，want %d", got, http.StatusOK)
	}
	if hits := h.upstreamHits(); hits != 1 {
		t.Fatalf("上游收到 %d 次请求，want 1", hits)
	}
	received := h.upstreamBody()
	if !bytes.Equal(received, payload) {
		t.Fatalf("上游收到 %d 字节，want 解压后的明文 %d 字节", len(received), len(payload))
	}
	if ce := h.upstreamEncoding(); ce != "" {
		t.Fatalf("上游收到 Content-Encoding = %q，want 空（明文已解压）", ce)
	}
}

/**
 * TestHandlerOversizeDecodedBodyPassesWhileScanWindowStillDetects 覆盖用户裁定
 * 的「解压超限放过」：解压产出远超扫描窗时请求放行，但落在扫描窗内的攻击
 * 载荷仍必须被拦下，上限不能变成新的绕过面。
 */
func TestHandlerOversizeDecodedBodyPassesWhileScanWindowStillDetects(t *testing.T) {
	benign := bytes.Repeat([]byte("A"), 4<<20)
	benignCompressed := encodeGzip(t, benign)
	if len(benignCompressed) > requestInspectionBodyLimit {
		t.Fatalf("测试前提不成立：压缩体 %d 字节已超过扫描窗", len(benignCompressed))
	}

	attacking := append([]byte(`{"note":"<script>alert(1)</script>"},`), bytes.Repeat([]byte("A"), 4<<20)...)
	attackingCompressed := encodeGzip(t, attacking)

	tests := []struct {
		name       string
		body       []byte
		wantStatus int
		wantHits   int32
	}{
		{name: "解压后 4 MiB 良性载荷：超限放过", body: benignCompressed, wantStatus: http.StatusOK, wantHits: 1},
		{name: "解压后 4 MiB 但攻击在扫描窗内：仍拦截", body: attackingCompressed, wantStatus: http.StatusForbidden, wantHits: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newCompressedBodyHarness(t)
			ctx := h.newRequest(t, tt.body, "gzip")

			h.handler(context.Background(), ctx)

			got := ctx.Response.StatusCode()
			hits := h.upstreamHits()
			t.Logf("压缩体 %d 字节 → 状态码 %d，上游收到 %d 次", len(tt.body), got, hits)
			if got != tt.wantStatus {
				t.Fatalf("状态码 = %d，want %d", got, tt.wantStatus)
			}
			if hits != tt.wantHits {
				t.Fatalf("上游收到 %d 次请求，want %d", hits, tt.wantHits)
			}
		})
	}
}

/**
 * TestHandlerMismatchedContentEncodingDoesNotFallBackToRawBytes 锁定畸形压缩体
 * 的现状：声明的内容编码与实际字节不符时，WAF 拿不到可解压的明文，也不回退
 * 到原始压缩字节。该行为等于放行到转发层，上游随后解析失败（现状为 502，
 * 由既有上传路径决定），本用例只锁定「不因本次改动额外拦截」。
 */
func TestHandlerMismatchedContentEncodingDoesNotFallBackToRawBytes(t *testing.T) {
	payload := append([]byte(`{"note":"<script>alert(1)</script>"},`), bytes.Repeat([]byte(`{"f":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},`), 100)...)

	h := newCompressedBodyHarness(t)
	ctx := h.newRequest(t, payload, "br")

	h.handler(context.Background(), ctx)

	got := ctx.Response.StatusCode()
	t.Logf("明文声明 br → 状态码 %d，上游收到 %d 次", got, h.upstreamHits())
	if got == http.StatusForbidden {
		t.Fatal("畸形压缩体不得在 WAF 侧被判拦截：解压失败只降级为样本为空")
	}
}

// compressedBodyHarness 是压缩请求体端到端用例共用的站点环境：一个记录上游
// 请求次数、请求体字节与 Content-Encoding 的测试上游，加上按站点配置装配好
// 的 WAF Handler。
type compressedBodyHarness struct {
	handler    app.HandlerFunc
	upstream   *httptest.Server
	hits       atomic.Int32
	body       atomic.Value
	encoding   atomic.Value
	siteHost   string
	contentLen atomic.Int64
	// holder 与 engine 保留下来，供带事件写入器的变体重建 handler 时复用同
	// 一份快照与引擎，避免两套站点配置产生行为差异。
	holder *snapshot.Holder
	engine *engine.Engine
}

func newCompressedBodyHarness(t *testing.T) *compressedBodyHarness {
	t.Helper()
	h := &compressedBodyHarness{siteHost: "gz.example.com"}

	h.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hits.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Logf("上游读取请求体失败: %v", err)
		}
		h.body.Store(body)
		h.encoding.Store(r.Header.Get("Content-Encoding"))
		h.contentLen.Store(r.ContentLength)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(h.upstream.Close)

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.OWASPEnabled = true
	protection.OWASPAction = "intercept"
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site:                store.Site{ID: 1, Host: h.siteHost, Bind: ":80"},
		Bind:                ":80",
		UpstreamURLs:        []string{h.upstream.URL},
		EffectiveProtection: &protection,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", h.siteHost): &rt,
		},
	})

	eng := engine.New(holder, nil, nil, nil)
	h.handler = Handler(Options{
		Holder: holder,
		Engine: eng,
		Log:    slog.Default(),
		Bind:   ":80",
	})
	h.holder = holder
	h.engine = eng
	return h
}

func (h *compressedBodyHarness) newRequest(t *testing.T, body []byte, contentEncoding string) *app.RequestContext {
	t.Helper()
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodPost)
	ctx.Request.SetRequestURI("/submit")
	ctx.Request.Header.SetHost(h.siteHost)
	ctx.Request.Header.Set("Content-Type", "application/json")
	if contentEncoding != "" {
		ctx.Request.Header.Set("Content-Encoding", contentEncoding)
	}
	ctx.Request.SetBodyStream(&trackingRequestBodyStream{reader: bytes.NewReader(body)}, len(body))
	return ctx
}

func (h *compressedBodyHarness) upstreamHits() int32 { return h.hits.Load() }

func (h *compressedBodyHarness) upstreamBody() []byte {
	value, _ := h.body.Load().([]byte)
	return value
}

func (h *compressedBodyHarness) upstreamEncoding() string {
	value, _ := h.encoding.Load().(string)
	return value
}
