package pages

import (
	"net/http"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/test/assert"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

/**
 * newRenewContext 构造一次携带空响应体的 Hertz 请求上下文。
 *
 * @param t 测试上下文
 * @return 已初始化的 Hertz 请求上下文
 */
func newRenewContext(t *testing.T) *app.RequestContext {
	t.Helper()
	ctx := app.NewContext(0)
	ctx.Request.Header.SetHost("renew.example.com")
	return ctx
}

// TestWriteCookieRenewPage 验证续期页的关键输出特征：
// 页面含 C2 种子解封脚本、location.reload 重试语义与诊断响应头。
func TestWriteCookieRenewPage(t *testing.T) {
	ctx := newRenewContext(t)
	rt := &snapshot.SiteRuntime{
		Site: store.Site{
			Host: "renew.example.com",
		},
	}
	seed := CookieRenewSeed{Envelope: "ZW52ZWxvcGU", KeyHex: "aabb"}
	WriteCookieRenewPage(ctx, "req-renew-1", rt, nil, http.StatusPreconditionFailed, seed)

	assert.DeepEqual(t, http.StatusPreconditionFailed, ctx.Response.StatusCode())
	assert.DeepEqual(t, "renew", string(ctx.Response.Header.Peek("X-OWAF-Probe")))
	assert.DeepEqual(t, "req-renew-1", string(ctx.Response.Header.Peek("X-Request-ID")))
	if got := string(ctx.Response.Header.Peek("Cache-Control")); got == "" {
		t.Fatal("Cache-Control header missing")
	}

	body := string(ctx.Response.Body())
	for _, token := range []string{
		"__waf_nonce2",
		"location.reload",
		"Establishing secure session",
		"Request ID: req-renew-1",
		"vm_assemble_shards",
		seed.Envelope,
		seed.KeyHex,
	} {
		if !strings.Contains(body, token) {
			t.Fatalf("body missing %q", token)
		}
	}
	// 旧的自派生逻辑必须彻底消失：否则 C2 又可被脚本伪造。
	for _, token := range []string{"Date.now().toString(36)", "slice(-8)"} {
		if strings.Contains(body, token) {
			t.Fatalf("body still contains client-side C2 derivation %q", token)
		}
	}
	// 续期页必须是独立页面，不能携带挑战表单链的任何痕迹。
	for _, token := range []string{"__waf_challenge_token", "__waf_challenge_ts", "__waf_pow_sig"} {
		if strings.Contains(body, token) {
			t.Fatalf("body must not contain challenge form field %q", token)
		}
	}
	// 本函数不得写任何 Set-Cookie；C1 由 dataplane 的 setNonceCookie 负责。
	ctx.Response.Header.VisitAll(func(key, value []byte) {
		if string(key) == "Set-Cookie" {
			t.Fatalf("renew page must not set cookies, got %q", string(value))
		}
	})
}

// TestWriteCookieRenewPageNilSnapshotUsesDefaults 验证 nil 快照/运行时的默认品牌渲染。
func TestWriteCookieRenewPageNilSnapshotUsesDefaults(t *testing.T) {
	ctx := newRenewContext(t)
	WriteCookieRenewPage(ctx, "req-renew-nil", nil, nil, http.StatusPreconditionFailed, CookieRenewSeed{})
	body := string(ctx.Response.Body())
	if !strings.Contains(body, "My-OpenWAF") {
		t.Fatalf("default branding missing, body head: %s", cutString(body, 400))
	}
}

// TestWriteCookieRenewPageWithoutSeedReloads 验证种子缺失时页面立即回退：
// 不调用 WASM、不落位任何值，只重载等待服务端重签。
func TestWriteCookieRenewPageWithoutSeedReloads(t *testing.T) {
	ctx := newRenewContext(t)
	WriteCookieRenewPage(ctx, "req-renew-noseed", nil, nil, http.StatusPreconditionFailed, CookieRenewSeed{})
	body := string(ctx.Response.Body())
	if !strings.Contains(body, "if(!ENV||!KEY){finish();return}") {
		t.Fatal("seed-less page must take the early-return reload path")
	}
	if !strings.Contains(body, "location.reload") {
		t.Fatal("seed-less page must still reload")
	}
	// 回退路径终点是 reload，不得绕过 env/key 判空去碰 WASM。
	if strings.Contains(body, "setC2(\"w2.\")") {
		t.Fatal("seed-less page must not write an empty C2 value")
	}
}

func cutString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
