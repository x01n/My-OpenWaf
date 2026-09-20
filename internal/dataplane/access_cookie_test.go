package dataplane

import (
	"strconv"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
)

// 站点访问控制的会话 cookie 此前零测试覆盖。
//
// 这类 cookie 承载的是「已通过站点登录」的凭据，属性写错的后果都是安静的：
// 丢了 HttpOnly，XSS 就能读走会话；丢了 SameSite，跨站请求会带上它；
// 站点启用 TLS 却漏了 Secure，凭据会在明文信道上发出去。三者都不会报错，
// 也不会影响功能自测，只有被利用时才暴露。

// parseSetCookie 把响应里的 Set-Cookie 拆成「cookie 值 + 属性集合」。
//
// 属性名统一转小写便于断言；带值的属性（如 max-age=60）按 name=value 存。
func parseSetCookie(t *testing.T, raw string) (value string, attrs map[string]string) {
	t.Helper()
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		t.Fatalf("Set-Cookie 为空: %q", raw)
	}
	value = strings.TrimSpace(parts[0])
	attrs = make(map[string]string, len(parts))
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if i := strings.Index(p, "="); i >= 0 {
			attrs[strings.ToLower(p[:i])] = p[i+1:]
		} else {
			attrs[strings.ToLower(p)] = ""
		}
	}
	return value, attrs
}

// TestSetAccessSessionCookieSecurityAttributes 钉住会话 cookie 的安全属性。
func TestSetAccessSessionCookieSecurityAttributes(t *testing.T) {
	const (
		name  = "__owaf_access_1"
		token = "b2f4c1d0e9a8"
	)

	t.Run("站点未启用 TLS", func(t *testing.T) {
		c := app.NewContext(0)
		setAccessSessionCookie(c, name, token, 3600, false)

		raw := string(c.Response.Header.Peek("Set-Cookie"))
		if raw == "" {
			t.Fatal("未写出 Set-Cookie")
		}
		value, attrs := parseSetCookie(t, raw)

		if value != name+"="+token {
			t.Errorf("cookie 值 = %q, want %q", value, name+"="+token)
		}
		if _, ok := attrs["httponly"]; !ok {
			t.Error("缺少 HttpOnly——脚本将能读到会话凭据")
		}
		if got := attrs["samesite"]; got != "Lax" {
			t.Errorf("SameSite = %q, want Lax——缺失或放宽会让跨站请求带上会话", got)
		}
		if got := attrs["path"]; got != "/" {
			t.Errorf("Path = %q, want /", got)
		}
		if got := attrs["max-age"]; got != "3600" {
			t.Errorf("Max-Age = %q, want 3600", got)
		}
		if _, ok := attrs["secure"]; ok {
			t.Error("站点未启用 TLS 时不应加 Secure，否则明文站点上 cookie 根本发不出去")
		}
	})

	t.Run("站点启用 TLS", func(t *testing.T) {
		c := app.NewContext(0)
		setAccessSessionCookie(c, name, token, 3600, true)

		_, attrs := parseSetCookie(t, string(c.Response.Header.Peek("Set-Cookie")))
		if _, ok := attrs["secure"]; !ok {
			t.Error("站点启用 TLS 时必须加 Secure，否则凭据可能经明文信道发出")
		}
		if _, ok := attrs["httponly"]; !ok {
			t.Error("Secure 分支同样要保留 HttpOnly")
		}
	})
}

// TestSetAccessSessionCookieTTLFallback 验证非正数 TTL 回退到一天。
//
// 传 0 通常意味着调用方没配 SessionTTL。若原样写成 Max-Age=0，浏览器会立刻
// 删除该 cookie——用户刚登录就被登出，且没有任何报错。
func TestSetAccessSessionCookieTTLFallback(t *testing.T) {
	for _, ttl := range []int{0, -1, -86400} {
		t.Run("ttl="+strconv.Itoa(ttl), func(t *testing.T) {
			c := app.NewContext(0)
			setAccessSessionCookie(c, "__owaf_access_1", "tok", ttl, false)

			_, attrs := parseSetCookie(t, string(c.Response.Header.Peek("Set-Cookie")))
			if got := attrs["max-age"]; got != "86400" {
				t.Errorf("Max-Age = %q, want 86400——非正数 TTL 应回退到一天，"+
					"写成 0 会让浏览器当场删除 cookie，表现为「刚登录就被登出」", got)
			}
		})
	}
}

// TestClearAccessSessionCookie 验证登出时的清除语义。
//
// 清除靠的是 Max-Age=0 加空值。属性必须与写入时一致（同名、同 Path、同 Secure），
// 否则浏览器会认为这是另一个 cookie，旧的那个原封不动留着——用户以为登出了，
// 会话其实还在。
func TestClearAccessSessionCookie(t *testing.T) {
	const name = "__owaf_access_7"

	t.Run("非 TLS 站点", func(t *testing.T) {
		c := app.NewContext(0)
		clearAccessSessionCookie(c, name, false)

		value, attrs := parseSetCookie(t, string(c.Response.Header.Peek("Set-Cookie")))
		if value != name+"=" {
			t.Errorf("cookie 值 = %q, want %q（应清空）", value, name+"=")
		}
		if got := attrs["max-age"]; got != "0" {
			t.Errorf("Max-Age = %q, want 0——这是让浏览器立即删除的信号", got)
		}
		if got := attrs["path"]; got != "/" {
			t.Errorf("Path = %q, want /——与写入时不一致会清不掉原 cookie", got)
		}
		if _, ok := attrs["httponly"]; !ok {
			t.Error("清除时也应保留 HttpOnly，属性不匹配可能导致清除失败")
		}
		if _, ok := attrs["secure"]; ok {
			t.Error("非 TLS 站点不应加 Secure")
		}
	})

	t.Run("TLS 站点", func(t *testing.T) {
		c := app.NewContext(0)
		clearAccessSessionCookie(c, name, true)

		_, attrs := parseSetCookie(t, string(c.Response.Header.Peek("Set-Cookie")))
		if _, ok := attrs["secure"]; !ok {
			t.Error("写入时带 Secure，清除时也必须带，否则浏览器视作不同 cookie 而清不掉")
		}
	})
}

// TestAccessSessionCookieRoundTrip 验证写入与清除针对的是同一个 cookie。
//
// 两个函数各写各的属性，一旦有人只改其中一个（比如把写入侧的 SameSite 调成
// Strict），清除就会失效。这里对齐比较，把它们绑在一起。
func TestAccessSessionCookieRoundTrip(t *testing.T) {
	const name = "__owaf_access_9"

	for _, secure := range []bool{false, true} {
		setCtx := app.NewContext(0)
		setAccessSessionCookie(setCtx, name, "tok", 600, secure)
		setValue, setAttrs := parseSetCookie(t, string(setCtx.Response.Header.Peek("Set-Cookie")))

		clearCtx := app.NewContext(0)
		clearAccessSessionCookie(clearCtx, name, secure)
		clearValue, clearAttrs := parseSetCookie(t, string(clearCtx.Response.Header.Peek("Set-Cookie")))

		if !strings.HasPrefix(setValue, name+"=") || !strings.HasPrefix(clearValue, name+"=") {
			t.Fatalf("secure=%v: cookie 名不一致: set=%q clear=%q", secure, setValue, clearValue)
		}
		// 浏览器按 name + Path + Secure 判定是否同一个 cookie，这几项必须一致。
		for _, attr := range []string{"path", "secure", "httponly", "samesite"} {
			_, inSet := setAttrs[attr]
			_, inClear := clearAttrs[attr]
			if inSet != inClear {
				t.Errorf("secure=%v: 属性 %q 在写入(%v)与清除(%v)间不一致——浏览器会视作不同 cookie，登出将失效",
					secure, attr, inSet, inClear)
			}
			if inSet && inClear && setAttrs[attr] != clearAttrs[attr] {
				t.Errorf("secure=%v: 属性 %q 取值不一致: set=%q clear=%q",
					secure, attr, setAttrs[attr], clearAttrs[attr])
			}
		}
	}
}

// TestSafeRefererRedirect 覆盖「跳回原页面」的收口逻辑。
//
// 挑战与验证流程都用 Referer 把用户送回来处，而 Referer 完全由外部页面决定。
// 攻击者从自己的页面向验证端点发起提交，Referer 就是攻击者域名——用户完成验证后
// 被送过去，且那一刻页面还顶着「刚通过站点验证」的上下文，正适合钓凭据。
func TestSafeRefererRedirect(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		referer string
		want    string
	}{
		{"同源 Referer 取路径", "site.test", "https://site.test/dashboard", "/dashboard"},
		{"同源带查询串", "site.test", "https://site.test/a?b=1", "/a?b=1"},
		{"同源带端口", "site.test:8443", "https://site.test/page", "/page"},
		{"Referer 带端口而 Host 不带", "site.test", "https://site.test:8443/page", "/page"},
		{"跨站 Referer 丢弃", "site.test", "https://evil.com/phish", "/"},
		{"子域不算同源", "site.test", "https://evil.site.test.attacker.com/x", "/"},
		{"无 Referer", "site.test", "", "/"},
		{"Referer 仅为域名无路径", "site.test", "https://site.test", "/"},
		{"协议相对形式的 Referer", "site.test", "//evil.com/x", "/"},
		{"无法解析的 Referer", "site.test", "ht tp://bad", "/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := app.NewContext(0)
			c.Request.Header.SetHost(tc.host)
			if tc.referer != "" {
				c.Request.Header.Set("Referer", tc.referer)
			}
			if got := safeRefererRedirect(c); got != tc.want {
				t.Errorf("safeRefererRedirect() = %q, want %q —— 该值会成为验证后的跳转目标",
					got, tc.want)
			}
		})
	}
}
