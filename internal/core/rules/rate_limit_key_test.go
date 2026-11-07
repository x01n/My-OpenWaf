package rules

import (
	"net"
	"testing"

	"My-OpenWaf/internal/core/pipeline"
)

/**
 * legacyRateLimitKey 复刻改动前的键口径（clientIP + "|" + host 原值）。
 *
 * 仅用于本文件的回归对照：证明新键在纯值构造输入上的分组与旧键一一对应。
 * 生产代码里已无此形态。
 */
func legacyRateLimitKey(host string, ip net.IP) string {
	client := ""
	if ip != nil {
		client = ip.String()
	}
	return client + "|" + host
}

/**
 * TestRateLimitKeyLegacyGroupingPreservedForPlainInputs 是「纯值构造退化为原行为」的证明。
 *
 * 论据：键的新旧形态都是「分组键」而非「标识」，调用方只关心
 * 「两个请求是否落进同一计数桶」。对一批已规范化的 host 与客户端 IP，
 * 新键的等价类划分必须与旧键逐对一致——同组仍同组，异组仍异组。
 */
func TestRateLimitKeyLegacyGroupingPreservedForPlainInputs(t *testing.T) {
	hosts := []string{"", "api.a.com", "b.example", "*.wild.test", "127.0.0.1", "[::1]"}
	ips := []net.IP{nil, net.ParseIP("203.0.113.9"), net.ParseIP("198.51.100.7"), net.ParseIP("2001:db8::1")}

	// 纯值构造的调用方不填 SiteID/Bind，两者保持空/0。
	const plainSiteID = 0
	const plainBind = ""

	var samples []struct {
		host string
		ip   net.IP
		old  string
		new  string
	}
	for _, host := range hosts {
		for _, ip := range ips {
			samples = append(samples, struct {
				host string
				ip   net.IP
				old  string
				new  string
			}{
				host: host,
				ip:   ip,
				old:  legacyRateLimitKey(host, ip),
				new:  RateLimitKey(plainBind, plainSiteID, host, ip),
			})
		}
	}

	for i := range samples {
		for j := range samples {
			oldSame := samples[i].old == samples[j].old
			newSame := samples[i].new == samples[j].new
			if oldSame != newSame {
				t.Fatalf("分组划分发生漂移：host=%q/ip=%v 与 host=%q/ip=%v 旧键同行=%v 新键同行=%v",
					samples[i].host, samples[i].ip, samples[j].host, samples[j].ip, oldSame, newSame)
			}
		}
	}
}

/**
 * TestRateLimitKeyNormalizesHostVariants 记录一处刻意的收紧。
 *
 * 站点匹配走 snapshot.NormalizeMatchHost（小写、去端口），因此
 * "API.A.COM:80" 与 "api.a.com" 命中的是同一个站点。旧键直接使用 Host 头
 * 原值，同一站点的两种合法写法会各自开出计数桶，限流配额被翻倍绕过。
 * 新键与站点匹配同口径，两者必须落进同一桶。
 */
func TestRateLimitKeyNormalizesHostVariants(t *testing.T) {
	ip := net.ParseIP("203.0.113.9")
	canonical := RateLimitKey("", 0, "api.a.com", ip)
	for _, variant := range []string{"API.A.COM", "api.a.com:80", "  api.a.com  ", "Api.A.Com:8080"} {
		if got := RateLimitKey("", 0, variant, ip); got != canonical {
			t.Fatalf("Host 写法 %q 未归一到同一计数桶：%q != %q", variant, got, canonical)
		}
	}
}

/**
 * TestRateLimitKeySeparatesSiteAndBind 守护站点与监听端口的隔离维度。
 *
 * 站点匹配键是 bind + Host，同一 Host 在不同 bind 上是两个不同站点行，
 * 各自持有独立的限流配额；只按 Host 建键会让它们的窗口互相挤占。
 */
func TestRateLimitKeySeparatesSiteAndBind(t *testing.T) {
	ip := net.ParseIP("203.0.113.9")

	base := RateLimitKey(":80", 1, "api.a.com", ip)
	if base == RateLimitKey(":80", 2, "api.a.com", ip) {
		t.Fatal("不同站点（同 bind 同 Host）必须使用不同的限流键")
	}
	if base == RateLimitKey(":443", 1, "api.a.com", ip) {
		t.Fatal("不同监听端口必须使用不同的限流键")
	}
	if base == RateLimitKey(":80", 1, "api.a.com", net.ParseIP("198.51.100.7")) {
		t.Fatal("不同客户端 IP 必须使用不同的限流键")
	}
	if base != RateLimitKey(":80", 1, "api.a.com", net.ParseIP("203.0.113.9")) {
		t.Fatal("同一输入的限流键必须稳定")
	}
	if base == RateLimitKey(":80", 0, "api.a.com", ip) {
		t.Fatal("站点未解析（SiteID=0）必须与站点 1 分离")
	}
}

/**
 * TestCCRateKeyIncludesSiteAndBind 确认 cc_rate 规则频次键与限流键同源。
 *
 * MatchCtx 的纯值构造路径不填站点身份，但经 fillMatchCtxFromPipeline
 * 从 RequestCtx 填充时必须带上，否则 cc_rate 的窗口同样跨站点合并。
 */
func TestCCRateKeyIncludesSiteAndBind(t *testing.T) {
	ip := net.ParseIP("203.0.113.9")

	a := MatchCtx{Bind: ":80", SiteID: 1, Host: "api.a.com", ClientIP: ip}
	b := MatchCtx{Bind: ":80", SiteID: 2, Host: "api.a.com", ClientIP: ip}
	if ccRateKey(a) == ccRateKey(b) {
		t.Fatal("不同站点的 cc_rate 频次键必须不同")
	}
	if ccRateKey(a) == ccRateKey(MatchCtx{Bind: ":443", SiteID: 1, Host: "api.a.com", ClientIP: ip}) {
		t.Fatal("不同监听端口的 cc_rate 频次键必须不同")
	}
	if ccRateKey(a) != ccRateKey(MatchCtx{Bind: ":80", SiteID: 1, Host: "API.A.COM:80", ClientIP: ip}) {
		t.Fatal("规范化后相同的 Host 必须共用 cc_rate 计数桶")
	}
}

/**
 * TestFillMatchCtxCarriesSiteIdentity 证明字段确实从 RequestCtx 传递过来。
 *
 * 只加字段不填充等于没加：本用例锁住填充路径。
 */
func TestFillMatchCtxCarriesSiteIdentity(t *testing.T) {
	reqCtx := &pipeline.RequestCtx{Bind: ":8443", SiteID: 42, Host: "api.a.com", ClientIP: net.ParseIP("203.0.113.9")}
	mc := ctxFromPipeline(reqCtx, false)
	if mc.Bind != ":8443" || mc.SiteID != 42 {
		t.Fatalf("MatchCtx 未带上站点身份：bind=%q siteID=%d", mc.Bind, mc.SiteID)
	}
	if ccRateKey(mc) != RateLimitKey(":8443", 42, "api.a.com", reqCtx.ClientIP) {
		t.Fatal("经管线填充的 MatchCtx 与直接构造的键必须一致")
	}
}

/**
 * TestReqRateLimitPhaseCountsPerSiteIsolated 从可观测行为验证请求限流隔离。
 *
 * 配额 2（与 ratelimit.RateLimiter.Allow 的 `n <= max` 语义一致）：窗口内第 3 次
 * 才越限。若键不区分站点，站点 1 越限后站点 2 的首次请求会一并被判超限。
 */
func TestReqRateLimitPhaseCountsPerSiteIsolated(t *testing.T) {
	limiter := newSiteIsolationLimiter(2)
	phase := NewReqRateLimitPhase(limiter, "rate_limit")

	siteOne := &pipeline.RequestCtx{Bind: ":80", SiteID: 1, Host: "api.a.com", ClientIP: net.ParseIP("203.0.113.9")}
	siteTwo := &pipeline.RequestCtx{Bind: ":80", SiteID: 2, Host: "api.a.com", ClientIP: net.ParseIP("203.0.113.9")}

	// 站点 1 用满配额：前 2 次放行。
	for i := 1; i <= 2; i++ {
		if _, stop := phase.Execute(siteOne); stop {
			t.Fatalf("站点 1 第 %d 次请求在配额内，不应触发限流", i)
		}
	}
	// 站点 1 第三次：越限。
	if _, stop := phase.Execute(siteOne); !stop {
		t.Fatal("站点 1 第三次请求应触发限流")
	}
	// 站点 2 首次：必须独立计数，仍在配额内。
	if _, stop := phase.Execute(siteTwo); stop {
		t.Fatal("站点 2 首次请求不应触发限流——两个站点共用了同一计数桶")
	}

	// 另一监听端口上的同一站点同样独立。
	otherBind := &pipeline.RequestCtx{Bind: ":443", SiteID: 1, Host: "api.a.com", ClientIP: net.ParseIP("203.0.113.9")}
	if _, stop := phase.Execute(otherBind); stop {
		t.Fatal("另一监听端口上的首次请求不应触发限流——两个 bind 共用了同一计数桶")
	}
}

/**
 * TestCCRateMatcherCountsPerSiteIsolated 验证 cc_rate 匹配器的窗口隔离。
 *
 * 阈值 2：键若不含站点身份，站点 2 的首次命中就会被判超限。
 */
func TestCCRateMatcherCountsPerSiteIsolated(t *testing.T) {
	pattern := `{"op":"cc_rate","window":3600,"threshold":2,"children":[{"kind":"path_contains","arg":"/site-isolation-cc"}]}`
	if errs := validateCompoundPattern(pattern); len(errs) != 0 {
		t.Fatalf("本用例的 cc_rate 固件非法：%v", errs)
	}
	matcher := buildMatcher("compound", pattern)

	ip := net.ParseIP("203.0.113.9")
	siteOne := MatchCtx{Bind: ":80", SiteID: 1, Host: "api.a.com", Path: "/site-isolation-cc", ClientIP: ip}
	siteTwo := MatchCtx{Bind: ":80", SiteID: 2, Host: "api.a.com", Path: "/site-isolation-cc", ClientIP: ip}

	if matcher.Match(siteOne) {
		t.Fatal("站点 1 首次命中不应超限")
	}
	if matcher.Match(siteTwo) {
		t.Fatal("站点 2 首次命中不应超限——两个站点共用了同一 cc_rate 计数桶")
	}
	if !matcher.Match(siteOne) {
		t.Fatal("站点 1 第二次命中应达到阈值")
	}
	if !matcher.Match(siteTwo) {
		t.Fatal("站点 2 第二次命中应达到阈值")
	}
}

// newSiteIsolationLimiter 是本包内最小限流后端替身：固定窗口按 key 计数。
type newSiteIsolationLimiterType struct {
	max    int
	counts map[string]int
}

func newSiteIsolationLimiter(max int) *newSiteIsolationLimiterType {
	return &newSiteIsolationLimiterType{max: max, counts: map[string]int{}}
}

func (l *newSiteIsolationLimiterType) Enabled() bool                { return true }
func (l *newSiteIsolationLimiterType) Reconfigure(_, _ int, _ bool) {}
func (l *newSiteIsolationLimiterType) Close()                       {}
func (l *newSiteIsolationLimiterType) IsOverLimit(key string) bool  { return l.counts[key] > l.max }
func (l *newSiteIsolationLimiterType) Increment(key string) int64 {
	l.counts[key]++
	return int64(l.counts[key])
}
func (l *newSiteIsolationLimiterType) Allow(key string) bool {
	l.counts[key]++
	return l.counts[key] <= l.max
}
