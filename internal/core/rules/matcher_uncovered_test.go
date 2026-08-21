package rules

import (
	"testing"
)

// 本文件补齐 15 个此前零测试覆盖的匹配器。
//
// 这些都是用户可直接配置的规则类型，实现本身没查出问题，但没有任何测试钉住语义——
// 一次重构就能把「Host 为空时否定匹配返回 true」这类边界悄悄改掉，而 WAF 的规则
// 判定出错的表现是漏拦或误拦，不会有报错。
//
// 每条用例都写明断言的是哪个具体语义，而不是只堆一个 true/false。

// matchCase 是匹配器的一条断言。
type matchCase struct {
	name string
	ctx  MatchCtx
	want bool
	why  string // 失败时说明这条断言守的是什么语义
}

// runMatchCases 用 buildMatcher 构造匹配器并逐条断言。
func runMatchCases(t *testing.T, kind, arg string, cases []matchCase) {
	t.Helper()
	m := buildMatcher(kind, arg)
	if m == nil {
		t.Fatalf("buildMatcher(%q, %q) 返回 nil", kind, arg)
	}
	// buildMatcher 对无法识别的 kind 与非法参数一律返回 neverMatcher（恒 false）。
	// 不挡住这种情况的话，kind 写错时所有期望 false 的断言都会假装通过，
	// 只有期望 true 的会失败——本文件初版就是这么踩进去的。
	if _, never := m.(*neverMatcher); never {
		t.Fatalf("buildMatcher(%q, %q) 得到 neverMatcher：kind 无法识别或参数非法", kind, arg)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.Match(tc.ctx); got != tc.want {
				t.Errorf("Match() = %v, want %v — %s", got, tc.want, tc.why)
			}
		})
	}
}

// ---- Host 系列 ----

// TestHostFullMatcher 覆盖含端口匹配与通配符。
//
// 通配 `*.example.com` 刻意同时匹配子域与裸域（实现里 HasSuffix 之外还比了
// TrimPrefix 后的结果），配错会让「拦截整个域」的规则漏掉主域本身。
func TestHostFullMatcher(t *testing.T) {
	runMatchCases(t, "host_full", "api.example.com", []matchCase{
		{"精确匹配", MatchCtx{Host: "api.example.com"}, true, "主机名相等应命中"},
		{"带端口", MatchCtx{Host: "api.example.com:8443"}, true, "去端口后应命中"},
		{"大小写不敏感", MatchCtx{Host: "API.Example.COM"}, true, "Host 会被转小写后比较"},
		{"前后空白", MatchCtx{Host: "  api.example.com  "}, true, "取值前会 TrimSpace"},
		{"不同主机", MatchCtx{Host: "www.example.com"}, false, "不应误命中同域其他主机"},
		{"空 Host", MatchCtx{}, false, "无 Host 时不应命中"},
		{"从请求头取 Host", MatchCtx{Headers: map[string]string{"host": "api.example.com"}, HeadersLowercase: true}, true,
			"ctx.Host 为空时应回退到 host 请求头"},
	})

	runMatchCases(t, "host_full", "*.example.com", []matchCase{
		{"通配匹配子域", MatchCtx{Host: "api.example.com"}, true, "*.example.com 应命中子域"},
		{"通配匹配裸域", MatchCtx{Host: "example.com"}, true,
			"实现刻意让 *.example.com 也命中主域，否则「拦整个域」会漏掉主域本身"},
		{"通配匹配多级子域", MatchCtx{Host: "a.b.example.com"}, true, "后缀匹配应支持多级"},
		{"通配不匹配他域", MatchCtx{Host: "example.org"}, false, "不应跨域命中"},
		{"通配不匹配相似后缀", MatchCtx{Host: "notexample.com"}, false,
			"必须按 .example.com 后缀匹配，不能只看 example.com 子串"},
	})
}

func TestHostMatcherIPv6AndHostnamePortBoundaries(t *testing.T) {
	runMatchCases(t, "host", "2001:db8::1", []matchCase{
		{"裸 IPv6 精确匹配", MatchCtx{Host: "2001:db8::1"}, true, "裸 IPv6 不能把末尾数字误判成端口"},
		{"裸 IPv6 不误配相邻地址", MatchCtx{Host: "2001:db8::2"}, false, "不同的 IPv6 地址不能因末段被剥离而命中"},
		{"带括号 IPv6 与端口匹配", MatchCtx{Host: "[2001:db8::1]:443"}, true, "Host 头中的括号只属于 IPv6 端口语法"},
	})

	runMatchCases(t, "host", "api.example.com", []matchCase{
		{"hostname 带端口", MatchCtx{Host: "api.example.com:8443"}, true, "host 匹配器应忽略纯数字端口"},
		{"hostname 端口不能改变主机", MatchCtx{Host: "api.example.com:443"}, true, "不同纯数字端口仍应归一化为同一主机"},
	})
}

func TestHostFullMatcherIPv6AndWildcardPort(t *testing.T) {
	runMatchCases(t, "host_full", "2001:db8::1", []matchCase{
		{"裸 IPv6 精确匹配", MatchCtx{Host: "2001:db8::1"}, true, "host_full 应保留裸 IPv6 的完整地址"},
		{"裸 IPv6 不误配相邻地址", MatchCtx{Host: "2001:db8::2"}, false, "不同的 IPv6 地址不能被截成相同前缀"},
		{"裸 IPv6 规则匹配带端口请求", MatchCtx{Host: "[2001:db8::1]:443"}, true, "未指定端口时应沿用 hostname:port 的兼容语义"},
	})

	runMatchCases(t, "host_full", "[2001:db8::1]:8443", []matchCase{
		{"IPv6 端口精确匹配", MatchCtx{Host: "[2001:db8::1]:8443"}, true, "显式 IPv6 端口必须精确匹配"},
		{"IPv6 端口不匹配", MatchCtx{Host: "[2001:db8::1]:443"}, false, "不同端口不能命中 host_full"},
	})

	runMatchCases(t, "host_full", "*.example.com:8443", []matchCase{
		{"通配符带端口匹配子域", MatchCtx{Host: "api.example.com:8443"}, true, "通配符只替换主机名，显式端口仍需相等"},
		{"通配符带端口匹配裸域", MatchCtx{Host: "example.com:8443"}, true, "保持既有 wildcard apex 语义并校验端口"},
		{"通配符端口不匹配", MatchCtx{Host: "api.example.com:443"}, false, "通配符不能忽略配置中的显式端口"},
	})
}

func TestHostRegexMatcher(t *testing.T) {
	runMatchCases(t, "host_regex", `^api\d+\.example\.com$`, []matchCase{
		{"命中", MatchCtx{Host: "api01.example.com"}, true, "正则应匹配主机名"},
		{"带端口仍命中", MatchCtx{Host: "api01.example.com:8080"}, true,
			"正则匹配的是去掉端口的主机名，锚定 $ 才不会因端口失配"},
		{"不命中", MatchCtx{Host: "web.example.com"}, false, "不符正则不应命中"},
		{"空 Host", MatchCtx{}, false, "无 Host 时直接返回 false，不进正则"},
	})
}

func TestHostContainsMatcher(t *testing.T) {
	// 配置写大写，验证编译期已 ToLower——否则主机名被转小写后永远配不上。
	runMatchCases(t, "host_contains", "ADMIN", []matchCase{
		{"配置大写仍命中", MatchCtx{Host: "admin.example.com"}, true,
			"substr 在 buildMatcher 里已 ToLower，大写配置不应失效"},
		{"主机名大写", MatchCtx{Host: "ADMIN.example.com"}, true, "主机名会被转小写"},
		{"不含子串", MatchCtx{Host: "www.example.com"}, false, "不含时不应命中"},
		{"非纯数字端口段整体保留", MatchCtx{Host: "www.example.com:9admin"}, true,
			"端口段非全数字时不视作端口，整串都参与匹配，故此处含 admin"},
		{"空 Host", MatchCtx{}, false, "无 Host 时不应命中"},
	})

	// 纯数字端口会被剥离，不参与主机名匹配。
	runMatchCases(t, "host_contains", "8080", []matchCase{
		{"纯数字端口被剥离", MatchCtx{Host: "www.example.com:8080"}, false,
			"端口不属于主机名，配 host_contains:8080 不应因端口而命中"},
	})
}

// TestHostNotContainsMatcher 是否定逻辑，边界最容易写反。
//
// 尤其「Host 为空返回 true」这一条：实现选择把「没有 Host」视为「不包含」，
// 若被改成 false，配了 host_not_contains 的拦截规则会对无 Host 的请求失效。
func TestHostNotContainsMatcher(t *testing.T) {
	runMatchCases(t, "host_not_contains", "trusted", []matchCase{
		{"不含子串则命中", MatchCtx{Host: "evil.example.com"}, true, "否定匹配：不含即命中"},
		{"含子串则不命中", MatchCtx{Host: "trusted.example.com"}, false, "含有子串时否定匹配应为 false"},
		{"空 Host 命中", MatchCtx{}, true,
			"实现把「无 Host」视为「不包含」，改成 false 会让规则对无 Host 请求失效"},
		{"大小写不敏感", MatchCtx{Host: "TRUSTED.example.com"}, false,
			"主机名与 substr 都会转小写，大写 Host 同样应判为「包含」"},
	})
}

// ---- URL 系列 ----

// TestFullURLContainsMatcher 验证匹配目标是 path + "?" + query 且大小写不敏感。
func TestFullURLContainsMatcher(t *testing.T) {
	runMatchCases(t, "full_url_contains", "id=1 or 1=1", []matchCase{
		{"命中查询串", MatchCtx{Path: "/search", Query: "id=1 or 1=1"}, true, "path?query 拼接后应包含子串"},
		{"大小写不敏感", MatchCtx{Path: "/search", Query: "ID=1 OR 1=1"}, true,
			"用的是 containsFoldASCII，大小写变形不应绕过"},
		{"仅路径不含", MatchCtx{Path: "/search", Query: ""}, false, "查询为空时不应命中"},
		{"跨越问号边界", MatchCtx{Path: "/a", Query: "b"}, false, "拼接后为 /a?b，不应误命中"},
	})

	// 子串横跨 path 与 query 的分隔符，验证确实是拼接后再匹配。
	runMatchCases(t, "full_url_contains", "/admin?token", []matchCase{
		{"跨路径与查询", MatchCtx{Path: "/admin", Query: "token=x"}, true,
			"匹配目标是拼接后的完整 URL，而非分别匹配"},
		{"只有路径", MatchCtx{Path: "/admin"}, false, "查询为空时不拼接问号，不应命中"},
	})
}

func TestFullURLRegexMatcher(t *testing.T) {
	runMatchCases(t, "full_url_regex", `^/api/v\d+/users\?id=\d+$`, []matchCase{
		{"命中", MatchCtx{Path: "/api/v1/users", Query: "id=42"}, true, "正则作用于拼接后的 URL"},
		{"查询不符", MatchCtx{Path: "/api/v1/users", Query: "id=abc"}, false, "查询部分不符不应命中"},
		{"缺少查询", MatchCtx{Path: "/api/v1/users"}, false, "无查询时 URL 不含问号，锚定的正则应失配"},
	})
}

// ---- 请求头 / Cookie / Referer ----

func TestCookieContainsMatcher(t *testing.T) {
	runMatchCases(t, "cookie_contains", "sessionid=", []matchCase{
		{"命中", MatchCtx{Headers: map[string]string{"cookie": "sessionid=abc123; theme=dark"}, HeadersLowercase: true}, true,
			"应在 cookie 请求头中查找子串"},
		{"不含", MatchCtx{Headers: map[string]string{"cookie": "theme=dark"}, HeadersLowercase: true}, false,
			"不含时不应命中"},
		{"无 cookie 头", MatchCtx{}, false, "缺少 cookie 头时不应命中"},
	})
}

func TestRefererContainsMatcher(t *testing.T) {
	runMatchCases(t, "referer_contains", "evil.com", []matchCase{
		{"命中", MatchCtx{Headers: map[string]string{"referer": "https://evil.com/x"}, HeadersLowercase: true}, true,
			"应在 referer 请求头中查找子串"},
		{"不含", MatchCtx{Headers: map[string]string{"referer": "https://good.com/x"}, HeadersLowercase: true}, false,
			"不含时不应命中"},
		{"无 referer 头", MatchCtx{}, false, "缺少 referer 头时不应命中"},
	})
}

// TestHeaderOrderRegexMatcher 覆盖请求头顺序指纹。
//
// 请求头出现顺序是常用的客户端指纹信号：正常浏览器顺序稳定，脚本客户端往往不同。
func TestHeaderOrderRegexMatcher(t *testing.T) {
	runMatchCases(t, "header_order_regex", `^host,user-agent,accept$`, []matchCase{
		{"顺序命中", MatchCtx{HeaderOrder: "host,user-agent,accept"}, true, "顺序完全一致应命中"},
		{"顺序不同", MatchCtx{HeaderOrder: "host,accept,user-agent"}, false,
			"顺序不同应判为不同指纹——这正是该匹配器的存在意义"},
		{"顺序为空", MatchCtx{}, false, "没有采集到顺序时不应命中"},
	})
}

// ---- 查询串 ----

// TestQueryContainsMatcher 注意此匹配器大小写敏感。
//
// 与 full_url_contains 用 containsFoldASCII 不同，block_query_contains 走
// strings.Contains 且 arg 未转小写。这条差异必须钉住：若有人「统一」成大小写
// 不敏感，配了精确大小写的规则会开始误拦。
func TestQueryContainsMatcher(t *testing.T) {
	runMatchCases(t, "block_query_contains", "UNION", []matchCase{
		{"精确大小写命中", MatchCtx{Query: "id=1 UNION SELECT"}, true, "同样大小写应命中"},
		{"小写不命中", MatchCtx{Query: "id=1 union select"}, false,
			"该匹配器大小写敏感，与 full_url_contains 的折叠比较不同"},
		{"空查询", MatchCtx{}, false, "查询为空时不应命中"},
	})
}

// ---- 请求体系列 ----

func TestBodyContainsMatcher(t *testing.T) {
	runMatchCases(t, "body_contains", "<script>", []matchCase{
		{"命中", MatchCtx{Body: []byte(`{"c":"<script>alert(1)</script>"}`)}, true, "请求体含子串应命中"},
		{"不含", MatchCtx{Body: []byte(`{"c":"hello"}`)}, false, "不含时不应命中"},
		{"空请求体", MatchCtx{}, false, "无请求体时不应命中"},
	})
}

func TestBodyRegexMatcher(t *testing.T) {
	runMatchCases(t, "body_regex", `(?i)union\s+select`, []matchCase{
		{"命中", MatchCtx{Body: []byte("id=1 UNION  SELECT 1")}, true, "正则应作用于请求体"},
		{"大小写由正则自身控制", MatchCtx{Body: []byte("id=1 union select 1")}, true,
			"这里用 (?i) 开启忽略大小写，说明大小写策略由规则作者决定"},
		{"不命中", MatchCtx{Body: []byte("id=1")}, false, "不符正则不应命中"},
		{"空请求体", MatchCtx{}, false, "无请求体时不应命中"},
	})
}

// TestBodyJSONPathMatcher 覆盖路径定位与值匹配。
//
// 关键语义：路径不存在返回 false（而非把缺失当空串去匹配），否则一条
// `$.user.role` 的规则会对所有不带该字段的请求生效。
func TestBodyJSONPathMatcher(t *testing.T) {
	runMatchCases(t, "block_body_json_path", `$.user.role:^admin$`, []matchCase{
		{"路径存在且值匹配", MatchCtx{Body: []byte(`{"user":{"role":"admin"}}`)}, true, "嵌套路径应能定位到值"},
		{"值不匹配", MatchCtx{Body: []byte(`{"user":{"role":"guest"}}`)}, false, "值不符正则不应命中"},
		{"路径不存在", MatchCtx{Body: []byte(`{"user":{"name":"x"}}`)}, false,
			"缺字段必须返回 false，否则规则会对所有不带该字段的请求生效"},
		{"中间层不是对象", MatchCtx{Body: []byte(`{"user":"admin"}`)}, false,
			"路径中途遇到非对象应安全返回 false 而不是 panic"},
		{"非法 JSON", MatchCtx{Body: []byte(`{not json`)}, false, "解析失败应返回 false"},
		{"空请求体", MatchCtx{}, false, "无请求体时不应命中"},
		{"顶层数组", MatchCtx{Body: []byte(`[1,2,3]`)}, false,
			"实现只解析 JSON 对象，顶层数组应安全失配"},
	})

	// 非字符串值会被 json.Marshal 后再匹配。
	runMatchCases(t, "block_body_json_path", `$.count:^42$`, []matchCase{
		{"数值转字符串后匹配", MatchCtx{Body: []byte(`{"count":42}`)}, true,
			"非字符串值会 marshal 成文本再做正则"},
	})
}

// ---- multipart ----

// TestMultipartMatcher 覆盖上传文件名扫描。
//
// 前置条件是 Content-Type 必须是 multipart/form-data：缺了这一步就会把普通
// 请求体也当作 multipart 扫描。
func TestMultipartMatcher(t *testing.T) {
	body := "--BOUNDARY\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n" +
		"<?php ?>\r\n" +
		"--BOUNDARY--\r\n"
	mpHeaders := map[string]string{"content-type": "multipart/form-data; boundary=BOUNDARY"}

	runMatchCases(t, "block_multipart", `\.(php|jsp|asp)$`, []matchCase{
		{"命中危险扩展名", MatchCtx{Body: []byte(body), Headers: mpHeaders, HeadersLowercase: true}, true,
			"应从 part 头里提取 filename 并按正则判断"},
		{"非 multipart 请求", MatchCtx{Body: []byte(body), Headers: map[string]string{"content-type": "application/json"}, HeadersLowercase: true}, false,
			"Content-Type 不是 multipart 时应直接放过，避免把普通请求体当作上传扫描"},
		{"空请求体", MatchCtx{Headers: mpHeaders, HeadersLowercase: true}, false, "无请求体时不应命中"},
		{"缺 Content-Type", MatchCtx{Body: []byte(body)}, false, "拿不到 Content-Type 时不应命中"},
	})

	safeBody := "--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"photo.jpg\"\r\n\r\nx\r\n--B--\r\n"
	runMatchCases(t, "block_multipart", `\.(php|jsp|asp)$`, []matchCase{
		{"安全扩展名不命中", MatchCtx{Body: []byte(safeBody), Headers: map[string]string{"content-type": "multipart/form-data; boundary=B"}, HeadersLowercase: true}, false,
			"正常图片上传不应被拦"},
	})
}

// ---- 地理封锁 ----

// TestGeoBlockMatcher 覆盖按国家码封锁。
//
// 国家码来自上游 CDN 注入的请求头，实现按 x-geo-country、cf-ipcountry 的顺序查找。
// 值得钉住的是「第一个头存在但不在名单里时，仍会继续查第二个头」——若被改成
// 直接返回 false，同时经过两级 CDN 的部署会漏掉后一个头携带的国家码。
func TestGeoBlockMatcher(t *testing.T) {
	runMatchCases(t, "geo_block", "CN,RU, kp ", []matchCase{
		{"x-geo-country 命中", MatchCtx{
			Headers: map[string]string{"x-geo-country": "CN"}, HeadersLowercase: true,
		}, true, "应识别 x-geo-country"},

		{"cf-ipcountry 命中", MatchCtx{
			Headers: map[string]string{"cf-ipcountry": "RU"}, HeadersLowercase: true,
		}, true, "应识别 Cloudflare 的 cf-ipcountry"},

		{"配置含空格与小写仍命中", MatchCtx{
			Headers: map[string]string{"cf-ipcountry": "KP"}, HeadersLowercase: true,
		}, true, "国家码在编译期做了 TrimSpace + ToUpper"},

		{"请求头值小写仍命中", MatchCtx{
			Headers: map[string]string{"x-geo-country": "cn"}, HeadersLowercase: true,
		}, true, "匹配前会把请求头里的值转大写"},

		{"请求头值带空格仍命中", MatchCtx{
			Headers: map[string]string{"x-geo-country": " CN "}, HeadersLowercase: true,
		}, true, "匹配前会 TrimSpace"},

		{"不在名单内", MatchCtx{
			Headers: map[string]string{"x-geo-country": "JP"}, HeadersLowercase: true,
		}, false, "名单外的国家不应被拦"},

		{"两个头都在但都不命中", MatchCtx{
			Headers: map[string]string{"x-geo-country": "JP", "cf-ipcountry": "US"}, HeadersLowercase: true,
		}, false, "都不在名单时不应命中"},

		{"第一个头不命中时继续查第二个", MatchCtx{
			Headers: map[string]string{"x-geo-country": "JP", "cf-ipcountry": "CN"}, HeadersLowercase: true,
		}, true, "x-geo-country 未命中不代表结束，仍要看 cf-ipcountry"},

		{"两个头都没有", MatchCtx{}, false, "拿不到国家码时不应命中"},
	})
}
