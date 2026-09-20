package owasp

import "testing"

// wl 构造只含单条规则的覆盖表，规则 ID 使用真实内置 ID 以免依赖"未知规则默认启用"的兜底。
func wl(entries ...string) map[string]OWASPRuleOverride {
	return map[string]OWASPRuleOverride{"owasp:upload:003": {Whitelist: entries}}
}

const wlRuleID = "owasp:upload:003"

// TestIsPathWhitelistedMatchSemantics 覆盖白名单三种语义：
// 全局 "*"、末尾通配前缀、以及默认的精确匹配（不做隐式前缀扩展）。
func TestIsPathWhitelistedMatchSemantics(t *testing.T) {
	cases := []struct {
		name    string
		entries []string
		path    string
		want    bool
	}{
		{"全局通配豁免任意路径", []string{"*"}, "/anything/deep", true},
		{"精确匹配命中", []string{"/exact"}, "/exact", true},
		{"精确匹配不扩展到子路径", []string{"/exact"}, "/exact/sub", false},
		{"精确匹配不命中同前缀兄弟路径", []string{"/exact"}, "/exactly", false},
		{"子树通配命中子路径", []string{"/static/*"}, "/static/app.js", true},
		{"子树通配命中前缀自身", []string{"/static/*"}, "/static", true},
		{"子树通配不命中同前缀兄弟路径", []string{"/static/*"}, "/static-public/app.js", false},
		{"字面前缀通配命中同前缀兄弟路径", []string{"/static*"}, "/static-public/app.js", true},
		{"根通配等价于全局豁免", []string{"/*"}, "/anything", true},
		{"多条目命中其中之一", []string{"/a", "/b/*", "/c"}, "/b/inner", true},
		{"多条目全不命中", []string{"/a", "/b/*", "/c"}, "/d", false},
		{"无覆盖时不豁免", nil, "/anything", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsPathWhitelisted(wlRuleID, tc.path, wl(tc.entries...))
			if got != tc.want {
				t.Fatalf("IsPathWhitelisted(%q, entries=%v) = %v, want %v", tc.path, tc.entries, got, tc.want)
			}
		})
	}
}

// TestIsPathWhitelistedNormalizationIsSymmetric 校验大小写、首尾空白与尾随斜杠
// 在"白名单条目"与"请求路径"两侧被同样归一化。
// 回归目标：修复前 "/Admin/*" 无法命中 "/admin/x"，而 "/admin/*" 却能命中 "/ADMIN/x"。
func TestIsPathWhitelistedNormalizationIsSymmetric(t *testing.T) {
	cases := []struct {
		name    string
		entries []string
		path    string
	}{
		{"条目大写命中小写路径", []string{"/Admin/*"}, "/admin/x"},
		{"条目小写命中大写路径", []string{"/admin/*"}, "/ADMIN/x"},
		{"条目前导空白被裁剪", []string{" /admin/*"}, "/admin/x"},
		{"条目尾随空白被裁剪", []string{"/admin/* "}, "/admin/x"},
		{"精确条目大小写不敏感", []string{"/Exact"}, "/exact"},
		{"条目尾随斜杠等价于无斜杠", []string{"/admin/"}, "/admin"},
		{"路径尾随斜杠等价于无斜杠", []string{"/admin"}, "/admin/"},
		{"路径缺失前导斜杠被补齐", []string{"/admin"}, "admin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !IsPathWhitelisted(wlRuleID, tc.path, wl(tc.entries...)) {
				t.Fatalf("entries=%v path=%q 应命中白名单", tc.entries, tc.path)
			}
		})
	}
}

// TestIsPathWhitelistedIgnoresBlankEntries 校验空条目被忽略。
// 回归目标：修复前 "" 会被补成 "/" 并豁免根路径，等于凭空放开一条路径。
func TestIsPathWhitelistedIgnoresBlankEntries(t *testing.T) {
	for _, entry := range []string{"", " ", "\t", "\n"} {
		if IsPathWhitelisted(wlRuleID, "/", wl(entry)) {
			t.Errorf("空条目 %q 不应豁免根路径", entry)
		}
		if IsPathWhitelisted(wlRuleID, "/admin", wl(entry)) {
			t.Errorf("空条目 %q 不应豁免任意路径", entry)
		}
	}
	// 空条目与有效条目共存时，有效条目仍应生效。
	if !IsPathWhitelisted(wlRuleID, "/admin", wl("", "/admin")) {
		t.Error("空条目不应影响同表中有效条目的匹配")
	}
}

// TestIsPathWhitelistedRejectsTraversalEscape 是本次修复的核心安全断言：
// 前缀白名单只应豁免它字面声明的子树。路径含 ".." 时前缀匹配不再证明请求落在子树内，
// 必须拒绝豁免，否则 "/static/../admin" 可借白名单完全跳过该规则的检测。
func TestIsPathWhitelistedRejectsTraversalEscape(t *testing.T) {
	escapes := []struct {
		name string
		path string
	}{
		{"明文点点穿越", "/static/../admin"},
		{"多级明文穿越", "/static/../../etc/passwd"},
		{"单次编码穿越", "/static/..%2fadmin"},
		{"点被编码的穿越", "/static/%2e%2e/admin"},
		{"双重编码穿越", "/static/%252e%252e/admin"},
		{"反斜杠分隔穿越", "/static/..\\admin"},
		{"点点后缀变体", "/static/.../admin"},
		{"NUL 截断", "/static/app.js\x00.php"},
		{"编码 NUL 截断", "/static/app.js%00.php"},
	}
	for _, entry := range []string{"/static/*", "/static*"} {
		for _, tc := range escapes {
			t.Run(entry+"|"+tc.name, func(t *testing.T) {
				if IsPathWhitelisted(wlRuleID, tc.path, wl(entry)) {
					t.Fatalf("条目 %q 不应豁免可跳出前缀的路径 %q", entry, tc.path)
				}
			})
		}
	}

	// 精确匹配条目本就不会命中带穿越的路径，行为保持不变。
	if IsPathWhitelisted(wlRuleID, "/static/../admin", wl("/static")) {
		t.Error("精确条目不应命中穿越路径")
	}

	// "*" 没有前缀边界，穿越检查对它无意义，语义保持"豁免一切"。
	if !IsPathWhitelisted(wlRuleID, "/static/../admin", wl("*")) {
		t.Error(`"*" 应继续豁免全部路径，包括含穿越的路径`)
	}
}

// TestIsPathWhitelistedAllowsBenignDotsAndEncoding 校验穿越检查没有过度拦截：
// 单点段、文件名中的点、以及正常的百分号编码路径仍应被白名单豁免。
func TestIsPathWhitelistedAllowsBenignDotsAndEncoding(t *testing.T) {
	benign := []string{
		"/static/app.min.js",
		"/static/./app.js",
		"/static/.well-known/x",
		"/static/..bashrc-like-name",
		"/static/a..b/app.js",
		"/static/my%20file.js",
		"/static/%E4%B8%AD%E6%96%87.js",
	}
	for _, path := range benign {
		if !IsPathWhitelisted(wlRuleID, path, wl("/static/*")) {
			t.Errorf("良性路径 %q 应命中 /static/* 白名单", path)
		}
	}
}

// TestShouldSkipRulePrecedence 校验跳过判定的两个来源各自独立生效：
// 规则被显式关闭时无论路径都跳过；规则启用时仅路径命中白名单才跳过。
func TestShouldSkipRulePrecedence(t *testing.T) {
	disabled := false
	enabled := true

	cases := []struct {
		name      string
		override  OWASPRuleOverride
		path      string
		wantSkip  bool
		assertion string
	}{
		{
			name:      "显式关闭且路径不在白名单内仍跳过",
			override:  OWASPRuleOverride{Enabled: &disabled, Whitelist: []string{"/other"}},
			path:      "/admin",
			wantSkip:  true,
			assertion: "关闭开关独立于白名单生效",
		},
		{
			name:      "显式启用且路径命中白名单则跳过",
			override:  OWASPRuleOverride{Enabled: &enabled, Whitelist: []string{"/admin"}},
			path:      "/admin",
			wantSkip:  true,
			assertion: "启用状态不会压制白名单豁免",
		},
		{
			name:      "显式启用且无白名单不跳过",
			override:  OWASPRuleOverride{Enabled: &enabled},
			path:      "/admin",
			wantSkip:  false,
			assertion: "启用且无豁免时必须参与检测",
		},
		{
			name:      "未设置开关沿用注册表默认启用",
			override:  OWASPRuleOverride{},
			path:      "/admin",
			wantSkip:  false,
			assertion: "空覆盖不应改变默认启用状态",
		},
		{
			name:      "启用但路径含穿越时不跳过",
			override:  OWASPRuleOverride{Enabled: &enabled, Whitelist: []string{"/static/*"}},
			path:      "/static/../admin",
			wantSkip:  false,
			assertion: "穿越路径不得借白名单跳过检测",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			overrides := map[string]OWASPRuleOverride{wlRuleID: tc.override}
			if got := ShouldSkipRule(wlRuleID, tc.path, overrides); got != tc.wantSkip {
				t.Fatalf("ShouldSkipRule(%q) = %v, want %v（%s）", tc.path, got, tc.wantSkip, tc.assertion)
			}
		})
	}
}

// TestShouldSkipRuleWithoutOverrides 校验无覆盖表时的默认行为：
// 已注册的内置规则默认启用，因此不跳过；未知规则也按启用处理。
func TestShouldSkipRuleWithoutOverrides(t *testing.T) {
	if ShouldSkipRule(wlRuleID, "/admin", nil) {
		t.Error("nil 覆盖表下已注册规则不应跳过")
	}
	if ShouldSkipRule(wlRuleID, "/admin", map[string]OWASPRuleOverride{}) {
		t.Error("空覆盖表下已注册规则不应跳过")
	}
	if ShouldSkipRule("owasp:not-a-real-rule:999", "/admin", nil) {
		t.Error("未知规则应按启用处理，不跳过")
	}
}

// TestDecodePathForMatchRoundsAreBounded 校验解码轮数有上限，
// 超出上限的深层嵌套编码不会被继续展开，避免为畸形输入付出无界解码成本。
func TestDecodePathForMatchRoundsAreBounded(t *testing.T) {
	// %25 每轮解出一个 "%"，嵌套层数远超上限。
	deep := "/static/" + "%25252525252525252e%25252525252525252e" + "/admin"
	if _, escapes := decodePathForMatch(deep); escapes {
		t.Log("深层嵌套在上限内已判定为穿越")
	}
	// 无论是否判定为穿越，都不得因超深嵌套而豁免。
	if IsPathWhitelisted(wlRuleID, deep, wl("/static/*")) {
		t.Fatal("超深嵌套编码路径不应被白名单豁免")
	}
}
