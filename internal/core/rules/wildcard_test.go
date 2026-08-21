package rules

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/store"
)

// compileWildcardRules 走完整的 Compile 路径，确认新 kind 不会被 ParsePattern 丢弃。
func compileWildcardRules(t *testing.T) []Compiled {
	t.Helper()
	return Compile([]store.Rule{
		{Phase: "custom", Pattern: "path_wildcard:/admin/*", Action: "intercept", Priority: 1, Enabled: true},
	})
}

// buildWildcard 用 buildMatcher 直接构造匹配器，避免依赖 store.Rule 的其余字段。
func buildWildcard(t *testing.T, kind, arg string) Matcher {
	t.Helper()
	m := buildMatcher(kind, arg)
	if m == nil {
		t.Fatalf("buildMatcher(%q, %q) 返回 nil", kind, arg)
	}
	if _, isNever := m.(*neverMatcher); isNever {
		t.Fatalf("buildMatcher(%q, %q) 意外回落到 neverMatcher", kind, arg)
	}
	return m
}

// TestParsePatternRecognizesWildcardKinds 校验新 kind 走白名单前缀解析，
// 不会落进 compound 分支、也不会因未注册而被 Compile 丢弃。
func TestParsePatternRecognizesWildcardKinds(t *testing.T) {
	cases := []struct {
		pattern  string
		wantKind string
		wantArg  string
	}{
		{"path_wildcard:/admin/*", "path_wildcard", "/admin/*"},
		{"full_url_wildcard:*id=*", "full_url_wildcard", "*id=*"},
		{"host_wildcard:*.example.com", "host_wildcard", "*.example.com"},
		{"body_wildcard:*<script>*", "body_wildcard", "*<script>*"},
		{"header_wildcard:user-agent:*sqlmap*", "header_wildcard", "user-agent:*sqlmap*"},
	}
	for _, tc := range cases {
		kind, arg := ParsePattern(tc.pattern)
		if kind != tc.wantKind {
			t.Errorf("ParsePattern(%q) kind = %q, 期望 %q", tc.pattern, kind, tc.wantKind)
		}
		if arg != tc.wantArg {
			t.Errorf("ParsePattern(%q) arg = %q, 期望 %q", tc.pattern, arg, tc.wantArg)
		}
	}
}

func TestParsePatternPreservesWildcardBoundarySpaces(t *testing.T) {
	pattern := "path_wildcard: /admin/* "
	kind, arg := ParsePattern(pattern)
	if kind != "path_wildcard" {
		t.Fatalf("ParsePattern(%q) kind = %q, want path_wildcard", pattern, kind)
	}
	if arg != " /admin/* " {
		t.Fatalf("ParsePattern(%q) arg = %q, want boundary spaces preserved", pattern, arg)
	}
	if _, _, errs := ValidatePattern(pattern); len(errs) != 0 {
		t.Fatalf("ValidatePattern(%q) rejected a valid wildcard: %v", pattern, errs)
	}
}

func TestPathWildcardMatcher(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		// `*` 跨越 `/` 是本实现与 path.Match 的关键差异，正反例都要钉住。
		{"/admin/*", "/admin/login", true},
		{"/admin/*", "/admin/a/b/c", true},
		{"/admin/*", "/admin/", true},
		{"/admin/*", "/public/login", false},
		{"/admin/*", "/admin", false},
		{"*.php", "/index.php", true},
		{"*.php", "/a/b/index.php", true},
		{"*.php", "/index.phtml", false},
		{"/api/v?/users", "/api/v1/users", true},
		{"/api/v?/users", "/api/v10/users", false},
		{"/user[0-9]", "/user7", true},
		{"/user[0-9]", "/usera", false},
		{"/user[^0-9]", "/usera", true},
		{"/user[^0-9]", "/user7", false},
		{"/user[!0-9]", "/usera", true},
		{"/user[!0-9]", "/user7", false},
		// 锚定：模式必须覆盖整个路径，而非子串。
		{"/admin", "/admin/x", false},
		{"/admin", "/admin", true},
		// 大小写敏感，与 path_contains / block_path 一致。
		{"/Admin/*", "/admin/x", false},
		// 转义后的 `*` 是字面量。
		{`/a\*c`, "/a*c", true},
		{`/a\*c`, "/abc", false},
	}
	for _, tc := range cases {
		m := buildWildcard(t, "path_wildcard", tc.pattern)
		if got := m.Match(MatchCtx{Path: tc.path}); got != tc.want {
			t.Errorf("path_wildcard:%q 对 path=%q 得到 %v, 期望 %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestFullURLWildcardMatcher(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		query   string
		want    bool
	}{
		{"*id=*", "/item", "id=1", true},
		{"/item?id=*", "/item", "id=1", true},
		{"*union*select*", "/q", "a=union+x+select", true},
		{"*id=*", "/item", "", false},
		{"/item", "/item", "", true},
		{"/item", "/item", "id=1", false},
		// full_url_contains 大小写不敏感，本 kind 与之对齐。
		{"*UNION*", "/q", "a=union", true},
		{"*union*", "/q", "a=UNION", true},
	}
	for _, tc := range cases {
		m := buildWildcard(t, "full_url_wildcard", tc.pattern)
		got := m.Match(MatchCtx{Path: tc.path, Query: tc.query})
		if got != tc.want {
			t.Errorf("full_url_wildcard:%q 对 path=%q query=%q 得到 %v, 期望 %v",
				tc.pattern, tc.path, tc.query, got, tc.want)
		}
	}
}

func TestHostWildcardMatcher(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "evil.com", false},
		// 端口被 splitHostPortHeader 剥离，与其余 host* 匹配器一致。
		{"*.example.com", "api.example.com:8443", true},
		{"example.com", "EXAMPLE.COM", true},
		{"*.EXAMPLE.com", "api.example.com", true},
		{"api?.example.com", "api1.example.com", true},
		{"api?.example.com", "api.example.com", false},
	}
	for _, tc := range cases {
		m := buildWildcard(t, "host_wildcard", tc.pattern)
		if got := m.Match(MatchCtx{Host: tc.host}); got != tc.want {
			t.Errorf("host_wildcard:%q 对 host=%q 得到 %v, 期望 %v", tc.pattern, tc.host, got, tc.want)
		}
	}
	// 空 Host 不应命中。
	m := buildWildcard(t, "host_wildcard", "*.example.com")
	if m.Match(MatchCtx{}) {
		t.Error("host_wildcard 在 Host 缺失时不应命中")
	}
	// Host 缺失时回落到 header 查找。
	if !m.Match(MatchCtx{Headers: map[string]string{"Host": "api.example.com"}}) {
		t.Error("host_wildcard 应能从 Host 头取值")
	}
}

func TestBodyWildcardMatcher(t *testing.T) {
	cases := []struct {
		pattern string
		body    string
		want    bool
	}{
		{"*<script>*", `{"a":"<script>alert(1)</script>"}`, true},
		{"*<script>*", `{"a":"safe"}`, false},
		{"*union*select*", "id=1 union select 1,2", true},
		// `*` 覆盖换行，避免插入换行绕过。
		{"*a*b*", "a\nb", true},
		{"*passwd*", "file=/etc/passwd", true},
		{"*<SCRIPT>*", `{"a":"<script>"}`, false}, // 大小写敏感，与 body_contains 一致
	}
	for _, tc := range cases {
		m := buildWildcard(t, "body_wildcard", tc.pattern)
		if got := m.Match(MatchCtx{Body: []byte(tc.body)}); got != tc.want {
			t.Errorf("body_wildcard:%q 对 body=%q 得到 %v, 期望 %v", tc.pattern, tc.body, got, tc.want)
		}
	}
	// 空 body 不命中，与 bodyContainsMatcher 的短路一致。
	m := buildWildcard(t, "body_wildcard", "*")
	if m.Match(MatchCtx{Body: nil}) {
		t.Error("body_wildcard 在 body 为空时不应命中")
	}
}

func TestHeaderWildcardMatcher(t *testing.T) {
	cases := []struct {
		arg     string
		headers map[string]string
		want    bool
	}{
		// 含 `/` 的真实头值：这是选择跨 `/` 语义的直接动因。
		{"user-agent:*sqlmap*", map[string]string{"User-Agent": "sqlmap/1.5.2#stable"}, true},
		{"user-agent:*bot*", map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"}, true},
		{"content-type:*application/json*", map[string]string{"Content-Type": "application/json; charset=utf-8"}, true},
		{"user-agent:*sqlmap*", map[string]string{"User-Agent": "curl/8.0"}, false},
		// 头名大小写不敏感查找。
		{"User-Agent:*curl*", map[string]string{"user-agent": "curl/8.0"}, true},
		// 头缺失不命中。
		{"x-token:*", map[string]string{"User-Agent": "curl/8.0"}, false},
		// 值大小写敏感，与 headerContainsMatcher / headerRegexMatcher 一致。
		{"user-agent:*SQLMAP*", map[string]string{"User-Agent": "sqlmap/1.5"}, false},
	}
	for _, tc := range cases {
		m := buildWildcard(t, "header_wildcard", tc.arg)
		got := m.Match(MatchCtx{Headers: tc.headers})
		if got != tc.want {
			t.Errorf("header_wildcard:%q 对 headers=%v 得到 %v, 期望 %v", tc.arg, tc.headers, got, tc.want)
		}
	}
}

// TestHeaderWildcardMissingNameOrPattern 覆盖 arg 缺少 name 或 pattern 的情形。
// splitHeaderArg 要求冒号下标 > 0，因此 ":*x*" 会被整体当作 name、pattern 为空。
func TestHeaderWildcardMissingNameOrPattern(t *testing.T) {
	degenerate := []string{
		"user-agent", // 无冒号 → pattern 为空
		"",           // 全空
		":*sqlmap*",  // 冒号在下标 0 → name 取整串、pattern 为空
	}
	for _, arg := range degenerate {
		m := buildMatcher("header_wildcard", arg)
		if _, isNever := m.(*neverMatcher); !isNever {
			t.Errorf("header_wildcard:%q 应回落 neverMatcher, 实际 %T", arg, m)
		}
		if _, _, errs := ValidatePattern("header_wildcard:" + arg); len(errs) == 0 {
			t.Errorf("header_wildcard:%q 应在保存期被拒绝", arg)
		}
	}
}

// TestValidatePatternWildcardAccepts 合法模式必须被 ValidatePattern 放行，
// 且 kind 解析正确。
func TestValidatePatternWildcardAccepts(t *testing.T) {
	patterns := []string{
		"path_wildcard:/admin/*",
		"path_wildcard:/user[0-9]",
		`path_wildcard:/a\*c`,
		"path_wildcard:/a[!0-9]b",
		"full_url_wildcard:*id=*",
		"host_wildcard:*.example.com",
		"body_wildcard:*<script>*",
		"header_wildcard:user-agent:*sqlmap*",
		// 类内字面 `]` 需写作 `\]`。
		`path_wildcard:/a[\]]b`,
	}
	for _, p := range patterns {
		kind, _, errs := ValidatePattern(p)
		if kind == "" {
			t.Errorf("ValidatePattern(%q) 未识别出 kind", p)
		}
		if len(errs) != 0 {
			t.Errorf("ValidatePattern(%q) 意外报错: %v", p, errs)
		}
	}
}

// TestValidatePatternWildcardStarLimit 确保未转义的第九个通配星号在保存期被拒绝。
func TestValidatePatternWildcardStarLimit(t *testing.T) {
	withinLimit := strings.Repeat("a*", 8) + "end"
	if _, _, errs := ValidatePattern("path_wildcard:" + withinLimit); len(errs) != 0 {
		t.Fatalf("含 8 个未转义星号的模式意外被拒绝: %v", errs)
	}

	overLimit := strings.Repeat("a*", 9) + "end"
	if _, _, errs := ValidatePattern("path_wildcard:" + overLimit); len(errs) == 0 {
		t.Error("含第九个未转义星号的模式应在保存期被拒绝")
	}
	m := buildMatcher("path_wildcard", overLimit)
	if _, isNever := m.(*neverMatcher); !isNever {
		t.Errorf("含第九个未转义星号的直改规则应 fail-closed，实际 %T", m)
	}

	escapedStars := strings.Repeat(`a\*`, 9) + "end"
	if _, _, errs := ValidatePattern("path_wildcard:" + escapedStars); len(errs) != 0 {
		t.Errorf("转义星号不应占用通配星号预算: %v", errs)
	}
}

// TestValidatePatternWildcardRejectsIllegal 非法模式必须在保存期就被拒绝，
// 而不是编译成 neverMatcher 后在运行期静默永不命中。
func TestValidatePatternWildcardRejectsIllegal(t *testing.T) {
	illegal := []string{
		"path_wildcard:/a[",      // 字符类未闭合
		"path_wildcard:/a[b",     // 字符类未闭合
		"path_wildcard:/a[b-",    // 字符类未闭合
		`path_wildcard:/a\`,      // 悬空转义符
		"path_wildcard:/a[]",     // 空字符类
		"path_wildcard:/a[^]",    // 取反空字符类
		"path_wildcard:/a[z-a]",  // 反向字符区间会被 RE2 拒绝
		`path_wildcard:/a[\`,     // 类内悬空转义符
		"path_wildcard:",         // 空模式
		"path_wildcard:   ",      // 仅空白
		"full_url_wildcard:/a[",  //
		"host_wildcard:*.[",      //
		"body_wildcard:*[",       //
		"full_url_wildcard:",     // 空模式
		"host_wildcard:",         // 空模式
		"body_wildcard:",         // 空模式
		"header_wildcard:ua:/a[", // 头值模式非法
	}
	for _, p := range illegal {
		_, _, errs := ValidatePattern(p)
		if len(errs) == 0 {
			t.Errorf("ValidatePattern(%q) 应报错, 实际放行", p)
		}
	}
	// 非法模式若绕过保存期校验直改数据库，运行期必须 fail-closed。
	for _, p := range illegal {
		kind, arg := ParsePattern(p)
		if kind == "" {
			continue
		}
		m := buildMatcher(kind, arg)
		if _, isNever := m.(*neverMatcher); !isNever {
			t.Errorf("%q 运行期应回落 neverMatcher, 实际 %T", p, m)
		}
	}
}

// TestGlobToRegexSourceAnchorsAndFlags 钉住翻译产物的锚定与标志位。
// 锚点只在对应一端没有通配星号时出现：首尾星号靠"省掉锚点 + 非锚定搜索"
// 表达，而不是前导 `.*`，否则 RE2 无法启用字面量预扫描。
func TestGlobToRegexSourceAnchorsAndFlags(t *testing.T) {
	cases := []struct {
		pattern   string
		wantHeadA bool // 是否应有 \A
		wantTailZ bool // 是否应有 \z
	}{
		{"/admin/x", true, true},
		{"/admin/*", true, false},
		{"*admin", false, true},
		{"*admin*", false, false},
	}
	for _, tc := range cases {
		src, err := globToRegexSource(tc.pattern, false)
		if err != nil {
			t.Fatalf("globToRegexSource(%q) 意外报错: %v", tc.pattern, err)
		}
		if !strings.HasPrefix(src, "(?s)") {
			t.Errorf("%q 的翻译产物应带 (?s) 使 `.` 覆盖换行, 得到 %q", tc.pattern, src)
		}
		if got := strings.Contains(src, `\A`); got != tc.wantHeadA {
			t.Errorf("%q 的 \\A 存在性 = %v, 期望 %v (src=%q)", tc.pattern, got, tc.wantHeadA, src)
		}
		if got := strings.HasSuffix(src, `\z`); got != tc.wantTailZ {
			t.Errorf("%q 的 \\z 存在性 = %v, 期望 %v (src=%q)", tc.pattern, got, tc.wantTailZ, src)
		}
		// 不应再出现前导/尾随 `.*`，那会压制 RE2 的字面量预扫描。
		if strings.Contains(src, `(?s).*`) || strings.HasSuffix(src, `.*\z`) {
			t.Errorf("%q 的翻译产物残留首尾 `.*`: %q", tc.pattern, src)
		}
	}

	ci, err := globToRegexSource("/x?y", true)
	if err != nil {
		t.Fatalf("意外报错: %v", err)
	}
	if !strings.Contains(ci, "(?i)") {
		t.Errorf("大小写不敏感模式应带 (?i), 得到 %q", ci)
	}
	// 正则元字符必须被转义为字面量。
	m := buildWildcard(t, "path_wildcard", "/a.b+c")
	if m.Match(MatchCtx{Path: "/axbxc"}) {
		t.Error("`.` 与 `+` 应作为字面量，不应按正则元字符解释")
	}
	if !m.Match(MatchCtx{Path: "/a.b+c"}) {
		t.Error("字面量路径应命中")
	}
}

// TestWildcardUnicodeAndFullStringAnchoring 确保 `?` 按 Unicode 字符匹配，且正则路径仍覆盖整个目标串。
func TestWildcardUnicodeAndFullStringAnchoring(t *testing.T) {
	m := buildWildcard(t, "path_wildcard", "/用户/?")
	if !m.Match(MatchCtx{Path: "/用户/甲"}) {
		t.Error("? 应匹配一个 Unicode 字符")
	}
	if m.Match(MatchCtx{Path: "/用户/甲乙"}) {
		t.Error("? 不应匹配两个 Unicode 字符")
	}

	classMatcher := buildWildcard(t, "path_wildcard", "/[甲乙]")
	if !classMatcher.Match(MatchCtx{Path: "/甲"}) || classMatcher.Match(MatchCtx{Path: "/丙"}) {
		t.Error("Unicode 字符类应仅匹配其列出的字符")
	}

	anchored := buildWildcard(t, "path_wildcard", "/?dmin")
	if !anchored.Match(MatchCtx{Path: "/admin"}) {
		t.Error("完整目标串应命中")
	}
	for _, path := range []string{"/xadmin", "/adminx"} {
		if anchored.Match(MatchCtx{Path: path}) {
			t.Errorf("模式未覆盖整个目标串时不应命中: %q", path)
		}
	}
}

// TestWildcardCompiledMetadata 校验新 kind 经 Compile 后带上正确的元数据，
// 且能被 ParsePattern 识别而不被丢弃。
func TestWildcardCompiledMetadata(t *testing.T) {
	compiled := compileWildcardRules(t)
	if len(compiled) != 1 {
		t.Fatalf("期望编译出 1 条规则, 得到 %d", len(compiled))
	}
	if compiled[0].Kind != "path_wildcard" {
		t.Errorf("Kind = %q, 期望 path_wildcard", compiled[0].Kind)
	}
	if compiled[0].matchDesc != "path_wildcard:/admin/*" {
		t.Errorf("matchDesc = %q", compiled[0].matchDesc)
	}
	if !compiled[0].Match(MatchCtx{Path: "/admin/a/b"}) {
		t.Error("编译后的规则应命中 /admin/a/b")
	}
}

// TestWildcardInCompoundCondition 新 kind 作为复合条件叶子节点也要可用。
func TestWildcardInCompoundCondition(t *testing.T) {
	pattern := `{"op":"and","children":[{"kind":"path_wildcard","arg":"/admin/*"},{"kind":"host_wildcard","arg":"*.example.com"}]}`
	if _, _, errs := ValidatePattern(pattern); len(errs) != 0 {
		t.Fatalf("复合条件校验意外报错: %v", errs)
	}
	m := buildMatcher("compound", pattern)
	if !m.Match(MatchCtx{Path: "/admin/a/b", Host: "api.example.com"}) {
		t.Error("复合条件应命中")
	}
	if m.Match(MatchCtx{Path: "/admin/a/b", Host: "evil.com"}) {
		t.Error("host 不符时复合条件不应命中")
	}
	// 复合条件内的非法通配符模式同样要在保存期被拒。
	bad := `{"op":"and","children":[{"kind":"path_wildcard","arg":"/a["}]}`
	if _, _, errs := ValidatePattern(bad); len(errs) == 0 {
		t.Error("复合条件内的非法通配符模式应被拒绝")
	}
}

// TestWildcardMaliciousPatternTerminates 恶意模式必须在合理时间内返回。
// RE2 无回溯，故此处只验证不挂死、结果正确。
func TestWildcardMaliciousPatternTerminates(t *testing.T) {
	m := buildWildcard(t, "body_wildcard", strings.Repeat("a*", maxUnescapedWildcardStars)+"b")
	body := []byte(strings.Repeat("a", 4096))
	if m.Match(MatchCtx{Body: body}) {
		t.Error("末尾缺少 b 时不应命中")
	}
	if !m.Match(MatchCtx{Body: append(body, 'b')}) {
		t.Error("末尾有 b 时应命中")
	}
}

// TestWildcardShapeSelection 钉住哪些模式形态走字面量快路径。
// 形态判定错误会让匹配语义悄悄改变，因此必须显式断言。
func TestWildcardShapeSelection(t *testing.T) {
	cases := []struct {
		pattern   string
		fold      bool
		wantShape wildcardShape
	}{
		{"abc", false, wcExact},
		{"*abc*", false, wcContains},
		{"abc*", false, wcPrefix},
		{"*abc", false, wcSuffix},
		{"*", false, wcAny},
		{"**", false, wcAny},
		{"a*b", false, wcRegex},    // 中缀星号
		{"a?b", false, wcRegex},    // 单字符通配
		{"a[0-9]", false, wcRegex}, // 字符类
		{`a\*b`, false, wcExact},   // 转义星号是字面量
		// 大小写不敏感时只有 contains 形态有折叠实现，其余回落正则。
		{"*abc*", true, wcContains},
		{"abc", true, wcRegex},
		{"abc*", true, wcRegex},
		{"*abc", true, wcRegex},
	}
	for _, tc := range cases {
		w, err := compileWildcard(tc.pattern, tc.fold)
		if err != nil {
			t.Fatalf("compileWildcard(%q, %v) 报错: %v", tc.pattern, tc.fold, err)
		}
		if w.shape != tc.wantShape {
			t.Errorf("compileWildcard(%q, fold=%v) shape = %d, 期望 %d",
				tc.pattern, tc.fold, w.shape, tc.wantShape)
		}
	}
}

// TestCollapseGlobStars 连续星号必须归并，否则 `.*.*` 会白白放大 RE2 程序规模。
// 转义星号与字符类内的星号不参与归并。
func TestCollapseGlobStars(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a*b", "a*b"},
		{"a**b", "a*b"},
		{"a***b", "a*b"},
		{"**", "*"},
		{"***", "*"},
		{"*a*b*", "*a*b*"},
		{`a\**`, `a\**`},     // `\*` 是字面星号，不与后面的通配星号归并
		{`a\*\*b`, `a\*\*b`}, // 两个字面星号
		{"a[*]*b", "a[*]*b"}, // 类内星号不参与
		{"a[*][*]b", "a[*][*]b"},
	}
	for _, tc := range cases {
		if got := collapseGlobStars(tc.in); got != tc.want {
			t.Errorf("collapseGlobStars(%q) = %q, 期望 %q", tc.in, got, tc.want)
		}
	}
	// 归并不得改变匹配结果。
	for _, p := range []string{"a**b", "**", "*a**b*", `a\**`} {
		wCollapsed := buildWildcard(t, "path_wildcard", p)
		wSingle := buildWildcard(t, "path_wildcard", collapseGlobStars(p))
		for _, target := range []string{"ab", "axb", "a*b", "a*xb", "", "b", "axxb"} {
			if wCollapsed.Match(MatchCtx{Path: target}) != wSingle.Match(MatchCtx{Path: target}) {
				t.Errorf("归并改变了语义: pattern=%q target=%q", p, target)
			}
		}
	}
}

// TestWildcardFastPathMatchesRegexPath 差分测试：字面量快路径与纯正则路径
// 必须在所有输入上给出相同结果。快路径是性能优化，不得改变语义。
func TestWildcardFastPathMatchesRegexPath(t *testing.T) {
	patterns := []string{
		"abc", "*abc*", "abc*", "*abc", "*", "**",
		"/admin", "*/admin/*", "/admin/*", "*.php",
		`a\*b`, "*a*", "a", "/",
	}
	targets := []string{
		"", "a", "abc", "abcd", "xabc", "xabcx", "ABC",
		"/admin", "/admin/", "/admin/x", "/x/admin/y",
		"/index.php", "a*b", "/", "a\nb", "abc\nabc",
	}
	for _, p := range patterns {
		parsed, err := parseGlob(p)
		if err != nil {
			t.Fatalf("parseGlob(%q) 报错: %v", p, err)
		}
		for _, fold := range []bool{false, true} {
			w, err := compileWildcard(p, fold)
			if err != nil {
				t.Fatalf("compileWildcard(%q, %v) 报错: %v", p, fold, err)
			}
			// 强制走正则作为基准。
			baseline, err := cachedCompile(parsed.regexSource(fold))
			if err != nil {
				t.Fatalf("基准正则编译失败 (%q, fold=%v): %v", p, fold, err)
			}
			for _, target := range targets {
				want := baseline.MatchString(target)
				if got := w.matchString(target); got != want {
					t.Errorf("字符串路径不一致: pattern=%q fold=%v target=%q 快路径=%v 正则=%v (shape=%d)",
						p, fold, target, got, want, w.shape)
				}
				if got := w.matchBytes([]byte(target)); got != want {
					t.Errorf("字节路径不一致: pattern=%q fold=%v target=%q 快路径=%v 正则=%v (shape=%d)",
						p, fold, target, got, want, w.shape)
				}
			}
		}
	}
}

func BenchmarkPathWildcardMatch(b *testing.B) {
	m := buildMatcher("path_wildcard", "/admin/*")
	ctx := MatchCtx{Path: "/admin/users/42/edit"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkWildcard = m.Match(ctx)
	}
}

func BenchmarkPathWildcardMiss(b *testing.B) {
	m := buildMatcher("path_wildcard", "/admin/*")
	ctx := MatchCtx{Path: "/public/assets/app.js"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkWildcard = m.Match(ctx)
	}
}

func BenchmarkHeaderWildcardMatch(b *testing.B) {
	m := buildMatcher("header_wildcard", "user-agent:*sqlmap*")
	ctx := MatchCtx{Headers: map[string]string{"user-agent": "sqlmap/1.5.2#stable"}, HeadersLowercase: true}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkWildcard = m.Match(ctx)
	}
}

func BenchmarkBodyWildcardMatch(b *testing.B) {
	m := buildMatcher("body_wildcard", "*<script>*")
	body := []byte(strings.Repeat("x", 2048) + "<script>alert(1)</script>")
	ctx := MatchCtx{Body: body}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkWildcard = m.Match(ctx)
	}
}

// BenchmarkWildcardManyStars 恶意模式的热路径开销。
func BenchmarkWildcardManyStars(b *testing.B) {
	m := buildMatcher("body_wildcard", strings.Repeat("a*", maxUnescapedWildcardStars)+"b")
	ctx := MatchCtx{Body: []byte(strings.Repeat("a", 400))}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkWildcard = m.Match(ctx)
	}
}

// BenchmarkWildcardBuildCached 校验 buildMatcher 复用全局正则缓存，
// 不会每次重新编译。
func BenchmarkWildcardBuildCached(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkMatcher = buildMatcher("path_wildcard", "/admin/*")
	}
}

var (
	sinkWildcard bool
	sinkMatcher  Matcher
)
