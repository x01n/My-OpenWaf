package owasp

import (
	"strings"
	"testing"
)

// patternGroup 把一个检测 pattern 切片与它注册时使用的类别绑定在一起，
// 用于校验 DefaultOWASPRegistry 的注册完整性。
type patternGroup struct {
	name     string
	patterns []owaspPattern
	category OWASPCategory
}

// allPatternGroups 覆盖 owasp_registry.go 中 init() 注册的全部内置规则组。
// 新增一个 *Patterns 切片时必须同时在这里登记，否则注册完整性无人守护。
func allPatternGroups() []patternGroup {
	return []patternGroup{
		{"sqliPatterns", sqliPatterns, CatSQLi},
		{"xssPatterns", xssPatterns, CatXSS},
		{"cmdInjectPatterns", cmdInjectPatterns, CatCmdInject},
		{"ssrfPatterns", ssrfPatterns, CatSSRF},
		{"xxePatterns", xxePatterns, CatXXE},
		{"ldapiPatterns", ldapiPatterns, CatLDAPI},
		{"nosqliPatterns", nosqliPatterns, CatNoSQLi},
		{"tmplInjectPatterns", tmplInjectPatterns, CatTmplInject},
		{"jndiPatterns", jndiPatterns, CatJNDI},
		{"crlfPatterns", crlfPatterns, CatCRLF},
		{"exprLangPatterns", exprLangPatterns, CatExprLang},
		{"deserialPatterns", deserialPatterns, CatDeserial},
		{"graphqlPatterns", graphqlPatterns, CatGraphQLi},
		{"webshellPatterns", webshellPatterns, CatWebshell},
		{"revshellPatterns", revshellPatterns, CatRevShell},
		{"pathTravPatterns", pathTravPatterns, CatPathTrav},
	}
}

// TestRegistryCoversAllPatterns 校验每个检测 pattern 都已注册到运行时注册表，
// 且注册结果携带可展示的中文名称、说明与正确类别。
func TestRegistryCoversAllPatterns(t *testing.T) {
	for _, g := range allPatternGroups() {
		if len(g.patterns) == 0 {
			t.Errorf("%s 为空，注册完整性校验失去意义", g.name)
			continue
		}
		for _, p := range g.patterns {
			rule, ok := DefaultOWASPRegistry.Get(p.id)
			if !ok {
				t.Errorf("%s: 规则 %q 未注册到 DefaultOWASPRegistry", g.name, p.id)
				continue
			}
			if strings.TrimSpace(rule.Name) == "" {
				t.Errorf("%s: 规则 %q 的 Name 为空", g.name, p.id)
			}
			if strings.TrimSpace(rule.Description) == "" {
				t.Errorf("%s: 规则 %q 的 Description 为空", g.name, p.id)
			}
			if rule.Category != string(g.category) {
				t.Errorf("%s: 规则 %q 的 Category = %q，期望 %q", g.name, p.id, rule.Category, string(g.category))
			}
			if !rule.Enabled {
				t.Errorf("%s: 规则 %q 默认应启用", g.name, p.id)
			}
		}
	}
}

// TestRegistryRuleNamesAreLocalized 校验展示名称已中文化，
// 拦截 "XSS: id" 一类机械英文名称回归。
func TestRegistryRuleNamesAreLocalized(t *testing.T) {
	for _, rule := range DefaultOWASPRegistry.All() {
		if !containsHan(rule.Name) {
			t.Errorf("规则 %q 的 Name %q 不含中文，未完成本地化", rule.ID, rule.Name)
		}
		if !containsHan(rule.Description) {
			t.Errorf("规则 %q 的 Description %q 不含中文，未完成本地化", rule.ID, rule.Description)
		}
	}
}

// TestBuiltinRuleMetaCoversSQLiPatterns 校验 SQL 注入规则的中文元信息表
// 与检测 pattern 切片一一对应，既不缺失也不残留失效条目。
func TestBuiltinRuleMetaCoversSQLiPatterns(t *testing.T) {
	ids := make(map[string]struct{}, len(sqliPatterns))
	for _, p := range sqliPatterns {
		ids[p.id] = struct{}{}
		meta, ok := builtinRuleMeta[p.id]
		if !ok {
			t.Errorf("builtinRuleMeta 缺少 sqliPatterns 中的规则 %q", p.id)
			continue
		}
		if strings.TrimSpace(meta.name) == "" || strings.TrimSpace(meta.desc) == "" {
			t.Errorf("builtinRuleMeta[%q] 的名称或说明为空", p.id)
		}
	}
	for id := range builtinRuleMeta {
		if !strings.HasPrefix(id, "owasp:sqli:") {
			continue
		}
		if _, ok := ids[id]; !ok {
			t.Errorf("builtinRuleMeta 残留失效条目 %q，sqliPatterns 中已无对应 pattern", id)
		}
	}
}

// containsHan 判断字符串是否包含 CJK 统一汉字。
func containsHan(s string) bool {
	for _, r := range s {
		if r >= 0x4E00 && r <= 0x9FFF {
			return true
		}
	}
	return false
}
