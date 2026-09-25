package owasp

import "testing"

// TestDetectionCoverageAssertions R2-D 覆盖确认：每类至少 1 条 pattern，
// 该 pattern 进入 DefaultOWASPRegistry，注册分类与 pattern 所属类别一致。
// 调用点全链由 firstOWASPHitWithThresholds 主循环 grep 核实（见 r2-report.md 确认表）。
func TestDetectionCoverageAssertions(t *testing.T) {
	groups := []struct {
		name     string
		category OWASPCategory
		patterns []owaspPattern
	}{
		{"sqli", CatSQLi, sqliPatterns},
		{"xss", CatXSS, xssPatterns},
		{"cmd", CatCmdInject, cmdInjectPatterns},
		{"webshell", CatWebshell, webshellPatterns},
		{"revshell", CatRevShell, revshellPatterns},
		{"path_trav", CatPathTrav, pathTravPatterns},
		{"ssrf", CatSSRF, ssrfPatterns},
		{"xxe", CatXXE, xxePatterns},
		{"ldap", CatLDAPI, ldapiPatterns},
		{"nosql", CatNoSQLi, nosqliPatterns},
		{"template", CatTmplInject, tmplInjectPatterns},
		{"jndi", CatJNDI, jndiPatterns},
		{"crlf", CatCRLF, crlfPatterns},
		{"expr_lang", CatExprLang, exprLangPatterns},
		{"deserial", CatDeserial, deserialPatterns},
		{"graphql", CatGraphQLi, graphqlPatterns},
	}
	for _, g := range groups {
		if len(g.patterns) == 0 {
			t.Errorf("%s: pattern 表为空", g.name)
			continue
		}
		sample := g.patterns[0]
		if sample.re == nil || sample.id == "" {
			t.Errorf("%s: 首条 pattern 未完整初始化", g.name)
			continue
		}
		rule, ok := DefaultOWASPRegistry.Get(sample.id)
		if !ok {
			t.Errorf("%s: %s 未注册进 DefaultOWASPRegistry", g.name, sample.id)
			continue
		}
		if rule.Category != string(g.category) {
			t.Errorf("%s: 注册分类 %q != 期望 %q", g.name, rule.Category, g.category)
		}
		if !rule.Enabled {
			t.Errorf("%s: %s 默认未启用", g.name, sample.id)
		}
	}
}
