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

// TestBuiltinRuleMetaCoversAllPatterns 校验全部检测 pattern 切片与
// builtinRuleMeta 双向一一对应：每个切片的每条 id 必须在元信息表中登记，
// 表中的每个键必须属于某个切片，且同一 id 不得同时属于两个切片。
//
// 排除依据：以下稳定 RuleID 是硬编码发射点而非 *Patterns 切片成员，其
// 备注由 catalog.go 逐条维护、不得进入 builtinRuleMeta，因此反向检查
// 会直接拦截任何把发射点误登记进本表的行为：
//   - owasp:path:001-017（owasp.go:724-800，emitPathRule 系列；无 003 发射路径）
//   - owasp:upload:001-007（owasp_extended.go:730-802 checkFileUpload 发射点）
//   - owasp:proto:001-010（owasp_extended.go:1107-1195 协议/方法检查发射点）
//   - owasp:crlf:005（owasp.go:234-239 路径裸 CR/LF 发射点）
//
// 反例：owasp:deser:012 虽在 owasp.go:311-318 有硬编码发射点，但同时是
// deserialPatterns 切片成员（owasp_extended.go:1067），必须在此登记。
func TestBuiltinRuleMetaCoversAllPatterns(t *testing.T) {
	// idOwner 记录每个 id 所属切片名，同时检出跨切片重复 id。
	idOwner := make(map[string]string)
	for _, g := range allPatternGroups() {
		if len(g.patterns) == 0 {
			t.Errorf("%s 为空，注册完整性校验失去意义", g.name)
			continue
		}
		for _, p := range g.patterns {
			meta, ok := builtinRuleMeta[p.id]
			if !ok {
				t.Errorf("builtinRuleMeta 缺少 %s 中的规则 %q", g.name, p.id)
				continue
			}
			if strings.TrimSpace(meta.name) == "" || strings.TrimSpace(meta.desc) == "" {
				t.Errorf("builtinRuleMeta[%q] 的名称或说明为空", p.id)
			}
			if prev, dup := idOwner[p.id]; dup {
				t.Errorf("规则 %q 同时出现在切片 %s 与 %s 中", p.id, prev, g.name)
			} else {
				idOwner[p.id] = g.name
			}
		}
	}
	for id := range builtinRuleMeta {
		if _, ok := idOwner[id]; !ok {
			// path/upload/proto/crlf:005 等硬编码发射点由 catalog.go 维护，
			// 出现于此说明被误登记进本表。
			t.Errorf("builtinRuleMeta 残留失效条目 %q，无任何 pattern 切片使用；硬编码发射点的备注应由 catalog.go 维护", id)
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
