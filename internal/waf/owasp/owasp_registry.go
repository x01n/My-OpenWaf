package owasp

import (
	"encoding/json"
	"strings"
	"sync"
)

// OWASPRule represents a single granular OWASP detection rule with its own ID,
// category, and enable/disable switch. Each rule wraps one check function.
type OWASPRule struct {
	ID          string // e.g. "OWASP-SQLI-001"
	Category    string // e.g. "sqli"
	Name        string // e.g. "SQL Union Injection"
	Description string
	Enabled     bool // default true
	CheckFunc   func(input string) (score int, matched bool, desc string)
}

// OWASPRuleOverride allows per-rule configuration stored in ProtectionConfig.
type OWASPRuleOverride struct {
	Enabled     *bool    `json:"enabled,omitempty"`
	Whitelist   []string `json:"whitelist,omitempty"` // path whitelist — matching paths skip this rule
	Action      string   `json:"action,omitempty"`
	StatusCode  int      `json:"status_code,omitempty"`
	RedirectTo  string   `json:"redirect_to,omitempty"`
	Sensitivity string   `json:"sensitivity,omitempty"` // per-rule OWASP level (e.g. strict, high, medium)
}

// OWASPRuleRegistry is a thread-safe registry of all granular OWASP rules.
type OWASPRuleRegistry struct {
	rules map[string]*OWASPRule
	mu    sync.RWMutex
}

// DefaultOWASPRegistry is the global singleton rule registry.
var DefaultOWASPRegistry = &OWASPRuleRegistry{
	rules: make(map[string]*OWASPRule),
}

// Register adds a rule to the registry.
func (r *OWASPRuleRegistry) Register(rule *OWASPRule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules[rule.ID] = rule
}

// Get returns a rule by ID.
func (r *OWASPRuleRegistry) Get(id string) (*OWASPRule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rule, ok := r.rules[id]
	return rule, ok
}

// All returns a snapshot of all registered rules.
func (r *OWASPRuleRegistry) All() []*OWASPRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*OWASPRule, 0, len(r.rules))
	for _, rule := range r.rules {
		out = append(out, rule)
	}
	return out
}

// AllByCategory returns all rules belonging to a given category.
func (r *OWASPRuleRegistry) AllByCategory(category string) []*OWASPRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*OWASPRule
	for _, rule := range r.rules {
		if rule.Category == category {
			out = append(out, rule)
		}
	}
	return out
}

// Count returns the total number of registered rules.
func (r *OWASPRuleRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.rules)
}

// IsRuleEnabled checks whether a specific rule is enabled given the override config.
// If no override exists, the rule's default Enabled value is used.
func IsRuleEnabled(ruleID string, overrides map[string]OWASPRuleOverride) bool {
	if ov, ok := overrides[ruleID]; ok && ov.Enabled != nil {
		return *ov.Enabled
	}
	// Check registry default.
	if rule, ok := DefaultOWASPRegistry.Get(ruleID); ok {
		return rule.Enabled
	}
	return true // unknown rules default to enabled
}

/**
 * maxWhitelistPathDecodeRounds 限制白名单匹配前的百分号解码轮数。
 * 请求路径（reqCtx.Path 来自 URI().PathOriginal()）保留原始百分号编码，
 * 若只做一次解码，%252e%252e 这类双重编码仍可绕过穿越检查。
 */
const maxWhitelistPathDecodeRounds = 3

/**
 * decodePathPercentOnce 就地解码一轮 %XX 序列，返回解码结果与是否发生过解码。
 * 与 url.PathUnescape 不同：遇到非法的 % 序列不报错、原样保留，
 * 因为白名单判定必须对畸形路径给出确定结论，而不是因解析失败而放行。
 */
func decodePathPercentOnce(p string) (string, bool) {
	if !strings.Contains(p, "%") {
		return p, false
	}
	var b strings.Builder
	b.Grow(len(p))
	changed := false
	for i := 0; i < len(p); i++ {
		if p[i] == '%' && i+2 < len(p) && isHexByte(p[i+1]) && isHexByte(p[i+2]) {
			hi := unhexNibble(p[i+1])
			lo := unhexNibble(p[i+2])
			b.WriteByte(hi<<4 | lo)
			i += 2
			changed = true
			continue
		}
		b.WriteByte(p[i])
	}
	return b.String(), changed
}

/**
 * unhexNibble 将单个十六进制字符转为数值，调用前必须已通过 isHexByte 校验。
 */
func unhexNibble(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	default:
		return b - 'A' + 10
	}
}

/**
 * pathEscapesWhitelistPrefix 判断路径在解码后是否含有可跳出白名单前缀的构造。
 * 白名单只应豁免它字面声明的子树；一旦路径里出现 ".." 段或 NUL 截断，
 * 前缀匹配就不再能证明请求真的落在该子树内，此时必须拒绝豁免。
 */
func pathEscapesWhitelistPrefix(decoded string) bool {
	if strings.IndexByte(decoded, 0) >= 0 {
		return true
	}
	// 反斜杠在部分上游（IIS/Windows 路径）等价于分隔符，一并按段切分。
	for _, seg := range strings.FieldsFunc(decoded, func(r rune) bool { return r == '/' || r == '\\' }) {
		// 去掉空白后若整段只由两个以上的 "." 组成，视为穿越。
		// 覆盖 ".."、".. "、"..."（部分上游会把尾随点丢弃后还原成 ".."）等变体。
		trimmed := strings.Trim(seg, " \t")
		if len(trimmed) >= 2 && strings.Trim(trimmed, ".") == "" {
			return true
		}
	}
	return false
}

/**
 * normalizePathForMatch 归一化路径/白名单条目用于比较：
 * 去空白、统一小写、补前导 "/"、去掉尾随 "/"（根路径保持 "/"）。
 * 大小写在两侧同时归一化，避免出现"条目大写不生效、请求大写却生效"的不对称。
 */
func normalizePathForMatch(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if p == "/" {
		return p
	}
	return strings.TrimSuffix(p, "/")
}

/**
 * decodePathForMatch 反复解码百分号编码，返回用于白名单匹配的归一化路径，
 * 以及路径是否出现穿越/截断构造。任一解码轮次出现穿越即判定为穿越。
 */
func decodePathForMatch(path string) (normalized string, escapes bool) {
	current := path
	if pathEscapesWhitelistPrefix(current) {
		escapes = true
	}
	for i := 0; i < maxWhitelistPathDecodeRounds; i++ {
		decoded, changed := decodePathPercentOnce(current)
		if !changed {
			return normalizePathForMatch(current), escapes
		}
		current = decoded
		if pathEscapesWhitelistPrefix(current) {
			escapes = true
		}
	}
	// 解码轮数用尽仍能继续解码：无法证明剩余层级里没有穿越构造，
	// 因此按穿越处理（fail closed），拒绝带边界的白名单豁免。
	if _, changed := decodePathPercentOnce(current); changed {
		escapes = true
	}
	return normalizePathForMatch(current), escapes
}

/**
 * IsPathWhitelisted 判断请求路径是否命中某规则的路径白名单。
 *
 * 匹配语义（条目与请求路径均先归一化再比较）：
 *   - "*"：豁免全部路径，是唯一可跳过穿越检查的条目，因为它本就没有前缀边界。
 *   - 末尾带 "*"（如 "/static/*"）：前缀匹配，"/static/*" 同时命中 "/static" 自身。
 *   - 其余条目：精确匹配，不做隐式前缀扩展。
 *
 * 边界约束：
 *   - 空条目（"" 或纯空白）被忽略，不再退化成"豁免根路径"。
 *   - 请求路径先做多轮百分号解码；若解码后出现 ".." 段或 NUL 字节，
 *     则拒绝除 "*" 以外的一切豁免，防止 "/static/../admin" 借白名单绕过检测。
 */
func IsPathWhitelisted(ruleID, path string, overrides map[string]OWASPRuleOverride) bool {
	ov, ok := overrides[ruleID]
	if !ok || len(ov.Whitelist) == 0 {
		return false
	}
	return MatchPathList(path, ov.Whitelist)
}

/**
 * MatchPathList 判断请求路径是否命中路径条目列表。
 *
 * 匹配语义与边界约束与 IsPathWhitelisted 完全一致（见其文档注释），
 * 本函数是其纯匹配部分，供 IsPathWhitelisted 与按 phase 跳过检测复用，
 * 以免两处各自实现路径匹配而遗漏穿越防护。
 *
 * @param path    请求原始路径（保留原始百分号编码）。
 * @param entries 路径条目列表，空列表恒不命中。
 * @return 命中任一条目为 true。
 */
func MatchPathList(path string, entries []string) bool {
	if len(entries) == 0 {
		return false
	}
	np, escapes := decodePathForMatch(path)
	for _, wpRaw := range entries {
		wp := strings.TrimSpace(wpRaw)
		if wp == "" {
			// 空条目不表达任何路径，忽略以免误豁免根路径。
			continue
		}
		if wp == "*" {
			return true
		}
		if escapes {
			// 路径可跳出任何字面前缀，带边界的条目一律不豁免。
			continue
		}

		isWildcard := strings.HasSuffix(wp, "*")
		rawPrefix := strings.TrimSuffix(wp, "*")
		isTreeWildcard := isWildcard && strings.HasSuffix(strings.TrimSpace(rawPrefix), "/")
		prefix, entryEscapes := decodePathForMatch(rawPrefix)
		if entryEscapes {
			// 白名单自身包含穿越或截断构造时不产生豁免。
			continue
		}
		if isWildcard {
			// 保留 "/static/*" 与 "/static*" 的区别：前者只覆盖 /static 子树，
			// 后者是字面前缀，连 /static-public 也覆盖。
			if isTreeWildcard && prefix != "/" {
				prefix += "/"
			}
			if prefix == "/" {
				return true
			}
			if isTreeWildcard {
				if np == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(np, prefix) {
					return true
				}
				continue
			}
			if strings.HasPrefix(np, prefix) {
				return true
			}
			continue
		}
		if np == prefix {
			return true
		}
	}
	return false
}

// ParseOWASPRulesConfig parses a JSON string into the override map.
func ParseOWASPRulesConfig(raw string) map[string]OWASPRuleOverride {
	if raw == "" || raw == "{}" {
		return nil
	}
	var m map[string]OWASPRuleOverride
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil
	}
	return m
}

// SerializeOWASPRulesConfig serialises the override map into a JSON string.
func SerializeOWASPRulesConfig(m map[string]OWASPRuleOverride) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ShouldSkipRule combines enable check and path whitelist check for a hit.
// Returns true if the rule should be skipped for the given request path.
func ShouldSkipRule(ruleID, path string, overrides map[string]OWASPRuleOverride) bool {
	if !IsRuleEnabled(ruleID, overrides) {
		return true
	}
	if IsPathWhitelisted(ruleID, path, overrides) {
		return true
	}
	return false
}

// HitPassesOverrideSensitivity returns false when a per-rule sensitivity override
// requires a higher score than the hit carries.
func HitPassesOverrideSensitivity(hit OWASPHit, ov OWASPRuleOverride, catSens map[string]string) bool {
	s := strings.TrimSpace(ov.Sensitivity)
	if s == "" || catSens == nil {
		return true
	}
	th, enabled := CategoryThreshold(s, hit.Category, catSens)
	if !enabled {
		return false
	}
	return hit.Score >= th
}

// FilterHits filters OWASP hits based on rule overrides, path whitelists, and optional
// per-rule sensitivity overrides (requires category sensitivity map from ProtectionConfig).

// HitPassesFilters 判断单个命中是否通过覆盖/白名单/类别灵敏度过滤。
func HitPassesFilters(h OWASPHit, path string, overrides map[string]OWASPRuleOverride, catSens ...map[string]string) bool {
	if ShouldSkipRule(h.RuleID, path, overrides) {
		return false
	}
	if len(overrides) == 0 {
		return true
	}
	var cs map[string]string
	if len(catSens) > 0 {
		cs = catSens[0]
	}
	ov := RuleOverride(h.RuleID, overrides)
	if cs != nil && !HitPassesOverrideSensitivity(h, ov, cs) {
		return false
	}
	return true
}

// FilterFirstHit 返回第一个通过覆盖/白名单过滤的命中；无命中时 ok=false。
// 引擎路径只消费首个命中，避免 FilterHits 再分配 filtered slice。
func FilterFirstHit(hits []OWASPHit, path string, overrides map[string]OWASPRuleOverride, catSens ...map[string]string) (OWASPHit, bool) {
	if len(hits) == 0 {
		return OWASPHit{}, false
	}
	if len(overrides) == 0 {
		return hits[0], true
	}
	var cs map[string]string
	if len(catSens) > 0 {
		cs = catSens[0]
	}
	for _, h := range hits {
		if ShouldSkipRule(h.RuleID, path, overrides) {
			continue
		}
		ov := RuleOverride(h.RuleID, overrides)
		if cs != nil && !HitPassesOverrideSensitivity(h, ov, cs) {
			continue
		}
		return h, true
	}
	return OWASPHit{}, false
}

func FilterHits(hits []OWASPHit, path string, overrides map[string]OWASPRuleOverride, catSens ...map[string]string) []OWASPHit {
	if len(overrides) == 0 || len(hits) == 0 {
		return hits
	}
	var cs map[string]string
	if len(catSens) > 0 {
		cs = catSens[0]
	}
	filtered := make([]OWASPHit, 0, len(hits))
	for _, h := range hits {
		if ShouldSkipRule(h.RuleID, path, overrides) {
			continue
		}
		ov := RuleOverride(h.RuleID, overrides)
		if cs != nil && !HitPassesOverrideSensitivity(h, ov, cs) {
			continue
		}
		filtered = append(filtered, h)
	}
	return filtered
}

// RuleOverride returns the effective per-rule override for a hit.
func RuleOverride(ruleID string, overrides map[string]OWASPRuleOverride) OWASPRuleOverride {
	if len(overrides) == 0 {
		return OWASPRuleOverride{}
	}
	return overrides[ruleID]
}

func init() {
	registerSQLiRules()
	registerXSSRules()
	registerCmdInjectionRules()
	registerSSRFRules()
	registerXXERules()
	registerLDAPRules()
	registerNoSQLiRules()
	registerSSTIRules()
	registerJNDIRules()
	registerCRLFRules()
	registerExprLangRules()
	registerDeserializationRules()
	registerGraphQLRules()
	registerWebshellRules()
	registerRevShellRules()
	registerPathTraversalRules()
}

func registerSQLiRules() {
	for _, p := range sqliPatterns {
		meta := builtinRuleMeta[p.id]
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatSQLi),
			Name:        meta.name,
			Description: meta.desc,
			Enabled:     true,
		})
	}
}

func registerXSSRules() {
	for _, p := range xssPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatXSS),
			Name:        "XSS 跨站脚本攻击 - " + p.id,
			Description: "检测跨站脚本（XSS）攻击载荷，包括事件处理器、伪协议、内联事件与富文本注入等向量",
			Enabled:     true,
		})
	}
}

func registerCmdInjectionRules() {
	for _, p := range cmdInjectPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatCmdInject),
			Name:        "命令注入 - " + p.id,
			Description: "检测操作系统命令注入载荷，包括管道符、反引号、子命令执行与 Shell 脚本片段",
			Enabled:     true,
		})
	}
}

func registerSSRFRules() {
	for _, p := range ssrfPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatSSRF),
			Name:        "服务端请求伪造 - " + p.id,
			Description: "检测服务端请求伪造（SSRF）攻击载荷，包括内网/回环地址、非标准编码与协议混淆",
			Enabled:     true,
		})
	}
}

func registerXXERules() {
	for _, p := range xxePatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatXXE),
			Name:        "XML 外部实体注入 - " + p.id,
			Description: "检测 XML 外部实体注入（XXE）攻击，包括 SYSTEM 实体、参数实体与外部 DTD 引用",
			Enabled:     true,
		})
	}
}

func registerLDAPRules() {
	for _, p := range ldapiPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatLDAPI),
			Name:        "LDAP 注入 - " + p.id,
			Description: "检测 LDAP 注入攻击载荷，包括闭合括号、通配符与逻辑运算符滥用",
			Enabled:     true,
		})
	}
}

func registerNoSQLiRules() {
	for _, p := range nosqliPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatNoSQLi),
			Name:        "NoSQL 注入 - " + p.id,
			Description: "检测 NoSQL 数据库注入攻击，包括 MongoDB 操作符替换、$where 与 JavaScript 表达式滥用",
			Enabled:     true,
		})
	}
}

func registerSSTIRules() {
	for _, p := range tmplInjectPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatTmplInject),
			Name:        "模板注入 - " + p.id,
			Description: "检测服务端模板注入（SSTI）攻击载荷，覆盖 Jinja2、Twig、Freemarker、Smarty 等模板引擎",
			Enabled:     true,
		})
	}
}

func registerJNDIRules() {
	for _, p := range jndiPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatJNDI),
			Name:        "JNDI 注入 - " + p.id,
			Description: "检测 JNDI 注入攻击载荷，包括 LDAP/RMI 远程引用与 Log4Shell 类反序列化链",
			Enabled:     true,
		})
	}
}

func registerCRLFRules() {
	for _, p := range crlfPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatCRLF),
			Name:        "CRLF 注入 - " + p.id,
			Description: "检测回车换行注入（CRLF）攻击载荷，可用于响应头拆分、HTTP 响应走私与 XSS",
			Enabled:     true,
		})
	}
}

func registerExprLangRules() {
	for _, p := range exprLangPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatExprLang),
			Name:        "表达式语言注入 - " + p.id,
			Description: "检测表达式语言（EL/OGNL/SpEL）注入攻击载荷，可绕过沙箱执行任意代码",
			Enabled:     true,
		})
	}
}

func registerDeserializationRules() {
	for _, p := range deserialPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatDeserial),
			Name:        "反序列化攻击 - " + p.id,
			Description: "检测 Java/PHP/Python 反序列化攻击载荷，覆盖 ObjectInputStream、PHP serialize、pickle 协议",
			Enabled:     true,
		})
	}
}

func registerGraphQLRules() {
	for _, p := range graphqlPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatGraphQLi),
			Name:        "GraphQL 注入 - " + p.id,
			Description: "检测 GraphQL 注入与内省滥用攻击，可绕过字段级授权与暴露全 schema",
			Enabled:     true,
		})
	}
}

func registerWebshellRules() {
	for _, p := range webshellPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatWebshell),
			Name:        "WebShell 上传/通信 - " + p.id,
			Description: "检测 WebShell 上传或通信载荷，包括一句话木马、混淆 PHP/JSP/ASPX 与远程命令执行函数",
			Enabled:     true,
		})
	}
}

func registerRevShellRules() {
	for _, p := range revshellPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatRevShell),
			Name:        "反弹 Shell 通信 - " + p.id,
			Description: "检测反弹 Shell 通信载荷，包括 bash -i、nc mkfifo、python/c/perl/powershell 反向连接",
			Enabled:     true,
		})
	}
}

func registerPathTraversalRules() {
	for _, p := range pathTravPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:          p.id,
			Category:    string(CatPathTrav),
			Name:        "路径穿越 - " + p.id,
			Description: "检测路径穿越（Path Traversal）攻击载荷，包括 ../、URL 编码、双重编码与空字节绕过",
			Enabled:     true,
		})
	}
}
