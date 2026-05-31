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

// IsPathWhitelisted checks if a request path matches the whitelist for a rule.
func IsPathWhitelisted(ruleID, path string, overrides map[string]OWASPRuleOverride) bool {
	ov, ok := overrides[ruleID]
	if !ok || len(ov.Whitelist) == 0 {
		return false
	}
	lowerPath := strings.ToLower(path)
	for _, wp := range ov.Whitelist {
		wp = strings.ToLower(wp)
		if wp == "*" {
			return true
		}
		// Prefix match: /api/v1 matches /api/v1/users
		if strings.HasPrefix(lowerPath, wp) {
			return true
		}
		// Exact match
		if lowerPath == wp {
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

// ── Rule Registration (wraps existing detection patterns) ──

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

func registerPatternRules(category string, patterns []struct {
	re    interface{} // not used here — just for naming
	score int
	id    string
}, names map[string]string) {
	// This is a helper that we don't use directly since patterns have *regexp.Regexp.
	// Instead each register function iterates its own pattern slice.
}

func registerSQLiRules() {
	for _, p := range sqliPatterns {
		id := p.id
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       id,
			Category: string(CatSQLi),
			Name:     "SQLi: " + id,
			Enabled:  true,
		})
	}
}

func registerXSSRules() {
	for _, p := range xssPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatXSS),
			Name:     "XSS: " + p.id,
			Enabled:  true,
		})
	}
}

func registerCmdInjectionRules() {
	for _, p := range cmdInjectPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatCmdInject),
			Name:     "CmdInject: " + p.id,
			Enabled:  true,
		})
	}
}

func registerSSRFRules() {
	for _, p := range ssrfPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatSSRF),
			Name:     "SSRF: " + p.id,
			Enabled:  true,
		})
	}
}

func registerXXERules() {
	for _, p := range xxePatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatXXE),
			Name:     "XXE: " + p.id,
			Enabled:  true,
		})
	}
}

func registerLDAPRules() {
	for _, p := range ldapiPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatLDAPI),
			Name:     "LDAP: " + p.id,
			Enabled:  true,
		})
	}
}

func registerNoSQLiRules() {
	for _, p := range nosqliPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatNoSQLi),
			Name:     "NoSQLi: " + p.id,
			Enabled:  true,
		})
	}
}

func registerSSTIRules() {
	for _, p := range tmplInjectPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatTmplInject),
			Name:     "SSTI: " + p.id,
			Enabled:  true,
		})
	}
}

func registerJNDIRules() {
	for _, p := range jndiPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatJNDI),
			Name:     "JNDI: " + p.id,
			Enabled:  true,
		})
	}
}

func registerCRLFRules() {
	for _, p := range crlfPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatCRLF),
			Name:     "CRLF: " + p.id,
			Enabled:  true,
		})
	}
}

func registerExprLangRules() {
	for _, p := range exprLangPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatExprLang),
			Name:     "EL: " + p.id,
			Enabled:  true,
		})
	}
}

func registerDeserializationRules() {
	for _, p := range deserialPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatDeserial),
			Name:     "Deser: " + p.id,
			Enabled:  true,
		})
	}
}

func registerGraphQLRules() {
	for _, p := range graphqlPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatGraphQLi),
			Name:     "GraphQL: " + p.id,
			Enabled:  true,
		})
	}
}

func registerWebshellRules() {
	for _, p := range webshellPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatWebshell),
			Name:     "Webshell: " + p.id,
			Enabled:  true,
		})
	}
}

func registerRevShellRules() {
	for _, p := range revshellPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatRevShell),
			Name:     "RevShell: " + p.id,
			Enabled:  true,
		})
	}
}

func registerPathTraversalRules() {
	for _, p := range pathTravPatterns {
		DefaultOWASPRegistry.Register(&OWASPRule{
			ID:       p.id,
			Category: string(CatPathTrav),
			Name:     "PathTrav: " + p.id,
			Enabled:  true,
		})
	}
}
