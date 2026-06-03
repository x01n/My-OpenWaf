package cve

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// CVEDetector orchestrates CVE-specific vulnerability detection across
// multiple technology-focused sub-detectors (PHP, Java, Node.js, general).
type CVEDetector struct {
	phpDetector     *PHPCVEDetector
	javaDetector    *JavaCVEDetector
	nodeDetector    *NodeCVEDetector
	generalDetector *GeneralCVEDetector
	customRules     []CustomCVERule
	compiledCustom  []compiledCustomRule
	mu              sync.RWMutex
}

type CVEMatch struct {
	CVEID       string
	Category    string
	Severity    string
	Description string
	MatchedPart string
	Pattern     string
	Action      string // drop, block, log
}

// CustomCVERule is a user/auto-generated CVE rule loaded from the database.
type CustomCVERule struct {
	ID          uint
	CVEID       string
	Category    string
	Pattern     string // regex pattern
	Target      string // url, body, header, cookie
	Severity    string
	Action      string
	Enabled     bool
	Description string
}

type compiledCustomRule struct {
	rule CustomCVERule
	re   *regexp.Regexp
}

// CVERule 表示一条颗粒化的 CVE 检测规则
type CVERule struct {
	ID          string                                                          // 唯一标识，如 "cve-2021-44228"
	Name        string                                                          // 规则名称
	Description string                                                          // 规则描述
	CVE         string                                                          // CVE 编号
	Severity    string                                                          // critical/high/medium/low
	Category    string                                                          // cve_general/cve_java/cve_node/cve_php
	Enabled     bool                                                            // 是否启用
	Sensitivity string                                                          // 敏感度级别覆盖
	CheckFunc   func(uri, body, ua string, headers map[string]string) *CVEMatch // 检测函数
}

// CVERuleOverride 支持 JSON 配置禁用、敏感度和动作覆盖。
type CVERuleOverride struct {
	Enabled     *bool  `json:"enabled,omitempty"`
	Sensitivity string `json:"sensitivity,omitempty"`
	Action      string `json:"action,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
	RedirectTo  string `json:"redirect_to,omitempty"`
}

// CVERuleRegistry 线程安全的规则注册表
type CVERuleRegistry struct {
	mu    sync.RWMutex
	rules []*CVERule          // 保持插入顺序
	index map[string]*CVERule // 按ID快速查找
}

var globalCVERuleRegistry = &CVERuleRegistry{
	index: make(map[string]*CVERule),
}

// Register 注册一条颗粒化规则到注册表（不重复注册）
func (r *CVERuleRegistry) Register(rule *CVERule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.index[rule.ID]; exists {
		return
	}
	r.rules = append(r.rules, rule)
	r.index[rule.ID] = rule
}

// ApplyOverrides 应用 JSON 配置的禁用/敏感度覆盖
func (r *CVERuleRegistry) ApplyOverrides(overrides map[string]CVERuleOverride) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, ov := range overrides {
		if rule, ok := r.index[id]; ok {
			if ov.Enabled != nil {
				rule.Enabled = *ov.Enabled
			}
			if ov.Sensitivity != "" {
				rule.Sensitivity = ov.Sensitivity
			}
		}
	}
}

func ParseCVERuleOverrides(raw string) map[string]CVERuleOverride {
	if raw == "" || raw == "{}" {
		return nil
	}
	var overrides map[string]CVERuleOverride
	if err := json.Unmarshal([]byte(raw), &overrides); err != nil {
		return nil
	}
	return overrides
}

// DetectAll 执行注册表中所有启用的颗粒化规则
func (r *CVERuleRegistry) DetectAll(uri, body, ua string, headers map[string]string) []CVEMatch {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var matches []CVEMatch
	combinedLower := registryCombinedLower(uri, body, ua, headers)
	for _, rule := range r.rules {
		if !rule.Enabled {
			continue
		}
		if !shouldScanRegisteredCVERule(rule, combinedLower) {
			continue
		}
		if m := rule.CheckFunc(uri, body, ua, headers); m != nil {
			matches = append(matches, *m)
		}
	}
	return matches
}

func registryCombinedLower(uri, body, ua string, headers map[string]string) string {
	var b strings.Builder
	b.Grow(len(uri) + len(body) + len(ua) + len(headers)*32)
	b.WriteString(uri)
	b.WriteByte('\n')
	b.WriteString(body)
	b.WriteByte('\n')
	b.WriteString(ua)
	for k, v := range headers {
		b.WriteByte('\n')
		b.WriteString(k)
		b.WriteByte(':')
		b.WriteString(v)
	}
	return strings.ToLower(b.String())
}

func registeredCVERuleContainsAny(combinedLower string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(combinedLower, needle) {
			return true
		}
	}
	return false
}

func shouldScanRegisteredCVERule(rule *CVERule, combinedLower string) bool {
	switch rule.CVE {
	case "CVE-2023-GRAPHQL":
		return registeredCVERuleContainsAny(combinedLower, "__schema", "__type", "introspectionquery")
	case "CVE-2014-6271":
		return registeredCVERuleContainsAny(combinedLower, "() {")
	case "CVE-2025-30208":
		return registeredCVERuleContainsAny(combinedLower, "@fs/", "raw??", "html-proxy", "htmlproxy", "inline", "?url", "&url", ".html")
	case "CVE-2025-3248":
		return registeredCVERuleContainsAny(combinedLower, "validate/code", "__import__", "exec(", "eval(", "subprocess", "child_process")
	case "CVE-2025-24893":
		return registeredCVERuleContainsAny(combinedLower, "solrsearch", "media=rss", "groovy", "{{async", "{{ async")
	case "CVE-2025-53770":
		return registeredCVERuleContainsAny(combinedLower, "toolpane.aspx", "signout.aspx", "spinstall0.aspx", "msotlpn_dwp", "compresseddatatable", "__viewstate")
	case "CVE-2025-34028":
		return registeredCVERuleContainsAny(combinedLower, "deploywebpackage.do", "commcellname", "servicepack", "../", "http://", "https://")
	case "CVE-2025-47812":
		return registeredCVERuleContainsAny(combinedLower, "loginok.html", "%00", "io.popen", "lua")
	case "CVE-2025-4632":
		return registeredCVERuleContainsAny(combinedLower, "swupdatefileuploader", "filename=", "magicinfo", "../")
	case "CVE-2025-64446":
		return registeredCVERuleContainsAny(combinedLower, "fwbcgi", "cgiinfo")
	case "CVE-2025-10035":
		return registeredCVERuleContainsAny(combinedLower, "unlicensed.xhtml", "garequestaction=activate", "javax.faces.viewstate")
	case "CVE-2025-41243":
		return registeredCVERuleContainsAny(combinedLower, "actuator/gateway", "addresponseheader", "#{", "spel")
	case "CVE-2025-47916":
		return registeredCVERuleContainsAny(combinedLower, "themeeditor", "customcss", "expression=")
	case "CVE-2025-31161":
		return registeredCVERuleContainsAny(combinedLower, "webinterface/function", "aws4-hmac-sha256", "crushftp")
	case "CVE-2025-32756":
		return registeredCVERuleContainsAny(combinedLower, "hostcheck_validate", "authhash")
	case "CVE-2017-8046":
		return registeredCVERuleContainsAny(combinedLower, "json-patch", "application/patch+json", "spel", "#{", "t(")
	case "CVE-2023-1454":
		return registeredCVERuleContainsAny(combinedLower, "jeecg", "sys/", "select", "union", "updatexml", "extractvalue", "sleep(")
	case "CVE-2021-21351":
		return registeredCVERuleContainsAny(combinedLower, "<java", "<sorted-set", "<dynamic-proxy", "xstream", "processbuilder", "runtime")
	case "CVE-2019-3929":
		return registeredCVERuleContainsAny(combinedLower, "/cgi-bin/", "cgi", ";", "|", "`", "$(", "wget", "curl", "busybox")
	case "CVE-2024-JAVAINJ":
		return registeredCVERuleContainsAny(combinedLower, "ognl", "spel", "#{", "${", "runtime", "processbuilder", "class.forname", "javax.script")
	case "CVE-2024-REMOTECALL":
		return registeredCVERuleContainsAny(combinedLower, "jndi:", "ldap://", "rmi://", "iiop://", "jdbc:", "dns://")
	case "CVE-2024-DEEPPATH":
		return registeredCVERuleContainsAny(combinedLower, "../", "..\\", "%2e", "%252e", "%5c", "%00", "/etc/passwd", "web.config")
	case "CVE-2024-XXEUTF7":
		return registeredCVERuleContainsAny(combinedLower, "utf-7", "+adw-", "+adi-", "+afw-")
	case "CVE-2024-LDAPI":
		return registeredCVERuleContainsAny(combinedLower, "objectclass=", ")(|", ")(uid=", "*)(", "ldap")
	case "CVE-2024-NOSQLI":
		return registeredCVERuleContainsAny(combinedLower, "$gt", "$ne", "$regex", "$where", "$or", "$and", "constructor", "__proto__")
	case "CVE-2024-SENSFILE":
		return registeredCVERuleContainsAny(combinedLower, "/.env", "/.git/config", "/.htaccess", "/wp-config.php", "/web.config", "/etc/passwd")
	case "CVE-2024-LOWCMD":
		return registeredCVERuleContainsAny(combinedLower, ";", "|", "`", "$(", "whoami", "uname", "ifconfig", "ipconfig")
	default:
		return true
	}
}

// GetGlobalCVERuleRegistry 返回全局颗粒化规则注册表
func GetGlobalCVERuleRegistry() *CVERuleRegistry {
	return globalCVERuleRegistry
}

// CVERequest holds the normalised request data for CVE scanning.
type CVERequest struct {
	Path        string
	RawQuery    string
	Headers     map[string]string
	Body        string
	ContentType string
	// Decoded variants for multi-pass detection.
	DecodedPath     string
	DecodedQuery    string
	DecodedBody     string
	URLTargets      []string
	BodyTargets     []string
	URLBodyTargets  []string
	HeaderTargets   []string
	AllTargets      []string // aggregated targets (path+query+header values+body)
	AllTargetsLower []string // pre-lowercased AllTargets for hasCVESuspiciousContent
}

// NewCVEDetector initialises all sub-detectors.
func NewCVEDetector() *CVEDetector {
	return &CVEDetector{
		phpDetector:     NewPHPCVEDetector(),
		javaDetector:    NewJavaCVEDetector(),
		nodeDetector:    NewNodeCVEDetector(),
		generalDetector: NewGeneralCVEDetector(),
	}
}

// BuildCVERequest constructs a normalised CVERequest from raw request components.
func BuildCVERequest(path, rawQuery string, headers map[string]string, body []byte, contentType string) *CVERequest {
	bodyStr := ""
	if len(body) > 0 {
		bodyStr = string(body)
	}

	decodedPath := multiDecode(path)
	decodedQuery := multiDecode(rawQuery)
	decodedBody := multiDecode(bodyStr)

	urlTargets := []string{path, decodedPath}
	if rawQuery != "" {
		urlTargets = append(urlTargets, rawQuery, decodedQuery)
	}

	var bodyTargets []string
	if bodyStr != "" {
		bodyTargets = []string{bodyStr, decodedBody}
	}

	headerTargets := make([]string, 0, len(headers))
	for _, v := range headers {
		headerTargets = append(headerTargets, v)
	}

	urlBodyTargets := make([]string, 0, len(urlTargets)+len(bodyTargets))
	urlBodyTargets = append(urlBodyTargets, urlTargets...)
	urlBodyTargets = append(urlBodyTargets, bodyTargets...)

	var targets []string
	targets = append(targets, urlTargets...)
	targets = append(targets, headerTargets...)
	if contentType != "" {
		targets = append(targets, contentType)
	}
	targets = append(targets, bodyTargets...)

	targetsLower := make([]string, len(targets))
	for i, t := range targets {
		targetsLower[i] = strings.ToLower(t)
	}

	return &CVERequest{
		Path:            path,
		RawQuery:        rawQuery,
		Headers:         headers,
		Body:            bodyStr,
		ContentType:     contentType,
		DecodedPath:     decodedPath,
		DecodedQuery:    decodedQuery,
		DecodedBody:     decodedBody,
		URLTargets:      urlTargets,
		BodyTargets:     bodyTargets,
		URLBodyTargets:  urlBodyTargets,
		HeaderTargets:   headerTargets,
		AllTargets:      targets,
		AllTargetsLower: targetsLower,
	}
}

// Detect runs all sub-detectors, custom rules, and registry rules, returning all matches.
// Runs detectors sequentially with early exit for performance — spawning
// 4 goroutines per request adds ~10μs overhead that's significant at scale.
// The optional categorySensitivity map allows per-category sensitivity override;
// setting a category to "none" skips that sub-detector entirely.
func (d *CVEDetector) Detect(req *CVERequest, categorySensitivity ...map[string]string) []CVEMatch {
	// Fast path: skip CVE scanning for short clean requests.
	if !hasCVESuspiciousContent(req) {
		return nil
	}

	var catSens map[string]string
	if len(categorySensitivity) > 0 {
		catSens = categorySensitivity[0]
	}

	var matches []CVEMatch

	// Run detectors sequentially. Most requests won't match any, and
	// sequential execution avoids goroutine spawn/sync overhead.
	// General detector runs first as it covers the broadest set.
	isDetectorEnabled := func(key string) bool {
		if catSens == nil {
			return true
		}
		level := strings.ToLower(strings.TrimSpace(catSens[key]))
		return level != "none" && level != "off"
	}

	if isDetectorEnabled("cve_general") {
		if m := d.generalDetector.Detect(req); len(m) > 0 {
			matches = append(matches, m...)
		}
	}
	if isDetectorEnabled("cve_php") {
		if m := d.phpDetector.Detect(req); len(m) > 0 {
			matches = append(matches, m...)
		}
	}
	if isDetectorEnabled("cve_java") {
		if m := d.javaDetector.Detect(req); len(m) > 0 {
			matches = append(matches, m...)
		}
	}
	if isDetectorEnabled("cve_node") {
		if m := d.nodeDetector.Detect(req); len(m) > 0 {
			matches = append(matches, m...)
		}
	}

	// Custom rules.
	d.mu.RLock()
	customs := d.compiledCustom
	d.mu.RUnlock()

	for _, cr := range customs {
		if !cr.rule.Enabled {
			continue
		}
		target := pickTarget(req, cr.rule.Target)
		if cr.re.MatchString(target) {
			matches = append(matches, CVEMatch{
				CVEID:       cr.rule.CVEID,
				Category:    cr.rule.Category,
				Severity:    cr.rule.Severity,
				Description: cr.rule.Description,
				MatchedPart: cr.rule.Target,
				Pattern:     cr.rule.Pattern,
				Action:      cr.rule.Action,
			})
		}
	}

	// 执行注册表中的颗粒化规则
	uri := req.DecodedPath
	if req.DecodedQuery != "" {
		uri = uri + "?" + req.DecodedQuery
	}
	ua := req.Headers["User-Agent"]
	regMatches := globalCVERuleRegistry.DetectAll(uri, req.Body, ua, req.Headers)
	matches = append(matches, regMatches...)

	return matches
}

// hasCVESuspiciousContent performs a cheap pre-filter to skip CVE scanning
// for requests that are clearly clean. Checks for common exploit indicators.
func hasCVEHighRiskPunctuation(raw, lower string) bool {
	if strings.ContainsAny(raw, "\\|`") {
		return true
	}
	if strings.Contains(raw, "$") {
		return strings.Contains(lower, "${") || strings.Contains(lower, "$gt") || strings.Contains(lower, "$ne") || strings.Contains(lower, "$regex") || strings.Contains(lower, "$where") || strings.Contains(lower, "$or") || strings.Contains(lower, "$and")
	}
	if strings.Contains(raw, "{") || strings.Contains(raw, "}") {
		return strings.Contains(lower, "${") || strings.Contains(lower, "#{") || strings.Contains(lower, "{{") || strings.Contains(lower, "expression=") || strings.Contains(lower, "groovy") || strings.Contains(lower, "async=false") || strings.Contains(lower, "addresponseheader") || strings.Contains(lower, "unserialize") || strings.Contains(lower, "o:") || strings.Contains(lower, "a:")
	}
	if strings.Contains(raw, ";") {
		return strings.Contains(lower, "select") || strings.Contains(lower, "union") || strings.Contains(lower, "drop") || strings.Contains(lower, "insert") || strings.Contains(lower, "update") || strings.Contains(lower, "delete") || strings.Contains(lower, "exec") || strings.Contains(lower, "system") || strings.Contains(lower, "whoami") || strings.Contains(lower, "uname") || strings.Contains(lower, "ifconfig") || strings.Contains(lower, "ipconfig")
	}
	if strings.Contains(raw, "<") || strings.Contains(raw, ">") {
		return strings.Contains(lower, "<!") || strings.Contains(lower, "<script") || strings.Contains(lower, "<sorted-set") || strings.Contains(lower, "<dynamic-proxy") || strings.Contains(lower, "</")
	}
	if strings.Contains(raw, "(") || strings.Contains(raw, ")") {
		return strings.Contains(lower, "${") || strings.Contains(lower, "jndi:") || strings.Contains(lower, "runtime") || strings.Contains(lower, "exec") || strings.Contains(lower, "processbuilder") || strings.Contains(lower, "class.forname") || strings.Contains(lower, "objectclass=") || strings.Contains(lower, ")(|") || strings.Contains(lower, ")(uid=")
	}
	if strings.Contains(raw, "[") || strings.Contains(raw, "]") {
		return strings.Contains(lower, "this[") || strings.Contains(lower, "window[") || strings.Contains(lower, "globalthis") || strings.Contains(lower, "constructor") || strings.Contains(lower, "__proto__")
	}
	return false
}

func hasCVESuspiciousContent(req *CVERequest) bool {
	for i, t := range req.AllTargets {
		if len(t) < 3 {
			continue
		}
		lower := req.AllTargetsLower[i]
		if hasCVEHighRiskPunctuation(t, lower) {
			return true
		}
		if strings.Contains(lower, "http://") ||
			strings.Contains(lower, "https://") ||
			strings.Contains(lower, "file://") ||
			strings.Contains(lower, "169.254.169.254") ||
			strings.Contains(lower, "metadata.google") ||
			strings.Contains(lower, "jndi:") ||
			strings.Contains(lower, "__proto__") ||
			strings.Contains(lower, "constructor") ||
			strings.Contains(lower, "child_process") ||
			strings.Contains(lower, "php://") ||
			strings.Contains(lower, "invokefunction") ||
			strings.Contains(lower, "classloader") ||
			strings.Contains(lower, "serializ") ||
			strings.Contains(lower, "<!doctype") ||
			strings.Contains(lower, "<!entity") ||
			strings.Contains(lower, "../") ||
			strings.Contains(lower, "..\\") ||
			strings.Contains(lower, "%2e%2e") ||
			strings.Contains(lower, "0x") ||
			strings.Contains(lower, "rememberme=") ||
			strings.Contains(lower, "@type") ||
			strings.Contains(lower, "ognl") ||
			strings.Contains(lower, "#_member") ||
			strings.Contains(lower, "transfer-encoding") ||
			strings.Contains(lower, "content-length") ||
			strings.Contains(lower, "%0d%0a") ||
			strings.Contains(lower, "%ad") ||
			strings.Contains(lower, "eval-stdin") ||
			strings.Contains(lower, "developmentserver") ||
			strings.Contains(lower, "metadatauploader") ||
			strings.Contains(lower, "globalprotect") ||
			strings.Contains(lower, "x-middleware") ||
			strings.Contains(lower, "@fs/") ||
			strings.Contains(lower, "raw??") ||
			strings.Contains(lower, "validate/code") ||
			strings.Contains(lower, "solrsearch") ||
			strings.Contains(lower, "toolshell") ||
			strings.Contains(lower, "toolpane.aspx") ||
			strings.Contains(lower, "signout.aspx") ||
			strings.Contains(lower, "spinstall0.aspx") ||
			strings.Contains(lower, "deploywebpackage.do") ||
			strings.Contains(lower, "loginok.html") ||
			strings.Contains(lower, "swupdatefileuploader") ||
			strings.Contains(lower, "cgi-bin/fwbcgi") ||
			strings.Contains(lower, "cgiinfo") ||
			strings.Contains(lower, "unlicensed.xhtml") ||
			strings.Contains(lower, "garequestaction=activate") ||
			strings.Contains(lower, "javax.faces.viewstate") ||
			strings.Contains(lower, "actuator/gateway") ||
			strings.Contains(lower, "addresponseheader") ||
			strings.Contains(lower, "themeeditor") ||
			strings.Contains(lower, "customcss") ||
			strings.Contains(lower, "expression=") ||
			strings.Contains(lower, "aws4-hmac-sha256") ||
			strings.Contains(lower, "webinterface/function") ||
			strings.Contains(lower, "hostcheck_validate") ||
			strings.Contains(lower, "authhash") ||
			strings.Contains(lower, "multipart/form-data") ||
			strings.Contains(lower, "charset=utf-7") ||
			strings.Contains(lower, "charset=utf-16") ||
			strings.Contains(lower, "charset=utf-32") ||
			strings.Contains(lower, "shift-jis") ||
			strings.Contains(lower, "iso-2022-jp") ||
			strings.Contains(lower, "graphql") ||
			strings.Contains(lower, "introspection") ||
			// Spring Data REST RCE
			strings.Contains(lower, "json-patch+json") ||
			strings.Contains(lower, "processbuilder") ||
			strings.Contains(lower, "java.lang.runtime") ||
			// Jeecg-boot SQLi
			strings.Contains(lower, "/sys/dict/loadtreedata") ||
			strings.Contains(lower, "/sys/duplicate/check") ||
			strings.Contains(lower, "/sys/user/querysysuser") ||
			// XStream deser
			strings.Contains(lower, "<sorted-set>") ||
			strings.Contains(lower, "priorityqueue") ||
			strings.Contains(lower, "<dynamic-proxy>") ||
			strings.Contains(lower, "javax.naming") ||
			// Router CGI cmd injection
			strings.Contains(lower, "/cgi-bin/") ||
			strings.Contains(lower, "ping.cgi") ||
			strings.Contains(lower, "syscmd.cgi") ||
			strings.Contains(lower, "diagnostic.cgi") ||
			// Java code injection
			strings.Contains(lower, "getruntime") ||
			strings.Contains(lower, "class.forname") ||
			strings.Contains(lower, "reflect.method") ||
			strings.Contains(lower, "scriptengine") ||
			strings.Contains(lower, "valuestack") ||
			strings.Contains(lower, "actioncontext") ||
			// Remote call protocol / JDBC
			strings.Contains(lower, "rmi://") ||
			strings.Contains(lower, "ldap://") ||
			strings.Contains(lower, "ldaps://") ||
			strings.Contains(lower, "jdbc:") ||
			// Deep path traversal
			strings.Contains(lower, "....//") ||
			strings.Contains(lower, "%252e") ||
			strings.Contains(lower, "%c0%af") ||
			strings.Contains(lower, "%ef%bc%8f") ||
			strings.Contains(lower, "../../../../") ||
			// XXE UTF-7
			strings.Contains(lower, "+adw-") ||
			// LDAP injection
			strings.Contains(lower, ")(|") ||
			strings.Contains(lower, "objectclass=") ||
			strings.Contains(lower, ")(uid=") ||
			// NoSQL injection
			strings.Contains(lower, "$gt") ||
			strings.Contains(lower, "$ne") ||
			strings.Contains(lower, "$regex") ||
			strings.Contains(lower, "$where") ||
			strings.Contains(lower, "$or") ||
			strings.Contains(lower, "$and") ||
			// Sensitive file access
			strings.Contains(lower, "/.env") ||
			strings.Contains(lower, "/.git/config") ||
			strings.Contains(lower, "/.htaccess") ||
			strings.Contains(lower, "/.htpasswd") ||
			strings.Contains(lower, "/wp-config.php") ||
			strings.Contains(lower, "/web.config") ||
			strings.Contains(lower, "/database.yml") ||
			strings.Contains(lower, "/settings.py") ||
			strings.Contains(lower, "/application.properties") ||
			strings.Contains(lower, "/etc/passwd") ||
			strings.Contains(lower, "/etc/shadow") ||
			strings.Contains(lower, "/.ds_store") ||
			strings.Contains(lower, "/.svn/entries") ||
			// Low-severity cmd exec
			strings.Contains(lower, "whoami") ||
			strings.Contains(lower, "uname") ||
			strings.Contains(lower, "ifconfig") ||
			strings.Contains(lower, "ipconfig") ||
			strings.Contains(lower, "systeminfo") ||
			strings.Contains(lower, "net user") ||
			strings.Contains(lower, "hostname") {
			return true
		}
	}
	return false
}

// ReloadCustomRules hot-reloads custom CVE rules (thread-safe).
func (d *CVEDetector) ReloadCustomRules(rules []CustomCVERule) {
	compiled := make([]compiledCustomRule, 0, len(rules))
	for _, r := range rules {
		re, err := regexp.Compile("(?i)" + r.Pattern)
		if err != nil {
			continue // skip invalid patterns
		}
		compiled = append(compiled, compiledCustomRule{rule: r, re: re})
	}
	d.mu.Lock()
	d.customRules = rules
	d.compiledCustom = compiled
	d.mu.Unlock()
}

// AddCustomRule adds a single rule at runtime.
func (d *CVEDetector) AddCustomRule(rule CustomCVERule) {
	re, err := regexp.Compile("(?i)" + rule.Pattern)
	if err != nil {
		return
	}
	d.mu.Lock()
	d.customRules = append(d.customRules, rule)
	d.compiledCustom = append(d.compiledCustom, compiledCustomRule{rule: rule, re: re})
	d.mu.Unlock()
}

// RemoveCustomRule removes a rule by ID.
func (d *CVEDetector) RemoveCustomRule(id uint) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, cr := range d.compiledCustom {
		if cr.rule.ID == id {
			d.compiledCustom = append(d.compiledCustom[:i], d.compiledCustom[i+1:]...)
			break
		}
	}
	for i, r := range d.customRules {
		if r.ID == id {
			d.customRules = append(d.customRules[:i], d.customRules[i+1:]...)
			break
		}
	}
}

// pickTarget selects which request part to match against.
func pickTarget(req *CVERequest, target string) string {
	switch target {
	case "url":
		return req.DecodedPath + "?" + req.DecodedQuery
	case "body":
		return req.DecodedBody
	case "header":
		var sb strings.Builder
		for _, v := range req.Headers {
			sb.WriteString(v)
			sb.WriteByte('\n')
		}
		return sb.String()
	case "cookie":
		return req.Headers["Cookie"]
	default:
		return strings.Join(req.AllTargets, "\n")
	}
}

// multiDecode performs URL-decode then attempts base64-decode on the result.
func multiDecode(s string) string {
	if s == "" {
		return s
	}
	// Double URL decode.
	d1, err := url.QueryUnescape(s)
	if err != nil {
		d1 = s
	}
	d2, err := url.QueryUnescape(d1)
	if err != nil {
		d2 = d1
	}
	// Try base64 decode on original.
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) > 0 && isPrintable(b) {
		return d2 + "\x00" + string(b)
	}
	return d2
}

func isPrintable(b []byte) bool {
	printable := 0
	for _, c := range b {
		if c >= 0x20 && c <= 0x7E || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	return len(b) > 0 && float64(printable)/float64(len(b)) > 0.8
}
