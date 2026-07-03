package cve

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
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

// DetectFirst returns the first enabled registered rule match in registry order.
func (r *CVERuleRegistry) DetectFirst(uri, body, ua string, headers map[string]string) (CVEMatch, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	combinedLower := registryCombinedLower(uri, body, ua, headers)
	for _, rule := range r.rules {
		if !rule.Enabled {
			continue
		}
		if !shouldScanRegisteredCVERule(rule, combinedLower) {
			continue
		}
		if m := rule.CheckFunc(uri, body, ua, headers); m != nil {
			return *m, true
		}
	}
	return CVEMatch{}, false
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

func hasGraphQLIntrospectionSignalLower(s string) bool {
	if strings.Contains(s, "__schema") || strings.Contains(s, "introspectionquery") {
		return true
	}
	for i := strings.Index(s, "__type"); i >= 0; {
		end := i + len("__type")
		if end >= len(s) || !isGraphQLNameByte(s[end]) {
			return true
		}
		next := i + 1
		if next >= len(s) {
			return false
		}
		idx := strings.Index(s[next:], "__type")
		if idx < 0 {
			return false
		}
		i = next + idx
	}
	return false
}

func isGraphQLNameByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_'
}

func registeredCVERuleContainsLowCmdSignal(combinedLower string) bool {
	if len(combinedLower) == 0 {
		return false
	}
	if lowCmdTokenAtBoundary(combinedLower, 0) {
		return true
	}
	for i := 0; i < len(combinedLower)-1; i++ {
		if lowCmdBoundaryByte(combinedLower[i]) && lowCmdTokenAtBoundary(combinedLower, i+1) {
			return true
		}
	}
	return false
}

func lowCmdBoundaryByte(b byte) bool {
	switch b {
	case '&', '?', '=', '|', ';', '`', ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}

func lowCmdTokenAtBoundary(s string, offset int) bool {
	switch s[offset] {
	case 'w':
		return lowCmdSimpleTokenAt(s, offset, "whoami") ||
			lowCmdWhoAt(s, offset) ||
			lowCmdWhitespaceTokenAt(s, offset, "wget")
	case 'i':
		return lowCmdSimpleTokenAt(s, offset, "id") ||
			lowCmdSimpleTokenAt(s, offset, "ifconfig") ||
			lowCmdSimpleTokenAt(s, offset, "ipconfig")
	case 'h':
		return lowCmdSimpleTokenAt(s, offset, "hostname")
	case 's':
		return lowCmdSimpleTokenAt(s, offset, "systeminfo") ||
			lowCmdSimpleTokenAt(s, offset, "set")
	case 'p':
		return lowCmdSimpleTokenAt(s, offset, "pwd") ||
			lowCmdSimpleTokenAt(s, offset, "printenv") ||
			lowCmdPingOptionAt(s, offset)
	case 'e':
		return lowCmdCommandContextTokenAt(s, offset, "env")
	case 'u':
		return lowCmdUnameAt(s, offset)
	case 'c':
		return lowCmdWhitespaceTokenAt(s, offset, "curl") ||
			lowCmdCatEtcAt(s, offset)
	case 'n':
		return lowCmdWhitespaceTokenAt(s, offset, "nslookup") ||
			lowCmdNetUserAt(s, offset)
	case 'd':
		return lowCmdWhitespaceTokenAt(s, offset, "dig")
	case 't':
		return lowCmdWhitespaceTokenAt(s, offset, "traceroute")
	case 'l':
		return lowCmdLsLAAt(s, offset)
	default:
		return false
	}
}

func lowCmdSimpleTokenAt(s string, offset int, token string) bool {
	return hasPrefixAt(s, offset, token) && lowCmdSuffixAfter(s, offset+len(token))
}

func lowCmdCommandContextTokenAt(s string, offset int, token string) bool {
	if offset == 0 {
		return lowCmdSimpleTokenAt(s, offset, token)
	}
	switch s[offset-1] {
	case '|', ';', '`', ' ', '\t', '\r', '\n':
		return lowCmdSimpleTokenAt(s, offset, token)
	default:
		return false
	}
}

func lowCmdWhitespaceTokenAt(s string, offset int, token string) bool {
	end := offset + len(token)
	return hasPrefixAt(s, offset, token) && end < len(s) && isASCIISpaceByte(s[end])
}

func lowCmdUnameAt(s string, offset int) bool {
	end := offset + len("uname")
	if !hasPrefixAt(s, offset, "uname") {
		return false
	}
	pos := end
	for pos < len(s) && isASCIISpaceByte(s[pos]) {
		pos++
	}
	if pos+2 <= len(s) && s[pos] == '-' && s[pos+1] >= 'a' && s[pos+1] <= 'z' {
		pos += 2
	}
	return lowCmdSuffixAfter(s, pos)
}

func lowCmdWhoAt(s string, offset int) bool {
	if hasPrefixAt(s, offset, "who") {
		return lowCmdSpaceOrEndAfter(s, offset+len("who"))
	}
	if hasPrefixAt(s, offset, "w") {
		return lowCmdSpaceOrEndAfter(s, offset+len("w"))
	}
	return false
}

func lowCmdSpaceOrEndAfter(s string, offset int) bool {
	return offset >= len(s) || isASCIISpaceByte(s[offset])
}

func lowCmdNetUserAt(s string, offset int) bool {
	if !hasPrefixAt(s, offset, "net") {
		return false
	}
	pos := offset + len("net")
	if pos >= len(s) || !isASCIISpaceByte(s[pos]) {
		return false
	}
	for pos < len(s) && isASCIISpaceByte(s[pos]) {
		pos++
	}
	return hasPrefixAt(s, pos, "user")
}

func lowCmdCatEtcAt(s string, offset int) bool {
	if !hasPrefixAt(s, offset, "cat") {
		return false
	}
	pos := offset + len("cat")
	if pos >= len(s) || !isASCIISpaceByte(s[pos]) {
		return false
	}
	for pos < len(s) && isASCIISpaceByte(s[pos]) {
		pos++
	}
	return hasPrefixAt(s, pos, "/etc/passwd") || hasPrefixAt(s, pos, "/etc/shadow") || hasPrefixAt(s, pos, "/etc/hosts")
}

func lowCmdLsLAAt(s string, offset int) bool {
	if !hasPrefixAt(s, offset, "ls") {
		return false
	}
	pos := offset + len("ls")
	if pos >= len(s) || !isASCIISpaceByte(s[pos]) {
		return false
	}
	for pos < len(s) && isASCIISpaceByte(s[pos]) {
		pos++
	}
	return hasPrefixAt(s, pos, "-la")
}

func lowCmdPingOptionAt(s string, offset int) bool {
	if !hasPrefixAt(s, offset, "ping") {
		return false
	}
	pos := offset + len("ping")
	if pos >= len(s) || !isASCIISpaceByte(s[pos]) {
		return false
	}
	for pos < len(s) && isASCIISpaceByte(s[pos]) {
		pos++
	}
	return pos+2 <= len(s) && s[pos] == '-' && (s[pos+1] == 'n' || s[pos+1] == 'c')
}

func lowCmdSuffixAfter(s string, offset int) bool {
	for offset < len(s) && isASCIISpaceByte(s[offset]) {
		offset++
	}
	if offset >= len(s) {
		return true
	}
	switch s[offset] {
	case '&', ';', '|', ')', '`':
		return true
	case '%':
		return offset+2 < len(s) && isLowerHexByte(s[offset+1]) && isLowerHexByte(s[offset+2])
	default:
		return false
	}
}

func isASCIISpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\v' || b == '\f'
}

func isLowerHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
}

func hasJavaCodeInjectSignalLower(value string) bool {
	if strings.Contains(value, "processbuilder") ||
		strings.Contains(value, "javax.script") ||
		strings.Contains(value, "scriptenginemanager") ||
		strings.Contains(value, "getmethod") ||
		strings.Contains(value, "newinstance") ||
		strings.Contains(value, "unsafe") {
		return true
	}
	if strings.Contains(value, "runtime") && strings.Contains(value, "exec") {
		return true
	}
	if strings.Contains(value, "class") && strings.Contains(value, "forname") {
		return true
	}
	return strings.Contains(value, "reflect.method") && strings.Contains(value, "invoke")
}

func hasJavaOGNLSpELSignalLower(value string) bool {
	if strings.Contains(value, "#{") ||
		strings.Contains(value, "#context[") ||
		strings.Contains(value, "#attr[") ||
		strings.Contains(value, "#application[") ||
		strings.Contains(value, "#session[") ||
		strings.Contains(value, "#request[") ||
		strings.Contains(value, "#parameters[") ||
		strings.Contains(value, "#root") ||
		strings.Contains(value, "%23%7b") ||
		strings.Contains(value, "%24%7b") ||
		strings.Contains(value, ".getclass().forname") ||
		strings.Contains(value, "_memberaccess") ||
		strings.Contains(value, "actioncontext") ||
		strings.Contains(value, "java.lang.") ||
		strings.Contains(value, "ognlutil") ||
		strings.Contains(value, "valuestack") {
		return true
	}
	return strings.Contains(value, "${") && strings.Contains(value, "t(java.")
}

func hasDeepPathTraversalSignalLower(value string) bool {
	var slashCount, backslashCount, encodedCount int
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '.':
			if hasPrefixAt(value, i, "....//") ||
				hasPrefixAt(value, i, "..%c0%af") ||
				hasPrefixAt(value, i, "..%ef%bc%8f") ||
				hasPrefixAt(value, i, "..%25%35%63") ||
				hasPrefixAt(value, i, "..%c1%1c") ||
				hasPrefixAt(value, i, "..%c1%9c") ||
				hasPrefixAt(value, i, "..%c0%9v") ||
				hasPrefixAt(value, i, "..%uff0e%uff0e") ||
				hasPrefixAt(value, i, "..;/") {
				return true
			}
			if hasPrefixAt(value, i, "../") {
				slashCount++
				if slashCount >= 4 {
					return true
				}
				i += len("../") - 1
				continue
			}
			if hasPrefixAt(value, i, `..\`) {
				backslashCount++
				if backslashCount >= 4 {
					return true
				}
				i += len(`..\`) - 1
				continue
			}
		case '\\':
			if hasPrefixAt(value, i, `\.\.\.\.\`) {
				return true
			}
		case '/':
			if hasPrefixAt(value, i, "/.%2e/.%2e/") {
				return true
			}
		case '%':
			if hasPrefixAt(value, i, "%252e%252e/") || hasPrefixAt(value, i, "%c0%ae%c0%ae/") {
				return true
			}
			if hasPrefixAt(value, i, "%2e%2e%2f") {
				encodedCount++
				if encodedCount >= 4 {
					return true
				}
				i += len("%2e%2e%2f") - 1
				continue
			}
			if hasPrefixAt(value, i, "%2e%2e%5c") {
				encodedCount++
				if encodedCount >= 4 {
					return true
				}
				i += len("%2e%2e%5c") - 1
				continue
			}
		}
	}
	return false
}

func hasNoSQLInjectSignalLower(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] != '$' {
			continue
		}
		if hasPrefixAt(value, i, "$gt") ||
			hasPrefixAt(value, i, "$ne") ||
			hasPrefixAt(value, i, "$regex") ||
			hasPrefixAt(value, i, "$where") ||
			hasPrefixAt(value, i, "$or") ||
			hasPrefixAt(value, i, "$and") ||
			hasPrefixAt(value, i, "$not") ||
			hasPrefixAt(value, i, "$exists") ||
			hasPrefixAt(value, i, "$elemmatch") ||
			hasPrefixAt(value, i, "$nin") ||
			hasPrefixAt(value, i, "$lt") ||
			hasPrefixAt(value, i, "$gte") ||
			hasPrefixAt(value, i, "$lte") ||
			hasPrefixAt(value, i, "$in") ||
			hasPrefixAt(value, i, "$type") ||
			hasPrefixAt(value, i, "$size") ||
			hasPrefixAt(value, i, "$all") ||
			hasPrefixAt(value, i, "$mod") {
			return true
		}
	}
	return false
}

func hasCommvaultDeploySignalLower(value string) bool {
	return strings.Contains(value, "deploywebpackage.do") &&
		strings.Contains(value, "commcellname") &&
		strings.Contains(value, "servicepack") &&
		strings.Contains(value, "version=") &&
		registeredCVERuleContainsAny(value, "../", "%2e%2e", "http://", "https://", "/commandcenter/webpackage.do", ".zip")
}

func requestHasCommvaultDeploySignal(req *CVERequest) bool {
	return lowerTargetsContainAny(req.URLTargetsLower, "deploywebpackage.do") &&
		lowerTargetsContainAny(req.BodyTargetsLower, "commcellname") &&
		lowerTargetsContainAny(req.BodyTargetsLower, "servicepack") &&
		lowerTargetsContainAny(req.BodyTargetsLower, "version=") &&
		lowerTargetsContainAny(req.BodyTargetsLower, "../", "%2e%2e", "http://", "https://", "/commandcenter/webpackage.do", ".zip")
}

func hasRouterCGIPathSignalLower(value string) bool {
	return strings.Contains(value, "cgi") ||
		strings.Contains(value, "webcm") ||
		strings.Contains(value, "goform/") ||
		strings.Contains(value, "formlogin") ||
		strings.Contains(value, "boarddata")
}

func hasViteFSBypassSignalLower(value string) bool {
	return strings.Contains(value, "@fs/") &&
		registeredCVERuleContainsAny(value, "raw??", "html-proxy", "htmlproxy", "inline", "?url", "&url", ".html")
}

func hasLangflowValidateCodeSignalLower(value string) bool {
	return strings.Contains(value, "validate/code") &&
		registeredCVERuleContainsAny(value, "__import__", "exec(", "eval(", "open(", "subprocess", "child_process", "import os", "import subprocess")
}

func hasSharePointToolShellSignalLower(value string) bool {
	if strings.Contains(value, "spinstall0.aspx") || strings.Contains(value, "info3.aspx") {
		return true
	}
	return strings.Contains(value, "toolpane.aspx") &&
		strings.Contains(value, "displaymode=edit") &&
		strings.Contains(value, "signout.aspx") &&
		registeredCVERuleContainsAny(value, "msotlpn_dwp", "compresseddatatable", "__viewstate")
}

func hasJeecgSQLiSignalLower(value string) bool {
	return (strings.Contains(value, "/sys/") || strings.Contains(value, "/jmreport/")) &&
		registeredCVERuleContainsAny(value,
			"union", "select", "insert", "update", "delete", "drop",
			"sleep(", "benchmark(", "waitfor delay", "extractvalue", "updatexml", "load_file",
			"into outfile", "into dumpfile", " or ", " and ", "--", "#",
		)
}

func lowerTargetsHaveJavaInjectSignal(targets []string) bool {
	for _, lower := range targets {
		if hasJavaCodeInjectSignalLower(lower) || hasJavaOGNLSpELSignalLower(lower) {
			return true
		}
	}
	return false
}

func lowerTargetsHaveDeepPathTraversalSignal(targets []string) bool {
	for _, lower := range targets {
		if hasDeepPathTraversalSignalLower(lower) {
			return true
		}
	}
	return false
}

func lowerTargetsHaveNoSQLInjectSignal(targets []string) bool {
	for _, lower := range targets {
		if hasNoSQLInjectSignalLower(lower) {
			return true
		}
	}
	return false
}

func shouldScanRegisteredCVERule(rule *CVERule, combinedLower string) bool {
	switch rule.CVE {
	case "CVE-2023-GRAPHQL":
		return hasGraphQLIntrospectionSignalLower(combinedLower)
	case "CVE-2014-6271":
		return registeredCVERuleContainsAny(combinedLower, "() {")
	case "CVE-2025-30208":
		return hasViteFSBypassSignalLower(combinedLower)
	case "CVE-2025-3248":
		return hasLangflowValidateCodeSignalLower(combinedLower)
	case "CVE-2025-24893":
		return registeredCVERuleContainsAny(combinedLower, "solrsearch", "media=rss", "groovy", "{{async", "{{ async")
	case "CVE-2025-53770":
		return hasSharePointToolShellSignalLower(combinedLower)
	case "CVE-2025-34028":
		return hasCommvaultDeploySignalLower(combinedLower)
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
		return hasJeecgSQLiSignalLower(combinedLower)
	case "CVE-2021-21351":
		return registeredCVERuleContainsAny(combinedLower, "<java", "<sorted-set", "<dynamic-proxy", "xstream", "processbuilder", "runtime")
	case "CVE-2019-3929":
		return hasRouterCGIPathSignalLower(combinedLower)
	case "CVE-2024-JAVAINJ":
		return hasJavaCodeInjectSignalLower(combinedLower) || hasJavaOGNLSpELSignalLower(combinedLower)
	case "CVE-2024-REMOTECALL":
		return registeredCVERuleContainsAny(combinedLower, "jndi:", "ldap://", "rmi://", "iiop://", "jdbc:", "dns://")
	case "CVE-2024-DEEPPATH":
		return hasDeepPathTraversalSignalLower(combinedLower)
	case "CVE-2024-XXEUTF7":
		return registeredCVERuleContainsAny(combinedLower, "utf-7", "+adw-", "+adi-", "+afw-")
	case "CVE-2024-LDAPI":
		return registeredCVERuleContainsAny(combinedLower, "objectclass=", ")(|", ")(uid=", "*)(", "ldap")
	case "CVE-2024-NOSQLI":
		return hasNoSQLInjectSignalLower(combinedLower)
	case "CVE-2024-SENSFILE":
		return registeredCVERuleContainsAny(combinedLower, "/.env", "/.git/config", "/.htaccess", "/wp-config.php", "/web.config", "/etc/passwd")
	case "CVE-2024-LOWCMD":
		return registeredCVERuleContainsLowCmdSignal(combinedLower)
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
	DecodedPath        string
	DecodedQuery       string
	DecodedBody        string
	URLTargets         []string
	BodyTargets        []string
	URLBodyTargets     []string
	HeaderTargets      []string
	URLTargetsLower    []string
	BodyTargetsLower   []string
	HeaderTargetsLower []string
	AllTargets         []string // aggregated targets (path+query+header values+body)
	AllTargetsLower    []string // pre-lowercased AllTargets for hasCVESuspiciousContent
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
	req := &CVERequest{}
	BuildCVERequestInto(req, path, rawQuery, headers, body, contentType)
	return req
}

// BuildCVERequestInto fills dst with a normalised CVERequest from raw request components.
func BuildCVERequestInto(dst *CVERequest, path, rawQuery string, headers map[string]string, body []byte, contentType string) {
	bodyStr := buildCVEBodyString(body, contentType)

	decodedPath := multiDecode(path)
	decodedQuery := multiDecode(rawQuery)
	decodedBody := multiDecode(bodyStr)

	urlTargetCount := 1
	if decodedPath != path {
		urlTargetCount++
	}
	if rawQuery != "" {
		urlTargetCount++
		if decodedQuery != rawQuery {
			urlTargetCount++
		}
	}

	bodyTargetCount := 0
	if bodyStr != "" {
		bodyTargetCount++
		if decodedBody != bodyStr {
			bodyTargetCount++
		}
	}

	contentTypeCount := 0
	if contentType != "" {
		contentTypeCount = 1
	}

	targets := make([]string, 0, urlTargetCount+len(headers)+contentTypeCount+bodyTargetCount)
	targets = append(targets, path)
	if decodedPath != path {
		targets = append(targets, decodedPath)
	}
	if rawQuery != "" {
		targets = append(targets, rawQuery)
		if decodedQuery != rawQuery {
			targets = append(targets, decodedQuery)
		}
	}
	urlTargetsEnd := len(targets)

	headerTargetsStart := len(targets)
	for _, v := range headers {
		duplicate := false
		for _, existing := range targets[headerTargetsStart:] {
			if existing == v {
				duplicate = true
				break
			}
		}
		if !duplicate {
			targets = append(targets, v)
		}
	}
	headerTargetsEnd := len(targets)

	if contentType != "" {
		targets = append(targets, contentType)
	}
	bodyTargetsStart := len(targets)
	if bodyStr != "" {
		targets = append(targets, bodyStr)
		if decodedBody != bodyStr {
			targets = append(targets, decodedBody)
		}
	}

	urlTargets := targets[:urlTargetsEnd]
	headerTargets := targets[headerTargetsStart:headerTargetsEnd]
	bodyTargets := targets[bodyTargetsStart:]

	var urlBodyTargets []string
	if len(bodyTargets) == 0 {
		urlBodyTargets = urlTargets
	} else if headerTargetsStart == headerTargetsEnd && contentType == "" {
		urlBodyTargets = targets
	} else {
		urlBodyTargets = make([]string, 0, len(urlTargets)+len(bodyTargets))
		urlBodyTargets = append(urlBodyTargets, urlTargets...)
		urlBodyTargets = append(urlBodyTargets, bodyTargets...)
	}

	targetsLower := make([]string, len(targets))
	for i, t := range targets {
		targetsLower[i] = strings.ToLower(t)
	}
	urlTargetsLower := targetsLower[:urlTargetsEnd]
	headerTargetsLower := targetsLower[headerTargetsStart:headerTargetsEnd]
	bodyTargetsLower := targetsLower[bodyTargetsStart:]

	*dst = CVERequest{
		Path:               path,
		RawQuery:           rawQuery,
		Headers:            headers,
		Body:               bodyStr,
		ContentType:        contentType,
		DecodedPath:        decodedPath,
		DecodedQuery:       decodedQuery,
		DecodedBody:        decodedBody,
		URLTargets:         urlTargets,
		BodyTargets:        bodyTargets,
		URLBodyTargets:     urlBodyTargets,
		HeaderTargets:      headerTargets,
		URLTargetsLower:    urlTargetsLower,
		BodyTargetsLower:   bodyTargetsLower,
		HeaderTargetsLower: headerTargetsLower,
		AllTargets:         targets,
		AllTargetsLower:    targetsLower,
	}
}

func buildCVEBodyString(body []byte, contentType string) string {
	if len(body) == 0 {
		return ""
	}
	if strings.Contains(lowerCVERawTarget(contentType), "multipart/form-data") {
		return buildCVEMultipartBodyString(body, contentType)
	}
	return string(body)
}

func buildCVEMultipartBodyString(body []byte, contentType string) string {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	boundary := params["boundary"]
	if boundary == "" {
		return ""
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var out strings.Builder
	for i := 0; i < 20; i++ {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		appendCVEMultipartPartTarget(&out, part)
		part.Close()
	}
	return out.String()
}

func appendCVEMultipartPartTarget(out *strings.Builder, part *multipart.Part) {
	if out.Len() > 0 {
		out.WriteByte('\n')
	}
	if name := part.FormName(); name != "" {
		out.WriteString("name=")
		out.WriteString(name)
		out.WriteByte('\n')
	}
	filename := part.FileName()
	if filename != "" {
		out.WriteString("filename=")
		out.WriteString(filename)
		out.WriteByte('\n')
	}
	if partContentType := part.Header.Get("Content-Type"); partContentType != "" {
		out.WriteString("content-type=")
		out.WriteString(partContentType)
		out.WriteByte('\n')
	}

	buf, _ := io.ReadAll(io.LimitReader(part, 4096))
	if len(buf) == 0 || !cveBodyBytesMostlyText(buf) {
		return
	}
	out.Write(buf)
}

func cveBodyBytesMostlyText(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	printable := 0
	for _, b := range body {
		if (b >= 0x20 && b <= 0x7e) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return printable*100 >= len(body)*90
}

func lowerTargetsContainAny(targets []string, needles ...string) bool {
	if len(needles) == 1 {
		needle := needles[0]
		for _, lower := range targets {
			if strings.Contains(lower, needle) {
				return true
			}
		}
		return false
	}

	for _, lower := range targets {
		for _, needle := range needles {
			if strings.Contains(lower, needle) {
				return true
			}
		}
	}
	return false
}

func requestTargetContainsAny(req *CVERequest, target string, needles ...string) bool {
	switch target {
	case "url":
		return lowerTargetsContainAny(req.URLTargetsLower, needles...)
	case "body":
		return lowerTargetsContainAny(req.BodyTargetsLower, needles...)
	case "url_body":
		return lowerTargetsContainAny(req.URLTargetsLower, needles...) ||
			lowerTargetsContainAny(req.BodyTargetsLower, needles...)
	case "header":
		return lowerTargetsContainAny(req.HeaderTargetsLower, needles...)
	case "cookie":
		cookie, ok := cveHeaderValueOK(req.Headers, "Cookie")
		if !ok {
			return false
		}
		return stringsContainsAny(strings.ToLower(cookie), needles...)
	default:
		return lowerTargetsContainAny(req.AllTargetsLower, needles...)
	}
}

func stringsContainsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

// HasRawCVESuspiciousContent checks raw request components before building a
// full CVERequest. It mirrors the existing CVE fast path conservatively: when
// any raw field could become suspicious after normalization, callers must run
// the full BuildCVERequest + Detect path.
const (
	rawCVEHeaderOther = iota
	rawCVEHeaderContentLength
	rawCVEHeaderTransferEncoding
	rawCVEHeaderMiddlewareSubrequest
	rawCVEHeaderUserAgent
	rawCVEHeaderAccept
	rawCVEHeaderAcceptLanguage
)

func rawCVEHeaderKind(name string) int {
	switch name {
	case "Content-Length", "content-length":
		return rawCVEHeaderContentLength
	case "Transfer-Encoding", "transfer-encoding":
		return rawCVEHeaderTransferEncoding
	case "X-Middleware-Subrequest", "x-middleware-subrequest":
		return rawCVEHeaderMiddlewareSubrequest
	case "User-Agent", "user-agent":
		return rawCVEHeaderUserAgent
	case "Accept", "accept":
		return rawCVEHeaderAccept
	case "Accept-Language", "accept-language":
		return rawCVEHeaderAcceptLanguage
	}

	switch len(name) {
	case len("content-length"):
		if strings.EqualFold(name, "content-length") {
			return rawCVEHeaderContentLength
		}
	case len("transfer-encoding"):
		if strings.EqualFold(name, "transfer-encoding") {
			return rawCVEHeaderTransferEncoding
		}
	case len("x-middleware-subrequest"):
		if strings.EqualFold(name, "x-middleware-subrequest") {
			return rawCVEHeaderMiddlewareSubrequest
		}
	case len("user-agent"):
		if strings.EqualFold(name, "user-agent") {
			return rawCVEHeaderUserAgent
		}
	case len("accept"):
		if strings.EqualFold(name, "accept") {
			return rawCVEHeaderAccept
		}
	case len("accept-language"):
		if strings.EqualFold(name, "accept-language") {
			return rawCVEHeaderAcceptLanguage
		}
	}
	return rawCVEHeaderOther
}

func HasRawCVESuspiciousContent(path, rawQuery string, headers map[string]string, body []byte, contentType string) bool {
	if rawTargetHasCVESuspiciousContent(path) ||
		rawTargetHasCVESuspiciousContent(rawQuery) ||
		rawContentTypeHasCVESuspiciousContent(contentType) {
		return true
	}

	hasCL := false
	hasTE := false
	for k, v := range headers {
		headerKind := rawCVEHeaderKind(k)
		switch headerKind {
		case rawCVEHeaderContentLength:
			hasCL = true
		case rawCVEHeaderTransferEncoding:
			hasTE = true
			vl := strings.ToLower(v)
			if strings.Contains(vl, " chunked") || strings.Contains(vl, "\tchunked") ||
				strings.Contains(vl, "chunked ") || strings.Contains(vl, ",chunked") {
				return true
			}
		case rawCVEHeaderMiddlewareSubrequest:
			if strings.Contains(strings.ToLower(v), "middleware") {
				return true
			}
		}

		if shouldSkipRawCVEHeaderTarget(headerKind, v) {
			continue
		}
		if rawTargetHasCVESuspiciousContent(v) {
			return true
		}
	}
	if hasCL && hasTE {
		return true
	}
	if rawBodyHasCVESuspiciousContent(body) {
		return true
	}
	return false
}

func shouldSkipRawCVEHeaderTarget(headerKind int, value string) bool {
	switch headerKind {
	case rawCVEHeaderUserAgent:
		return value == "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	case rawCVEHeaderAccept:
		switch value {
		case "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"text/html",
			"application/json":
			return true
		}
	case rawCVEHeaderAcceptLanguage:
		return value == "zh-CN,zh;q=0.9,en;q=0.8" || value == "en-US,en;q=0.9"
	}
	return false
}

func rawTargetHasCVESuspiciousContent(raw string) bool {
	if raw == "" {
		return false
	}
	if strings.Contains(raw, "%") || looksLikeStdBase64(raw) {
		return true
	}
	lower := lowerCVERawTarget(raw)
	return hasCVEHighRiskPunctuation(raw, lower) || hasCVEKnownIndicator(lower)
}

func rawContentTypeHasCVESuspiciousContent(contentType string) bool {
	if contentType == "" {
		return false
	}
	if strings.EqualFold(contentType, "application/json") {
		return false
	}
	if strings.Contains(contentType, "%") {
		return true
	}
	lower := lowerCVERawTarget(contentType)
	return hasCVEHighRiskPunctuation(contentType, lower) || hasCVEKnownIndicator(lower)
}

func rawBodyHasCVESuspiciousContent(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	if looksLikeStdBase64Bytes(body) {
		return true
	}
	if rawBodyIsSimpleJSONWithoutCVEIndicator(body) {
		return false
	}
	return rawBodyHasCVEByteIndicator(body)
}

func looksLikeStdBase64Bytes(body []byte) bool {
	if len(body) < 4 || len(body)%4 != 0 {
		return false
	}
	padding := 0
	for _, c := range body {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			if padding > 0 {
				return false
			}
		case c == '=':
			padding++
			if padding > 2 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func rawBodyIsSimpleJSONWithoutCVEIndicator(body []byte) bool {
	tokenStart := -1
	for i, b := range body {
		if isSimpleJSONTokenByte(b) {
			if tokenStart == -1 {
				tokenStart = i
			}
			continue
		}
		if tokenStart != -1 {
			if rawBodyTokenHasCVEIndicator(body, tokenStart, i) ||
				(b == ':' && rawBodyTokenHasColonCVEIndicator(body, tokenStart, i)) {
				return false
			}
			tokenStart = -1
		}
		switch b {
		case ' ', '\t', '\r', '\n', '{', '}', '[', ']', ':', ',', '"':
			continue
		default:
			return false
		}
	}
	if tokenStart != -1 && rawBodyTokenHasCVEIndicator(body, tokenStart, len(body)) {
		return false
	}
	return true
}

func isSimpleJSONTokenByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '_'
}

func rawBodyTokenHasCVEIndicator(body []byte, offset, end int) bool {
	tokenLen := end - offset
	switch lowerCVEASCIIByte(body[offset]) {
	case '_':
		if tokenLen < len("__proto__") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "__proto__") ||
			hasRawBodyPrefixFoldAt(body, offset, "__viewstate") ||
			hasRawBodyPrefixFoldAt(body, offset, "__import__")
	case 'a':
		if tokenLen < len("authhash") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "addresponseheader") ||
			hasRawBodyPrefixFoldAt(body, offset, "actioncontext") ||
			hasRawBodyPrefixFoldAt(body, offset, "authhash")
	case 'b':
		if tokenLen < len("busybox") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "busybox")
	case 'c':
		if tokenLen < len("cgi") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "cgi") ||
			hasRawBodyPrefixFoldAt(body, offset, "cgiinfo") ||
			hasRawBodyPrefixFoldAt(body, offset, "citrix") ||
			hasRawBodyPrefixFoldAt(body, offset, "classloader") ||
			hasRawBodyPrefixFoldAt(body, offset, "commcellname") ||
			hasRawBodyPrefixFoldAt(body, offset, "compresseddatatable") ||
			hasRawBodyPrefixFoldAt(body, offset, "confluence") ||
			hasRawBodyPrefixFoldAt(body, offset, "constructor") ||
			hasRawBodyPrefixFoldAt(body, offset, "crushftp") ||
			hasRawBodyPrefixFoldAt(body, offset, "customcss") ||
			hasRawBodyPrefixFoldAt(body, offset, "curl")
	case 'd':
		if tokenLen < len("dana") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "dana") ||
			hasRawBodyPrefixFoldAt(body, offset, "developmentserver")
	case 'e':
		if tokenLen < len("eval") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "eval") ||
			hasRawBodyPrefixFoldAt(body, offset, "exec") ||
			hasRawBodyPrefixFoldAt(body, offset, "extractvalue")
	case 'f':
		if tokenLen < len("fwbcgi") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "filename") ||
			hasRawBodyPrefixFoldAt(body, offset, "fwbcgi")
	case 'g':
		if tokenLen < len("groovy") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "getruntime") ||
			hasRawBodyPrefixFoldAt(body, offset, "globalprotect") ||
			hasRawBodyPrefixFoldAt(body, offset, "graphql") ||
			hasRawBodyPrefixFoldAt(body, offset, "groovy")
	case 'h':
		if tokenLen < len("hostname") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "hostcheck_validate") ||
			hasRawBodyPrefixFoldAt(body, offset, "hostname")
	case 'i':
		if tokenLen < len("ivanti") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "ifconfig") ||
			hasRawBodyPrefixFoldAt(body, offset, "introspection") ||
			hasRawBodyPrefixFoldAt(body, offset, "invokefunction") ||
			hasRawBodyPrefixFoldAt(body, offset, "ipconfig") ||
			hasRawBodyPrefixFoldAt(body, offset, "ivanti")
	case 'j':
		if tokenLen < len("jeecg") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "jeecg")
	case 'l':
		if tokenLen < len("lua") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "ldap") ||
			hasRawBodyPrefixFoldAt(body, offset, "localhost") ||
			hasRawBodyPrefixFoldAt(body, offset, "lua")
	case 'm':
		if tokenLen < len("magicinfo") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "magicinfo") ||
			hasRawBodyPrefixFoldAt(body, offset, "metadatauploader") ||
			hasRawBodyPrefixFoldAt(body, offset, "msotlpn_dwp")
	case 'o':
		if tokenLen < len("ognl") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "ognl") ||
			hasRawBodyPrefixFoldAt(body, offset, "open")
	case 'p':
		if tokenLen < len("priorityqueue") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "priorityqueue") ||
			hasRawBodyPrefixFoldAt(body, offset, "processbuilder")
	case 'r':
		if tokenLen < len("runtime") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "runtime")
	case 's':
		if tokenLen < len("sys") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "scriptengine") ||
			hasRawBodyPrefixFoldAt(body, offset, "select") ||
			hasRawBodyPrefixFoldAt(body, offset, "serializ") ||
			hasRawBodyPrefixFoldAt(body, offset, "servicepack") ||
			hasRawBodyPrefixFoldAt(body, offset, "sleep") ||
			hasRawBodyPrefixFoldAt(body, offset, "solrsearch") ||
			hasRawBodyPrefixFoldAt(body, offset, "spel") ||
			hasRawBodyPrefixFoldAt(body, offset, "struts") ||
			hasRawBodyPrefixFoldAt(body, offset, "subprocess") ||
			hasRawBodyPrefixFoldAt(body, offset, "swupdatefileuploader") ||
			hasRawBodyPrefixFoldAt(body, offset, "sys") ||
			hasRawBodyPrefixFoldAt(body, offset, "system") ||
			hasRawBodyPrefixFoldAt(body, offset, "systeminfo")
	case 't':
		if tokenLen < len("template") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "template") ||
			hasRawBodyPrefixFoldAt(body, offset, "themeeditor") ||
			hasRawBodyPrefixFoldAt(body, offset, "toolshell")
	case 'u':
		if tokenLen < len("uname") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "uname") ||
			hasRawBodyPrefixFoldAt(body, offset, "union") ||
			hasRawBodyPrefixFoldAt(body, offset, "updatexml") ||
			hasRawBodyPrefixFoldAt(body, offset, "upload")
	case 'v':
		if tokenLen < len("valuestack") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "valuestack")
	case 'w':
		if tokenLen < len("wget") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "wget") ||
			hasRawBodyPrefixFoldAt(body, offset, "whoami")
	case 'x':
		if tokenLen < len("xstream") {
			return false
		}
		return hasRawBodyPrefixFoldAt(body, offset, "xstream")
	}
	return false
}

func rawBodyTokenHasColonCVEIndicator(body []byte, start, end int) bool {
	switch lowerCVEASCIIByte(body[start]) {
	case 'a':
		return end-start == 1
	case 'j':
		return (end-start == len("jdbc") && hasRawBodyPrefixFoldAt(body, start, "jdbc")) ||
			(end-start == len("jndi") && hasRawBodyPrefixFoldAt(body, start, "jndi"))
	case 'o':
		return end-start == 1
	}
	return false
}

func rawBodyHasCVEByteIndicator(body []byte) bool {
	hasBrace := false
	hasSemicolon := false
	hasAngle := false
	hasParen := false
	hasBracket := false
	braceIndicator := false
	semicolonIndicator := false
	angleIndicator := false
	parenIndicator := false
	bracketIndicator := false

	for i, b := range body {
		switch b {
		case '%', '\\', '|', '`':
			return true
		case '{', '}':
			hasBrace = true
		case ';':
			hasSemicolon = true
		case '<', '>':
			hasAngle = true
		case '(', ')':
			hasParen = true
		case '[', ']':
			hasBracket = true
		}

		switch lowerCVEASCIIByte(b) {
		case '$':
			if hasRawBodyPrefixFoldAt(body, i, "${") ||
				hasRawBodyPrefixFoldAt(body, i, "$gt") ||
				hasRawBodyPrefixFoldAt(body, i, "$ne") ||
				hasRawBodyPrefixFoldAt(body, i, "$regex") ||
				hasRawBodyPrefixFoldAt(body, i, "$where") ||
				hasRawBodyPrefixFoldAt(body, i, "$or") ||
				hasRawBodyPrefixFoldAt(body, i, "$and") {
				return true
			}
		case '#':
			if hasRawBodyPrefixFoldAt(body, i, "#_member") {
				return true
			}
			if hasRawBodyPrefixFoldAt(body, i, "#{") {
				braceIndicator = true
			}
		case '+':
			if hasRawBodyPrefixFoldAt(body, i, "+adw-") {
				return true
			}
		case '.':
			if hasRawBodyPrefixFoldAt(body, i, "../") ||
				hasRawBodyPrefixFoldAt(body, i, "..\\") ||
				hasRawBodyPrefixFoldAt(body, i, "....//") {
				return true
			}
		case '/':
			if hasRawBodyPrefixFoldAt(body, i, "/sys/dict/loadtreedata") ||
				hasRawBodyPrefixFoldAt(body, i, "/sys/duplicate/check") ||
				hasRawBodyPrefixFoldAt(body, i, "/sys/user/querysysuser") ||
				hasRawBodyPrefixFoldAt(body, i, "/cgi-bin/") ||
				hasRawBodyPrefixFoldAt(body, i, "/.env") ||
				hasRawBodyPrefixFoldAt(body, i, "/.git/config") ||
				hasRawBodyPrefixFoldAt(body, i, "/.htaccess") ||
				hasRawBodyPrefixFoldAt(body, i, "/.htpasswd") ||
				hasRawBodyPrefixFoldAt(body, i, "/wp-config.php") ||
				hasRawBodyPrefixFoldAt(body, i, "/web.config") ||
				hasRawBodyPrefixFoldAt(body, i, "/database.yml") ||
				hasRawBodyPrefixFoldAt(body, i, "/settings.py") ||
				hasRawBodyPrefixFoldAt(body, i, "/application.properties") ||
				hasRawBodyPrefixFoldAt(body, i, "/etc/passwd") ||
				hasRawBodyPrefixFoldAt(body, i, "/etc/shadow") ||
				hasRawBodyPrefixFoldAt(body, i, "/.ds_store") ||
				hasRawBodyPrefixFoldAt(body, i, "/.svn/entries") {
				return true
			}
		case '0':
			if hasRawBodyPrefixFoldAt(body, i, "0x") {
				return true
			}
		case '1':
			if hasRawBodyPrefixFoldAt(body, i, "169.254.169.254") {
				return true
			}
		case '<':
			if hasRawBodyPrefixFoldAt(body, i, "<!doctype") ||
				hasRawBodyPrefixFoldAt(body, i, "<!entity") ||
				hasRawBodyPrefixFoldAt(body, i, "<sorted-set>") ||
				hasRawBodyPrefixFoldAt(body, i, "<dynamic-proxy>") {
				return true
			}
			if hasRawBodyPrefixFoldAt(body, i, "<script") ||
				hasRawBodyPrefixFoldAt(body, i, "</") {
				angleIndicator = true
			}
		case '@':
			if hasRawBodyPrefixFoldAt(body, i, "@type") ||
				hasRawBodyPrefixFoldAt(body, i, "@fs/") {
				return true
			}
		case '_':
			if hasRawBodyPrefixFoldAt(body, i, "__proto__") ||
				hasRawBodyPrefixFoldAt(body, i, "__viewstate") {
				return true
			}
		case 'a':
			if hasRawBodyPrefixFoldAt(body, i, "actuator/gateway") ||
				hasRawBodyPrefixFoldAt(body, i, "addresponseheader") ||
				hasRawBodyPrefixFoldAt(body, i, "actioncontext") ||
				hasRawBodyPrefixFoldAt(body, i, "authhash") ||
				hasRawBodyPrefixFoldAt(body, i, "aws4-hmac-sha256") {
				return true
			}
			if hasRawBodyPrefixFoldAt(body, i, "async=false") ||
				hasRawBodyPrefixFoldAt(body, i, "a:") {
				braceIndicator = true
			}
		case 'c':
			if hasRawBodyPrefixFoldAt(body, i, "cgi-bin/fwbcgi") ||
				hasRawBodyPrefixFoldAt(body, i, "cgiinfo") ||
				hasRawBodyPrefixFoldAt(body, i, "charset=utf-7") ||
				hasRawBodyPrefixFoldAt(body, i, "charset=utf-16") ||
				hasRawBodyPrefixFoldAt(body, i, "charset=utf-32") ||
				hasRawBodyPrefixFoldAt(body, i, "child_process") ||
				hasRawBodyPrefixFoldAt(body, i, "class.forname") ||
				hasRawBodyPrefixFoldAt(body, i, "classloader") ||
				hasRawBodyPrefixFoldAt(body, i, "compresseddatatable") ||
				hasRawBodyPrefixFoldAt(body, i, "constructor") ||
				hasRawBodyPrefixFoldAt(body, i, "content-length") ||
				hasRawBodyPrefixFoldAt(body, i, "customcss") {
				return true
			}
		case 'd':
			if hasRawBodyPrefixFoldAt(body, i, "deploywebpackage.do") ||
				hasRawBodyPrefixFoldAt(body, i, "developmentserver") ||
				hasRawBodyPrefixFoldAt(body, i, "diagnostic.cgi") {
				return true
			}
			if hasRawBodyPrefixFoldAt(body, i, "drop") ||
				hasRawBodyPrefixFoldAt(body, i, "delete") {
				semicolonIndicator = true
			}
		case 'e':
			if hasRawBodyPrefixFoldAt(body, i, "eval-stdin") ||
				hasRawBodyPrefixFoldAt(body, i, "expression=") {
				return true
			}
			if hasRawBodyPrefixFoldAt(body, i, "exec") {
				semicolonIndicator = true
				parenIndicator = true
			}
		case 'f':
			if hasRawBodyPrefixFoldAt(body, i, "file://") {
				return true
			}
		case 'g':
			if hasRawBodyPrefixFoldAt(body, i, "garequestaction=activate") ||
				hasRawBodyPrefixFoldAt(body, i, "getruntime") ||
				hasRawBodyPrefixFoldAt(body, i, "globalprotect") ||
				hasRawBodyPrefixFoldAt(body, i, "graphql") {
				return true
			}
			if hasRawBodyPrefixFoldAt(body, i, "groovy") ||
				hasRawBodyPrefixFoldAt(body, i, "globalthis") {
				braceIndicator = true
				bracketIndicator = true
			}
		case 'h':
			if hasRawBodyPrefixFoldAt(body, i, "hostcheck_validate") ||
				hasRawBodyPrefixFoldAt(body, i, "hostname") ||
				hasRawBodyPrefixFoldAt(body, i, "http://") ||
				hasRawBodyPrefixFoldAt(body, i, "https://") {
				return true
			}
		case 'i':
			if hasRawBodyPrefixFoldAt(body, i, "ifconfig") ||
				hasRawBodyPrefixFoldAt(body, i, "introspection") ||
				hasRawBodyPrefixFoldAt(body, i, "invokefunction") ||
				hasRawBodyPrefixFoldAt(body, i, "ipconfig") ||
				hasRawBodyPrefixFoldAt(body, i, "iso-2022-jp") {
				return true
			}
			if hasRawBodyPrefixFoldAt(body, i, "insert") {
				semicolonIndicator = true
			}
		case 'j':
			if hasRawBodyPrefixFoldAt(body, i, "java.lang.runtime") ||
				hasRawBodyPrefixFoldAt(body, i, "javax.faces.viewstate") ||
				hasRawBodyPrefixFoldAt(body, i, "javax.naming") ||
				hasRawBodyPrefixFoldAt(body, i, "jdbc:") ||
				hasRawBodyPrefixFoldAt(body, i, "jndi:") ||
				hasRawBodyPrefixFoldAt(body, i, "json-patch+json") {
				return true
			}
		case 'l':
			if hasRawBodyPrefixFoldAt(body, i, "ldap://") ||
				hasRawBodyPrefixFoldAt(body, i, "ldaps://") ||
				hasRawBodyPrefixFoldAt(body, i, "loginok.html") {
				return true
			}
		case 'm':
			if hasRawBodyPrefixFoldAt(body, i, "metadata.google") ||
				hasRawBodyPrefixFoldAt(body, i, "metadatauploader") ||
				hasRawBodyPrefixFoldAt(body, i, "msotlpn_dwp") ||
				hasRawBodyPrefixFoldAt(body, i, "multipart/form-data") {
				return true
			}
		case 'n':
			if hasRawBodyPrefixFoldAt(body, i, "net user") {
				return true
			}
		case 'o':
			if hasRawBodyPrefixFoldAt(body, i, "objectclass=") ||
				hasRawBodyPrefixFoldAt(body, i, "ognl") {
				return true
			}
			if hasRawBodyPrefixFoldAt(body, i, "o:") {
				braceIndicator = true
			}
		case 'p':
			if hasRawBodyPrefixFoldAt(body, i, "php://") ||
				hasRawBodyPrefixFoldAt(body, i, "ping.cgi") ||
				hasRawBodyPrefixFoldAt(body, i, "priorityqueue") ||
				hasRawBodyPrefixFoldAt(body, i, "processbuilder") {
				return true
			}
		case 'r':
			if hasRawBodyPrefixFoldAt(body, i, "raw??") ||
				hasRawBodyPrefixFoldAt(body, i, "reflect.method") ||
				hasRawBodyPrefixFoldAt(body, i, "rememberme=") ||
				hasRawBodyPrefixFoldAt(body, i, "rmi://") {
				return true
			}
			if hasRawBodyPrefixFoldAt(body, i, "runtime") {
				parenIndicator = true
			}
		case 's':
			if hasRawBodyPrefixFoldAt(body, i, "scriptengine") ||
				hasRawBodyPrefixFoldAt(body, i, "serializ") ||
				hasRawBodyPrefixFoldAt(body, i, "shift-jis") ||
				hasRawBodyPrefixFoldAt(body, i, "signout.aspx") ||
				hasRawBodyPrefixFoldAt(body, i, "solrsearch") ||
				hasRawBodyPrefixFoldAt(body, i, "spinstall0.aspx") ||
				hasRawBodyPrefixFoldAt(body, i, "swupdatefileuploader") ||
				hasRawBodyPrefixFoldAt(body, i, "syscmd.cgi") ||
				hasRawBodyPrefixFoldAt(body, i, "systeminfo") {
				return true
			}
			if hasRawBodyPrefixFoldAt(body, i, "select") ||
				hasRawBodyPrefixFoldAt(body, i, "system") {
				semicolonIndicator = true
			}
		case 't':
			if hasRawBodyPrefixFoldAt(body, i, "themeeditor") ||
				hasRawBodyPrefixFoldAt(body, i, "toolshell") ||
				hasRawBodyPrefixFoldAt(body, i, "toolpane.aspx") ||
				hasRawBodyPrefixFoldAt(body, i, "transfer-encoding") {
				return true
			}
			if hasRawBodyPrefixFoldAt(body, i, "this[") {
				bracketIndicator = true
			}
		case 'u':
			if hasRawBodyPrefixFoldAt(body, i, "uname") ||
				hasRawBodyPrefixFoldAt(body, i, "unlicensed.xhtml") {
				return true
			}
			if hasRawBodyPrefixFoldAt(body, i, "union") ||
				hasRawBodyPrefixFoldAt(body, i, "unserialize") ||
				hasRawBodyPrefixFoldAt(body, i, "update") {
				semicolonIndicator = true
				braceIndicator = true
			}
		case 'v':
			if hasRawBodyPrefixFoldAt(body, i, "validate/code") ||
				hasRawBodyPrefixFoldAt(body, i, "valuestack") {
				return true
			}
		case 'w':
			if hasRawBodyPrefixFoldAt(body, i, "webinterface/function") ||
				hasRawBodyPrefixFoldAt(body, i, "whoami") {
				return true
			}
			if hasRawBodyPrefixFoldAt(body, i, "window[") {
				bracketIndicator = true
			}
		case 'x':
			if hasRawBodyPrefixFoldAt(body, i, "x-middleware") {
				return true
			}
		case ')':
			if hasRawBodyPrefixFoldAt(body, i, ")(|") ||
				hasRawBodyPrefixFoldAt(body, i, ")(uid=") {
				return true
			}
		}
	}

	return (hasBrace && braceIndicator) ||
		(hasSemicolon && semicolonIndicator) ||
		(hasAngle && angleIndicator) ||
		(hasParen && parenIndicator) ||
		(hasBracket && bracketIndicator)
}

func hasRawBodyPrefixFoldAt(body []byte, offset int, prefix string) bool {
	if len(body)-offset < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if lowerCVEASCIIByte(body[offset+i]) != prefix[i] {
			return false
		}
	}
	return true
}

func lowerCVEASCIIByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func lowerCVERawTarget(raw string) string {
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if (b >= 'A' && b <= 'Z') || b >= 0x80 {
			return strings.ToLower(raw)
		}
	}
	return raw
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
	ua := cveHeaderValue(req.Headers, "User-Agent")
	regMatches := globalCVERuleRegistry.DetectAll(uri, req.Body, ua, req.Headers)
	matches = append(matches, regMatches...)

	return matches
}

// DetectFirst returns the first CVE match using the same detector order as Detect.
func (d *CVEDetector) DetectFirst(req *CVERequest, categorySensitivity ...map[string]string) (CVEMatch, bool) {
	if !hasCVESuspiciousContent(req) {
		return CVEMatch{}, false
	}

	var catSens map[string]string
	if len(categorySensitivity) > 0 {
		catSens = categorySensitivity[0]
	}

	isDetectorEnabled := func(key string) bool {
		if catSens == nil {
			return true
		}
		level := strings.ToLower(strings.TrimSpace(catSens[key]))
		return level != "none" && level != "off"
	}

	if isDetectorEnabled("cve_general") {
		if m, ok := d.generalDetector.DetectFirst(req); ok {
			return m, true
		}
	}
	if isDetectorEnabled("cve_php") {
		if m, ok := d.phpDetector.DetectFirst(req); ok {
			return m, true
		}
	}
	if isDetectorEnabled("cve_java") {
		if m, ok := d.javaDetector.DetectFirst(req); ok {
			return m, true
		}
	}
	if isDetectorEnabled("cve_node") {
		if m, ok := d.nodeDetector.DetectFirst(req); ok {
			return m, true
		}
	}

	d.mu.RLock()
	customs := d.compiledCustom
	d.mu.RUnlock()

	for _, cr := range customs {
		if !cr.rule.Enabled {
			continue
		}
		target := pickTarget(req, cr.rule.Target)
		if cr.re.MatchString(target) {
			return CVEMatch{
				CVEID:       cr.rule.CVEID,
				Category:    cr.rule.Category,
				Severity:    cr.rule.Severity,
				Description: cr.rule.Description,
				MatchedPart: cr.rule.Target,
				Pattern:     cr.rule.Pattern,
				Action:      cr.rule.Action,
			}, true
		}
	}

	uri := req.DecodedPath
	if req.DecodedQuery != "" {
		uri = uri + "?" + req.DecodedQuery
	}
	ua := cveHeaderValue(req.Headers, "User-Agent")
	return globalCVERuleRegistry.DetectFirst(uri, req.Body, ua, req.Headers)
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
	if checkHTTPSmuggling(req) {
		return true
	}
	if hasCVEHeaderNameIndicator(req.Headers) {
		return true
	}
	for i, t := range req.AllTargets {
		if len(t) < 3 {
			continue
		}
		lower := req.AllTargetsLower[i]
		if hasCVEHighRiskPunctuation(t, lower) {
			return true
		}
		if hasCVEKnownIndicator(lower) {
			return true
		}
	}
	return false
}

func hasCVEHeaderNameIndicator(headers map[string]string) bool {
	for k, v := range headers {
		if strings.EqualFold(k, "x-middleware-subrequest") && strings.Contains(strings.ToLower(v), "middleware") {
			return true
		}
	}
	return false
}

func hasPrefixAt(s string, offset int, prefix string) bool {
	return len(s)-offset >= len(prefix) && strings.HasPrefix(s[offset:], prefix)
}

func hasCVEKnownIndicator(lower string) bool {
	for i := 0; i < len(lower); i++ {
		switch lower[i] {
		case '$':
			if hasPrefixAt(lower, i, "$gt") || hasPrefixAt(lower, i, "$ne") ||
				hasPrefixAt(lower, i, "$regex") || hasPrefixAt(lower, i, "$where") ||
				hasPrefixAt(lower, i, "$or") || hasPrefixAt(lower, i, "$and") {
				return true
			}
		case '#':
			if hasPrefixAt(lower, i, "#_member") {
				return true
			}
		case '%':
			if hasPrefixAt(lower, i, "%0d%0a") || hasPrefixAt(lower, i, "%2e%2e") ||
				hasPrefixAt(lower, i, "%ad") || hasPrefixAt(lower, i, "%252e") ||
				hasPrefixAt(lower, i, "%c0%af") || hasPrefixAt(lower, i, "%ef%bc%8f") {
				return true
			}
		case '+':
			if hasPrefixAt(lower, i, "+adw-") {
				return true
			}
		case '.':
			if hasPrefixAt(lower, i, "../") || hasPrefixAt(lower, i, "..\\") ||
				hasPrefixAt(lower, i, "....//") {
				return true
			}
		case '/':
			if hasPrefixAt(lower, i, "/sys/dict/loadtreedata") ||
				hasPrefixAt(lower, i, "/sys/duplicate/check") ||
				hasPrefixAt(lower, i, "/sys/user/querysysuser") ||
				hasPrefixAt(lower, i, "/cgi-bin/") ||
				hasPrefixAt(lower, i, "/.env") ||
				hasPrefixAt(lower, i, "/.git/config") ||
				hasPrefixAt(lower, i, "/.htaccess") ||
				hasPrefixAt(lower, i, "/.htpasswd") ||
				hasPrefixAt(lower, i, "/wp-config.php") ||
				hasPrefixAt(lower, i, "/web.config") ||
				hasPrefixAt(lower, i, "/database.yml") ||
				hasPrefixAt(lower, i, "/settings.py") ||
				hasPrefixAt(lower, i, "/application.properties") ||
				hasPrefixAt(lower, i, "/etc/passwd") ||
				hasPrefixAt(lower, i, "/etc/shadow") ||
				hasPrefixAt(lower, i, "/.ds_store") ||
				hasPrefixAt(lower, i, "/.svn/entries") {
				return true
			}
		case '0':
			if hasPrefixAt(lower, i, "0x") {
				return true
			}
		case '1':
			if hasPrefixAt(lower, i, "169.254.169.254") {
				return true
			}
		case '<':
			if hasPrefixAt(lower, i, "<!doctype") ||
				hasPrefixAt(lower, i, "<!entity") ||
				hasPrefixAt(lower, i, "<sorted-set>") ||
				hasPrefixAt(lower, i, "<dynamic-proxy>") {
				return true
			}
		case '@':
			if hasPrefixAt(lower, i, "@type") || hasPrefixAt(lower, i, "@fs/") {
				return true
			}
		case '_':
			if hasPrefixAt(lower, i, "__proto__") {
				return true
			}
		case 'a':
			if hasPrefixAt(lower, i, "actuator/gateway") ||
				hasPrefixAt(lower, i, "addresponseheader") ||
				hasPrefixAt(lower, i, "actioncontext") ||
				hasPrefixAt(lower, i, "authhash") ||
				hasPrefixAt(lower, i, "aws4-hmac-sha256") {
				return true
			}
		case 'c':
			if hasPrefixAt(lower, i, "cgi-bin/fwbcgi") ||
				hasPrefixAt(lower, i, "cgiinfo") ||
				hasPrefixAt(lower, i, "charset=utf-7") ||
				hasPrefixAt(lower, i, "charset=utf-16") ||
				hasPrefixAt(lower, i, "charset=utf-32") ||
				hasPrefixAt(lower, i, "child_process") ||
				hasPrefixAt(lower, i, "class.forname") ||
				hasPrefixAt(lower, i, "classloader") ||
				hasPrefixAt(lower, i, "constructor") ||
				hasPrefixAt(lower, i, "content-length") ||
				hasPrefixAt(lower, i, "customcss") {
				return true
			}
		case 'd':
			if hasPrefixAt(lower, i, "deploywebpackage.do") ||
				hasPrefixAt(lower, i, "developmentserver") ||
				hasPrefixAt(lower, i, "diagnostic.cgi") {
				return true
			}
		case 'e':
			if hasPrefixAt(lower, i, "eval-stdin") ||
				hasPrefixAt(lower, i, "expression=") {
				return true
			}
		case 'f':
			if hasPrefixAt(lower, i, "file://") {
				return true
			}
		case 'g':
			if hasPrefixAt(lower, i, "garequestaction=activate") ||
				hasPrefixAt(lower, i, "getruntime") ||
				hasPrefixAt(lower, i, "globalprotect") ||
				hasPrefixAt(lower, i, "graphql") {
				return true
			}
		case 'h':
			if hasPrefixAt(lower, i, "hostcheck_validate") ||
				hasPrefixAt(lower, i, "hostname") ||
				hasPrefixAt(lower, i, "http://") ||
				hasPrefixAt(lower, i, "https://") {
				return true
			}
		case 'i':
			if hasPrefixAt(lower, i, "ifconfig") ||
				hasPrefixAt(lower, i, "introspection") ||
				hasPrefixAt(lower, i, "invokefunction") ||
				hasPrefixAt(lower, i, "ipconfig") ||
				hasPrefixAt(lower, i, "iso-2022-jp") {
				return true
			}
		case 'j':
			if hasPrefixAt(lower, i, "java.lang.runtime") ||
				hasPrefixAt(lower, i, "javax.faces.viewstate") ||
				hasPrefixAt(lower, i, "javax.naming") ||
				hasPrefixAt(lower, i, "jdbc:") ||
				hasPrefixAt(lower, i, "jndi:") ||
				hasPrefixAt(lower, i, "json-patch+json") {
				return true
			}
		case 'l':
			if hasPrefixAt(lower, i, "ldap://") ||
				hasPrefixAt(lower, i, "ldaps://") ||
				hasPrefixAt(lower, i, "loginok.html") {
				return true
			}
		case 'm':
			if hasPrefixAt(lower, i, "metadata.google") ||
				hasPrefixAt(lower, i, "metadatauploader") ||
				hasPrefixAt(lower, i, "multipart/form-data") {
				return true
			}
		case 'n':
			if hasPrefixAt(lower, i, "net user") {
				return true
			}
		case 'o':
			if hasPrefixAt(lower, i, "objectclass=") ||
				hasPrefixAt(lower, i, "ognl") {
				return true
			}
		case 'p':
			if hasPrefixAt(lower, i, "php://") ||
				hasPrefixAt(lower, i, "ping.cgi") ||
				hasPrefixAt(lower, i, "priorityqueue") ||
				hasPrefixAt(lower, i, "processbuilder") {
				return true
			}
		case 'r':
			if hasPrefixAt(lower, i, "raw??") ||
				hasPrefixAt(lower, i, "reflect.method") ||
				hasPrefixAt(lower, i, "rememberme=") ||
				hasPrefixAt(lower, i, "rmi://") {
				return true
			}
		case 's':
			if hasPrefixAt(lower, i, "scriptengine") ||
				hasPrefixAt(lower, i, "serializ") ||
				hasPrefixAt(lower, i, "shift-jis") ||
				hasPrefixAt(lower, i, "signout.aspx") ||
				hasPrefixAt(lower, i, "solrsearch") ||
				hasPrefixAt(lower, i, "spinstall0.aspx") ||
				hasPrefixAt(lower, i, "swupdatefileuploader") ||
				hasPrefixAt(lower, i, "syscmd.cgi") ||
				hasPrefixAt(lower, i, "systeminfo") {
				return true
			}
		case 't':
			if hasPrefixAt(lower, i, "themeeditor") ||
				hasPrefixAt(lower, i, "toolshell") ||
				hasPrefixAt(lower, i, "toolpane.aspx") ||
				hasPrefixAt(lower, i, "transfer-encoding") {
				return true
			}
		case 'u':
			if hasPrefixAt(lower, i, "uname") ||
				hasPrefixAt(lower, i, "unlicensed.xhtml") {
				return true
			}
		case 'v':
			if hasPrefixAt(lower, i, "validate/code") ||
				hasPrefixAt(lower, i, "valuestack") {
				return true
			}
		case 'w':
			if hasPrefixAt(lower, i, "webinterface/function") ||
				hasPrefixAt(lower, i, "whoami") {
				return true
			}
		case 'x':
			if hasPrefixAt(lower, i, "x-middleware") {
				return true
			}
		case ')':
			if hasPrefixAt(lower, i, ")(|") || hasPrefixAt(lower, i, ")(uid=") {
				return true
			}
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
		return cveHeaderValue(req.Headers, "Cookie")
	default:
		return strings.Join(req.AllTargets, "\n")
	}
}

func cveHeaderValue(headers map[string]string, name string) string {
	value, _ := cveHeaderValueOK(headers, name)
	return value
}

func cveHeaderValueOK(headers map[string]string, name string) (string, bool) {
	if len(headers) == 0 {
		return "", false
	}
	if value, ok := headers[name]; ok {
		return value, true
	}
	if lower := cveLowerHeaderName(name); lower != name {
		if value, ok := headers[lower]; ok {
			return value, true
		}
	}
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

func cveLowerHeaderName(name string) string {
	switch name {
	case "Authorization":
		return "authorization"
	case "CGIINFO":
		return "cgiinfo"
	case "Content-Type":
		return "content-type"
	case "Cookie":
		return "cookie"
	case "Host":
		return "host"
	case "Origin":
		return "origin"
	case "Referer":
		return "referer"
	case "User-Agent":
		return "user-agent"
	}
	return strings.ToLower(name)
}

// multiDecode performs URL-decode then attempts base64-decode on the result.
func multiDecode(s string) string {
	if s == "" {
		return s
	}

	d2 := s
	if strings.ContainsAny(s, "%+") {
		d1, err := url.QueryUnescape(s)
		if err != nil {
			d1 = s
		}
		d2, err = url.QueryUnescape(d1)
		if err != nil {
			d2 = d1
		}
	}

	if looksLikeStdBase64(s) {
		if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) > 0 && isPrintable(b) {
			return d2 + "\x00" + string(b)
		}
	}
	return d2
}

func looksLikeStdBase64(s string) bool {
	if len(s) < 4 || len(s)%4 != 0 {
		return false
	}
	padding := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			if padding > 0 {
				return false
			}
		case c == '=':
			padding++
			if padding > 2 {
				return false
			}
		default:
			return false
		}
	}
	return true
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
