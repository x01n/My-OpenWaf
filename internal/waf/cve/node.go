package cve

import (
	"regexp"
	"strings"
)

func init() {
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-rsc-flight-rce",
		Name:     "React Server Components Flight Protocol RCE",
		CVE:      "CVE-2025-55182",
		Severity: "critical",
		Category: "cve_node",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			// Detect Flight protocol + prototype chain in body
			if reRSCFlightRef.MatchString(body) &&
				(reRSCProtoConstructor.MatchString(body) || reRSCConstructorChain.MatchString(body)) {
				return &CVEMatch{
					CVEID:       "CVE-2025-55182",
					Category:    "cve_node",
					Severity:    "critical",
					Description: "React2Shell: RSC Flight protocol with prototype chain attack",
					MatchedPart: "body",
					Pattern:     "rsc-flight-rce",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-nextjs-middleware-bypass",
		Name:     "Next.js Middleware Authorization Bypass",
		CVE:      "CVE-2025-29927",
		Severity: "critical",
		Category: "cve_node",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			for k, v := range headers {
				if strings.EqualFold(k, "x-middleware-subrequest") && strings.Contains(strings.ToLower(v), "middleware") {
					return &CVEMatch{
						CVEID:       "CVE-2025-29927",
						Category:    "cve_node",
						Severity:    "critical",
						Description: "Next.js middleware authorization bypass via x-middleware-subrequest header",
						MatchedPart: "header",
						Pattern:     "nextjs-middleware-bypass",
						Action:      "drop",
					}
				}
			}
			return nil
		},
	})
}

// NodeCVEDetector detects Node.js / React / Express specific CVE exploitation attempts.
type NodeCVEDetector struct {
	rules []nodeCVERule
}

type nodeCVERule struct {
	cveID       string
	severity    string
	description string
	patterns    []*regexp.Regexp
	target      string
}

// Compiled Node.js CVE patterns (init-time).
var (
	// Prototype Pollution (CVE-2019-10744, CVE-2020-28469, etc.)
	reProtoPollution1 = regexp.MustCompile(`(?i)"__proto__"\s*:`)
	reProtoPollution2 = regexp.MustCompile(`(?i)__proto__\[`)
	reProtoPollution3 = regexp.MustCompile(`(?i)__proto__=`)
	reProtoPollution4 = regexp.MustCompile(`(?i)constructor\s*\[\s*"?prototype"?\s*\]`)
	reProtoPollution5 = regexp.MustCompile(`(?i)constructor\.prototype`)

	// React SSR injection
	reReactSSR1 = regexp.MustCompile(`(?i)dangerouslySetInnerHTML`)
	reReactSSR2 = regexp.MustCompile(`(?i)__NEXT_DATA__`)
	reReactSSR3 = regexp.MustCompile("(?i)`[^`]*\\$\\{[^}]+\\}[^`]*`") // template literal injection

	// Node.js command injection
	reNodeCmd1 = regexp.MustCompile(`(?i)child_process`)
	reNodeCmd2 = regexp.MustCompile(`(?i)require\s*\(\s*['"]child_process['"]`)
	reNodeCmd3 = regexp.MustCompile(`(?i);\s*(ls|cat|id|whoami|uname|pwd|wget|curl)\b`)
	reNodeCmd4 = regexp.MustCompile(`(?i)\|\s*(cat|id|whoami|uname)\s+/`)
	reNodeCmd5 = regexp.MustCompile("(?i)`[^`]*(ls|cat|id|whoami|uname|pwd)[^`]*`") // backtick command substitution

	// Express/Koa path traversal (CVE-2017-14849, etc.)
	reNodePathTrav1 = regexp.MustCompile(`(?i)\.\.%2[fF]`)
	reNodePathTrav2 = regexp.MustCompile(`(?i)\.\.%5[cC]`)
	reNodePathTrav3 = regexp.MustCompile(`(?i)\.\.[;/]`)
	reNodePathTrav4 = regexp.MustCompile(`(?i)\.\.\\`)

	// EJS template injection (CVE-2022-29078)
	reEJS1 = regexp.MustCompile(`(?i)<%-?\s*(include|require|process|global|root|console)\b|<%=\s*(process|require|global|root|console)\b`)
	reEJS2 = regexp.MustCompile(`(?i)settings\s*\[\s*['"]view\s*options`)

	// vm2 sandbox escape (CVE-2023-32314)
	reVM2_1 = regexp.MustCompile(`(?i)this\.constructor\.constructor`)
	reVM2_2 = regexp.MustCompile(`(?i)Function\s*\(\s*['"]return\s+process['"]`)

	// Next.js SSRF (CVE-2024-34351)
	reNextSSRF1 = regexp.MustCompile(`(?i)x-middleware-subrequest`)

	// React2Shell / React Server Components RCE (CVE-2025-55182, CVSS 10.0)
	reRSCFlightRef        = regexp.MustCompile(`\$\d+:[A-Z]`)
	reRSCProtoConstructor = regexp.MustCompile(`(?i)__proto__\s*[\[.]\s*["']?constructor`)
	reRSCConstructorChain = regexp.MustCompile(`(?i)constructor\s*[\[.]\s*["']?constructor`)
	reRSCFunctionNew      = regexp.MustCompile(`(?i)Function\s*\(\s*['"][^'"]*(?:require|process|child_process|exec|spawn)`)
	reRSCBlobHandler      = regexp.MustCompile(`(?i)new\s+Blob\s*\(.*new\s+Response`)
	reRSCChildProcess     = regexp.MustCompile(`(?i)require\s*\(\s*['"]child_process['"].*(?:exec|spawn|fork)`)
	reRSCPromiseExec      = regexp.MustCompile(`(?i)\.then\s*\(.*(?:eval|Function|require)\s*\(`)
	reRSCDynamicImport    = regexp.MustCompile(`(?i)import\s*\(\s*['"](?:child_process|fs|net|http|os)['"]`)

	// Next.js middleware bypass (CVE-2025-29927)
	reNextMiddlewareBypass = regexp.MustCompile(`(?i)x-middleware-subrequest:\s*middleware`)

	// Next.js Server Actions path confusion (CVE-2025-55184)
	reNextServerAction = regexp.MustCompile(`(?i)/_next/data/.*\.json\?.*__nextDataReq`)
)

// NewNodeCVEDetector creates a Node.js CVE detector with built-in rules.
func NewNodeCVEDetector() *NodeCVEDetector {
	d := &NodeCVEDetector{}
	d.rules = []nodeCVERule{
		{
			cveID: "CVE-2019-10744", severity: "critical",
			description: "Prototype Pollution via __proto__ or constructor.prototype manipulation",
			patterns:    []*regexp.Regexp{reProtoPollution1, reProtoPollution2, reProtoPollution3, reProtoPollution4, reProtoPollution5},
			target:      "all",
		},
		{
			cveID: "CVE-2020-REACT-SSR", severity: "high",
			description: "React SSR injection via dangerouslySetInnerHTML or __NEXT_DATA__ manipulation",
			patterns:    []*regexp.Regexp{reReactSSR1, reReactSSR2, reReactSSR3},
			target:      "all",
		},
		{
			cveID: "CVE-2019-NODE-CMD", severity: "critical",
			description: "Node.js command injection via child_process or shell metacharacters",
			patterns:    []*regexp.Regexp{reNodeCmd1, reNodeCmd2, reNodeCmd3, reNodeCmd4, reNodeCmd5},
			target:      "all",
		},
		{
			cveID: "CVE-2017-14849", severity: "high",
			description: "Express/Koa path traversal via encoded dot-dot-slash",
			patterns:    []*regexp.Regexp{reNodePathTrav1, reNodePathTrav2, reNodePathTrav3, reNodePathTrav4},
			target:      "url",
		},
		{
			cveID: "CVE-2022-29078", severity: "high",
			description: "EJS server-side template injection",
			patterns:    []*regexp.Regexp{reEJS1, reEJS2},
			target:      "all",
		},
		{
			cveID: "CVE-2023-32314", severity: "critical",
			description: "vm2 sandbox escape via constructor chain",
			patterns:    []*regexp.Regexp{reVM2_1, reVM2_2},
			target:      "all",
		},
		{
			cveID: "CVE-2024-34351", severity: "high",
			description: "Next.js SSRF via x-middleware-subrequest header",
			patterns:    []*regexp.Regexp{reNextSSRF1},
			target:      "header",
		},
		{
			cveID: "CVE-2025-55182", severity: "critical",
			description: "React2Shell: RSC Flight protocol prototype chain traversal to Function constructor RCE",
			patterns: []*regexp.Regexp{
				reRSCProtoConstructor, reRSCConstructorChain, reRSCFunctionNew,
				reRSCBlobHandler, reRSCChildProcess, reRSCPromiseExec, reRSCDynamicImport,
			},
			target: "body",
		},
		{
			cveID: "CVE-2025-55182", severity: "critical",
			description: "React2Shell: Flight wire format reference with prototype pollution indicators",
			patterns:    []*regexp.Regexp{reRSCFlightRef},
			target:      "body",
		},
		{
			cveID: "CVE-2025-29927", severity: "critical",
			description: "Next.js middleware authorization bypass via x-middleware-subrequest",
			patterns:    []*regexp.Regexp{reNextMiddlewareBypass},
			target:      "header",
		},
		{
			cveID: "CVE-2025-55184", severity: "high",
			description: "Next.js Server Actions path confusion",
			patterns:    []*regexp.Regexp{reNextServerAction},
			target:      "url",
		},
	}
	return d
}

// Detect scans the request for Node.js CVE exploitation attempts.
func nodeRequestContainsAny(req *CVERequest, rule nodeCVERule, needles ...string) bool {
	return requestTargetContainsAny(req, rule.target, needles...)
}

func shouldScanNodeRule(req *CVERequest, rule nodeCVERule) bool {
	switch rule.cveID {
	case "CVE-2019-10744":
		return nodeRequestContainsAny(req, rule, "__proto__", "constructor.prototype", "prototype[")
	case "CVE-2020-REACT-SSR":
		return nodeRequestContainsAny(req, rule, "dangerouslysetinnerhtml", "__next_data__", "react")
	case "CVE-2019-NODE-CMD":
		return nodeRequestContainsAny(req, rule, "child_process", "exec(", "spawn(", "process.env", "require(", "whoami", "uname", "wget", "curl", "|", "`")
	case "CVE-2017-14849":
		return nodeRequestContainsAny(req, rule, "../", "%2e", "%5c", "..\\")
	case "CVE-2022-29078":
		return nodeRequestContainsAny(req, rule, "ejs", "<%", "template")
	case "CVE-2023-32314":
		return nodeRequestContainsAny(req, rule, "vm2", "constructor", "globalthis")
	case "CVE-2024-34351", "CVE-2025-29927":
		return nodeRequestContainsAny(req, rule, "x-middleware", "middleware-subrequest")
	case "CVE-2025-55182":
		return nodeRequestContainsAny(req, rule, "react.server", "rsc", "$@", "$1:", "__proto__", "child_process", "constructor", "function(", "new blob", "new response", "dynamic import")
	case "CVE-2025-55184":
		return nodeRequestContainsAny(req, rule, "server-action", "server action", "next-action", "/_next/data/", "__nextdatareq")
	default:
		return true
	}
}

func (d *NodeCVEDetector) Detect(req *CVERequest) []CVEMatch {
	var matches []CVEMatch
	for _, rule := range d.rules {
		if !shouldScanNodeRule(req, rule) {
			continue
		}
		targets := resolveTargets(req, rule.target)
		for _, t := range targets {
			for _, pat := range rule.patterns {
				if pat.MatchString(t) {
					part := rule.target
					if part == "all" {
						part = guessMatchedPart(req, t)
					}
					matches = append(matches, CVEMatch{
						CVEID:       rule.cveID,
						Category:    "node",
						Severity:    rule.severity,
						Description: rule.description,
						MatchedPart: part,
						Pattern:     pat.String(),
						Action:      "drop",
					})
					goto nextRule
				}
			}
		}
	nextRule:
	}
	return matches
}

func (d *NodeCVEDetector) DetectFirst(req *CVERequest) (CVEMatch, bool) {
	for _, rule := range d.rules {
		if !shouldScanNodeRule(req, rule) {
			continue
		}
		targets := resolveTargets(req, rule.target)
		for _, t := range targets {
			for _, pat := range rule.patterns {
				if pat.MatchString(t) {
					part := rule.target
					if part == "all" {
						part = guessMatchedPart(req, t)
					}
					return CVEMatch{
						CVEID:       rule.cveID,
						Category:    "node",
						Severity:    rule.severity,
						Description: rule.description,
						MatchedPart: part,
						Pattern:     pat.String(),
						Action:      "drop",
					}, true
				}
			}
		}
	}
	return CVEMatch{}, false
}
