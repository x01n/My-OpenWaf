package waf

import (
	"regexp"
)

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
	}
	return d
}

// Detect scans the request for Node.js CVE exploitation attempts.
func (d *NodeCVEDetector) Detect(req *CVERequest) []CVEMatch {
	var matches []CVEMatch
	for _, rule := range d.rules {
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
