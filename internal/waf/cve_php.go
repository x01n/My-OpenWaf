package waf

import (
	"regexp"
	"strings"
)

// PHPCVEDetector detects PHP-specific CVE exploitation attempts.
type PHPCVEDetector struct {
	rules []phpCVERule
}

type phpCVERule struct {
	cveID       string
	severity    string
	description string
	patterns    []*regexp.Regexp
	target      string // "all", "url", "body", "header", "cookie"
}

// Compiled regex patterns (init-time, no runtime compilation).
var (
	// PHP object deserialization (CVE-2015-6835 and related)
	rePHPSerObj       = regexp.MustCompile(`(?i)O:\d+:"`)
	rePHPSerArray     = regexp.MustCompile(`(?i)a:\d+:\{`)
	rePHPUnserialize  = regexp.MustCompile(`(?i)unserialize\s*\(`)

	// PHP stream wrappers / file inclusion (CVE-2018-xxxx family)
	rePHPFilterStream = regexp.MustCompile(`(?i)php://filter/`)
	rePHPInputStream  = regexp.MustCompile(`(?i)php://input`)
	rePHPDataStream   = regexp.MustCompile(`(?i)data://text/plain;base64,`)
	rePHPExpect       = regexp.MustCompile(`(?i)expect://`)
	rePHPPhar         = regexp.MustCompile(`(?i)phar://`)

	// ThinkPHP RCE (CVE-2018-20062 and related)
	reThinkPHP1 = regexp.MustCompile(`(?i)s=index/think\\\\app/invokefunction`)
	reThinkPHP2 = regexp.MustCompile(`(?i)_method=__construct.*filter\[\]=system`)
	reThinkPHP3 = regexp.MustCompile(`(?i)c=Runtime&a=getContent`)
	reThinkPHP4 = regexp.MustCompile(`(?i)think\\\\app/invokefunction`)
	reThinkPHP5 = regexp.MustCompile(`(?i)filter\[\]\s*=\s*(system|exec|passthru|shell_exec)`)

	// Laravel RCE
	reLaravel1 = regexp.MustCompile(`(?i)_ignition/execute-solution`)
	reLaravel2 = regexp.MustCompile(`(?i)Illuminate\\\\Broadcasting\\\\PendingBroadcast`)
	reLaravel3 = regexp.MustCompile(`(?i)_ignition/health-check`)
	reLaravel4 = regexp.MustCompile(`(?i)Illuminate\\\\Foundation\\\\Testing`)

	// Webshell upload detection
	rePHPTag     = regexp.MustCompile(`(?i)<\?php`)
	rePHPEval    = regexp.MustCompile(`(?i)\beval\s*\(`)
	rePHPSystem  = regexp.MustCompile(`(?i)\bsystem\s*\(`)
	rePHPExec    = regexp.MustCompile(`(?i)\bexec\s*\(`)
	rePHPPassthru = regexp.MustCompile(`(?i)\bpassthru\s*\(`)
	rePHPShellExec = regexp.MustCompile(`(?i)\bshell_exec\s*\(`)
	rePHPExtUpload = regexp.MustCompile(`(?i)\.(php[345s7]?|phtml|pht|phps|phar)\b`)

	// Drupal Drupalgeddon2 (CVE-2018-7600)
	reDrupal1 = regexp.MustCompile(`(?i)#post_render.*#type\s*=\s*markup`)
	reDrupal2 = regexp.MustCompile(`(?i)#lazy_builder`)

	// PHPUnit RCE (CVE-2017-9841)
	rePHPUnit = regexp.MustCompile(`(?i)/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php`)
)

// NewPHPCVEDetector creates a PHP CVE detector with all built-in rules.
func NewPHPCVEDetector() *PHPCVEDetector {
	d := &PHPCVEDetector{}
	d.rules = []phpCVERule{
		{
			cveID: "CVE-2015-6835", severity: "high",
			description: "PHP object deserialization via serialized object pattern",
			patterns:    []*regexp.Regexp{rePHPSerObj, rePHPSerArray, rePHPUnserialize},
			target:      "all",
		},
		{
			cveID: "CVE-2018-14884", severity: "high",
			description: "PHP stream wrapper file inclusion (php://filter, php://input, data://, expect://, phar://)",
			patterns:    []*regexp.Regexp{rePHPFilterStream, rePHPInputStream, rePHPDataStream, rePHPExpect, rePHPPhar},
			target:      "all",
		},
		{
			cveID: "CVE-2018-20062", severity: "critical",
			description: "ThinkPHP remote code execution via invokefunction",
			patterns:    []*regexp.Regexp{reThinkPHP1, reThinkPHP2, reThinkPHP3, reThinkPHP4, reThinkPHP5},
			target:      "all",
		},
		{
			cveID: "CVE-2021-3129", severity: "critical",
			description: "Laravel Ignition RCE via _ignition/execute-solution",
			patterns:    []*regexp.Regexp{reLaravel1, reLaravel2, reLaravel3, reLaravel4},
			target:      "all",
		},
		{
			cveID: "CVE-2016-WEBSHELL", severity: "critical",
			description: "PHP webshell upload detected (eval/system/exec in uploaded PHP file)",
			patterns:    []*regexp.Regexp{rePHPTag, rePHPEval, rePHPSystem, rePHPExec, rePHPPassthru, rePHPShellExec},
			target:      "body",
		},
		{
			cveID: "CVE-2016-WEBSHELL-EXT", severity: "high",
			description: "Suspicious PHP extension in file upload",
			patterns:    []*regexp.Regexp{rePHPExtUpload},
			target:      "all",
		},
		{
			cveID: "CVE-2018-7600", severity: "critical",
			description: "Drupal Drupalgeddon2 RCE via render API",
			patterns:    []*regexp.Regexp{reDrupal1, reDrupal2},
			target:      "all",
		},
		{
			cveID: "CVE-2017-9841", severity: "high",
			description: "PHPUnit RCE via eval-stdin.php",
			patterns:    []*regexp.Regexp{rePHPUnit},
			target:      "url",
		},
	}
	return d
}

// Detect scans the request for PHP CVE exploitation attempts.
func (d *PHPCVEDetector) Detect(req *CVERequest) []CVEMatch {
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
						Category:    "php",
						Severity:    rule.severity,
						Description: rule.description,
						MatchedPart: part,
						Pattern:     pat.String(),
						Action:      "drop",
					})
					goto nextRule // one match per rule is enough
				}
			}
		}
	nextRule:
	}
	return matches
}

// resolveTargets returns the set of strings to scan based on target type.
func resolveTargets(req *CVERequest, target string) []string {
	switch target {
	case "url":
		return []string{req.Path, req.DecodedPath, req.RawQuery, req.DecodedQuery}
	case "body":
		if req.Body == "" {
			return nil
		}
		return []string{req.Body, req.DecodedBody}
	case "header":
		var out []string
		for _, v := range req.Headers {
			out = append(out, v)
		}
		return out
	case "cookie":
		c, ok := req.Headers["Cookie"]
		if !ok {
			return nil
		}
		return []string{c}
	default: // "all"
		return req.AllTargets
	}
}

// guessMatchedPart tries to determine which part of the request was matched.
func guessMatchedPart(req *CVERequest, matched string) string {
	if strings.Contains(req.Path, matched) || strings.Contains(req.DecodedPath, matched) ||
		strings.Contains(req.RawQuery, matched) || strings.Contains(req.DecodedQuery, matched) {
		return "url"
	}
	if strings.Contains(req.Body, matched) || strings.Contains(req.DecodedBody, matched) {
		return "body"
	}
	for _, v := range req.Headers {
		if strings.Contains(v, matched) {
			return "header"
		}
	}
	return "unknown"
}
