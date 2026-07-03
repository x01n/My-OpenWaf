package cve

import (
	"regexp"
	"strings"
)

func init() {
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-php-cgi-softyhphen",
		Name:     "PHP-CGI Soft-Hyphen Argument Injection",
		CVE:      "CVE-2024-4577",
		Severity: "critical",
		Category: "cve_php",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			combined := uri + body
			if rePHPCGI_SoftHyphenArg.MatchString(combined) &&
				(rePHPCGI_AutoPrepend.MatchString(combined) || rePHPCGI_AllowInclude.MatchString(combined)) {
				return &CVEMatch{
					CVEID:       "CVE-2024-4577",
					Category:    "cve_php",
					Severity:    "critical",
					Description: "PHP-CGI argument injection via soft-hyphen with auto_prepend/allow_url_include",
					MatchedPart: "all",
					Pattern:     "php-cgi-softhyphen",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-wordpress-file-read",
		Name:     "WordPress Arbitrary File Read",
		CVE:      "CVE-2024-2961",
		Severity: "high",
		Category: "cve_php",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reWPFileRead.MatchString(uri) {
				return &CVEMatch{
					CVEID:       "CVE-2024-2961",
					Category:    "cve_php",
					Severity:    "high",
					Description: "WordPress arbitrary file read via admin-ajax.php",
					MatchedPart: "url",
					Pattern:     "wp-file-read",
					Action:      "drop",
				}
			}
			return nil
		},
	})
}

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
	rePHPSerObj      = regexp.MustCompile(`(?i)O:\d+:"`)
	rePHPSerArray    = regexp.MustCompile(`(?i)a:\d+:\{`)
	rePHPUnserialize = regexp.MustCompile(`(?i)unserialize\s*\(`)

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
	rePHPTag       = regexp.MustCompile(`(?i)<\?php`)
	rePHPEval      = regexp.MustCompile(`(?i)\beval\s*\(`)
	rePHPSystem    = regexp.MustCompile(`(?i)\bsystem\s*\(`)
	rePHPExec      = regexp.MustCompile(`(?i)\bexec\s*\(`)
	rePHPPassthru  = regexp.MustCompile(`(?i)\bpassthru\s*\(`)
	rePHPShellExec = regexp.MustCompile(`(?i)\bshell_exec\s*\(`)
	rePHPExtUpload = regexp.MustCompile(`(?i)\.(php[345s7]?|phtml|pht|phps|phar)\b`)

	// Drupal Drupalgeddon2 (CVE-2018-7600)
	reDrupal1 = regexp.MustCompile(`(?i)#post_render.*#type\s*=\s*markup`)
	reDrupal2 = regexp.MustCompile(`(?i)#lazy_builder`)

	// PHPUnit RCE (CVE-2017-9841)
	rePHPUnit = regexp.MustCompile(`(?i)/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php`)

	// PHP-CGI argument injection via soft-hyphen (CVE-2024-4577)
	rePHPCGI_SoftHyphenArg = regexp.MustCompile(`(?i)%[aA][dD].*-[drnfem]`)
	rePHPCGI_AutoPrepend   = regexp.MustCompile(`(?i)auto_prepend_file\s*=\s*php://`)
	rePHPCGI_AllowInclude  = regexp.MustCompile(`(?i)allow_url_include\s*=\s*[1oOyY]`)

	// WordPress arbitrary file read (CVE-2024-2961)
	reWPFileRead = regexp.MustCompile(`(?i)/wp-admin/admin-ajax\.php.*action=.*file`)

	// Craft CMS RCE (CVE-2023-41892)
	reCraftCMS = regexp.MustCompile(`(?i)/actions/conditions/render.*configObject`)
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
		{
			cveID: "CVE-2024-4577", severity: "critical",
			description: "PHP-CGI argument injection via Windows soft-hyphen Best-Fit mapping",
			patterns:    []*regexp.Regexp{rePHPCGI_SoftHyphenArg, rePHPCGI_AutoPrepend, rePHPCGI_AllowInclude},
			target:      "all",
		},
		{
			cveID: "CVE-2023-41892", severity: "critical",
			description: "Craft CMS RCE via conditions/render endpoint",
			patterns:    []*regexp.Regexp{reCraftCMS},
			target:      "url",
		},
	}
	return d
}

// Detect scans the request for PHP CVE exploitation attempts.
func phpRequestContainsAny(req *CVERequest, rule phpCVERule, needles ...string) bool {
	return requestTargetContainsAny(req, rule.target, needles...)
}

func shouldScanPHPRule(req *CVERequest, rule phpCVERule) bool {
	switch rule.cveID {
	case "CVE-2015-6835":
		return phpRequestContainsAny(req, rule, "unserialize", "o:", "a:")
	case "CVE-2018-14884":
		return phpRequestContainsAny(req, rule, "php://", "data://", "expect://", "phar://")
	case "CVE-2018-20062":
		return phpRequestContainsAny(req, rule, "invokefunction", "thinkphp", "think\\app", "filter[]=", "filter%5b%5d=", "call_user_func", "_method=__construct", "c=runtime", "a=getcontent")
	case "CVE-2021-3129":
		return phpRequestContainsAny(req, rule, "_ignition/execute-solution", "_ignition/health-check", "laravel", "facade/ignition", "illuminate\\")
	case "CVE-2016-WEBSHELL":
		return phpRequestContainsAny(req, rule, "<?php", "eval(", "system(", "exec(", "passthru(", "shell_exec")
	case "CVE-2016-WEBSHELL-EXT":
		return phpRequestContainsAny(req, rule, ".php", ".phtml", ".phar", "filename=")
	case "CVE-2018-7600":
		return phpRequestContainsAny(req, rule, "drupal", "form_id=", "#post_render", "#markup", "#type")
	case "CVE-2017-9841":
		return phpRequestContainsAny(req, rule, "eval-stdin", "phpunit")
	case "CVE-2024-4577":
		return phpRequestContainsAny(req, rule, "%ad", "auto_prepend_file", "allow_url_include", "cgi.force_redirect")
	case "CVE-2023-41892":
		return phpRequestContainsAny(req, rule, "conditions/render", "actions/conditions", "configobject", "craftcms", "craft cms")
	default:
		return true
	}
}

func (d *PHPCVEDetector) Detect(req *CVERequest) []CVEMatch {
	var matches []CVEMatch
	for _, rule := range d.rules {
		if !shouldScanPHPRule(req, rule) {
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

func (d *PHPCVEDetector) DetectFirst(req *CVERequest) (CVEMatch, bool) {
	for _, rule := range d.rules {
		if !shouldScanPHPRule(req, rule) {
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
						Category:    "php",
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
	case "url_body":
		out := []string{req.Path, req.DecodedPath, req.RawQuery, req.DecodedQuery}
		if req.Body != "" {
			out = append(out, req.Body, req.DecodedBody)
		}
		return out
	case "header":
		var out []string
		for _, v := range req.Headers {
			out = append(out, v)
		}
		return out
	case "cookie":
		c, ok := cveHeaderValueOK(req.Headers, "Cookie")
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
