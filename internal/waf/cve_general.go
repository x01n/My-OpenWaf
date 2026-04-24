package waf

import (
	"regexp"
	"strings"
)

// GeneralCVEDetector detects technology-agnostic CVE exploitation patterns.
type GeneralCVEDetector struct {
	rules []generalCVERule
}

type generalCVERule struct {
	cveID       string
	severity    string
	description string
	patterns    []*regexp.Regexp
	target      string
	matchAll    bool // if true, ALL patterns must match (conjunction)
}

var (
	reSSRF_10          = regexp.MustCompile(`(?i)(?:^|[/=?&])https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	reSSRF_172         = regexp.MustCompile(`(?i)(?:^|[/=?&])https?://172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}`)
	reSSRF_192         = regexp.MustCompile(`(?i)(?:^|[/=?&])https?://192\.168\.\d{1,3}\.\d{1,3}`)
	reSSRF_127         = regexp.MustCompile(`(?i)(?:^|[/=?&])https?://127\.0\.0\.\d{1,3}`)
	reSSRF_local       = regexp.MustCompile(`(?i)(?:^|[/=?&])https?://localhost`)
	reSSRF_meta        = regexp.MustCompile(`(?i)169\.254\.169\.254`)
	reSSRF_gcloud      = regexp.MustCompile(`(?i)metadata\.google\.internal`)
	reSSRF_file        = regexp.MustCompile(`(?i)file://`)
	reSSRF_ipv6        = regexp.MustCompile(`(?i)(?:^|[/=?&])https?://\[?::1\]?[:/]`)
	reSSRF_0000        = regexp.MustCompile(`(?i)(?:^|[/=?&])https?://0\.0\.0\.0`)
	reXXE_doctype      = regexp.MustCompile(`(?i)<!DOCTYPE\s`)
	reXXE_entity       = regexp.MustCompile(`(?i)<!ENTITY\s`)
	reXXE_system       = regexp.MustCompile(`(?i)SYSTEM\s+["'](?:file|http|ftp|gopher)://`)
	reXXE_public       = regexp.MustCompile(`(?i)PUBLIC\s+["']-//`)
	rePathTrav_double  = regexp.MustCompile(`(?i)%252[eE]%252[eE]%252[fF]`)
	rePathTrav_utf8    = regexp.MustCompile(`(?i)\.\.%[cC]0%[aA][fF]`)
	rePathTrav_double2 = regexp.MustCompile(`(?i)\.\.\.\./`)
	rePathTrav_win     = regexp.MustCompile(`(?i)\.\.\\`)
	rePathTrav_win5c   = regexp.MustCompile(`(?i)\.\.%5[cC]`)
	rePathTrav_null    = regexp.MustCompile(`(?i)\.\./%00`)
	reCRLF_encoded     = regexp.MustCompile(`(?i)%0[dD]%0[aA]`)
	reCRLF_raw         = regexp.MustCompile(`\r\n`)
	reCRLF_header      = regexp.MustCompile(`(?i)%0[dD]%0[aA](Set-Cookie|Location|Content-Type):`)
	reSmuggle_clte     = regexp.MustCompile(`(?i)transfer-encoding\s*:\s*chunked`)
	reSmuggle_te       = regexp.MustCompile(`(?i)transfer-encoding\s*:\s*[\s,]*(chunked|identity)`)
	reShellShock       = regexp.MustCompile(`(?i)\(\)\s*\{[^}]*\}\s*;`)
	reHeartbleed       = regexp.MustCompile(`(?i)heartbleed`)

	// HTTP header injection
	reHeaderInject = regexp.MustCompile(`(?i)%0[dD]%0[aA]\s*(HTTP/|Content-|Location:|Set-Cookie)`)

	// SAP NetWeaver Visual Composer (CVE-2025-31324)
	reSAPMetadataUploader = regexp.MustCompile(`(?i)/developmentserver/metadatauploader`)
	reSAPIRJServlet       = regexp.MustCompile(`(?i)/irj/servlet`)

	// PHP-CGI argument injection (CVE-2024-4577)
	rePHPCGISoftHyphen = regexp.MustCompile(`(?i)[%\x00-\xff]ad.*-[dD]\s*(allow_url_include|auto_prepend_file)`)
	rePHPCGIArgInject  = regexp.MustCompile(`(?i)php://input.*allow_url_include|auto_prepend_file.*php://input`)
	rePHPCGISoftHyphen2 = regexp.MustCompile(`%[aA][dD]`)

	// PAN-OS GlobalProtect (CVE-2024-3400)
	rePANOSCookieTraversal = regexp.MustCompile(`(?i)SESSID=.*\.\.`)
	rePANOSGlobalProtect   = regexp.MustCompile(`(?i)/ssl-vpn/hipreport\.esp`)

	// Confluence RCE (CVE-2023-22527)
	reConfluenceOGNL = regexp.MustCompile(`(?i)/template/aui/text-inline\.vm`)

	// Citrix Bleed (CVE-2023-4966)
	reCitrixBleed = regexp.MustCompile(`(?i)/vpn/\.\./vpns/|/vpn/index\.html`)

	// Apache Struts path traversal (CVE-2024-53677)
	reStrutsUpload = regexp.MustCompile(`(?i)top\["[^"]*"\]\s*=`)

	// Ivanti Connect Secure (CVE-2024-21887, CVE-2025-0282)
	reIvantiCSAPI = regexp.MustCompile(`(?i)/api/v1/totp/user-backup-code/\.\.;/`)
	reIvantiCSWeb = regexp.MustCompile(`(?i)/dana-na/auth/url_default/welcome\.cgi`)
)

// NewGeneralCVEDetector creates a general CVE detector with built-in rules.
func NewGeneralCVEDetector() *GeneralCVEDetector {
	d := &GeneralCVEDetector{}
	d.rules = []generalCVERule{
		{
			cveID: "CVE-2019-SSRF", severity: "high",
			description: "SSRF attempt targeting internal network, cloud metadata, or local files",
			patterns: []*regexp.Regexp{
				reSSRF_10, reSSRF_172, reSSRF_192, reSSRF_127, reSSRF_local,
				reSSRF_meta, reSSRF_gcloud, reSSRF_file, reSSRF_ipv6, reSSRF_0000,
			},
			target: "all",
		},
		{
			cveID: "CVE-2018-XXE", severity: "high",
			description: "XML External Entity (XXE) injection via DOCTYPE/ENTITY declaration",
			patterns:    []*regexp.Regexp{reXXE_doctype, reXXE_entity, reXXE_system, reXXE_public},
			target:      "body",
		},
		{
			cveID: "CVE-2019-PATHTRA", severity: "medium",
			description: "Enhanced path traversal via double encoding, UTF-8, or Windows-style backslash",
			patterns:    []*regexp.Regexp{rePathTrav_double, rePathTrav_utf8, rePathTrav_double2, rePathTrav_win, rePathTrav_win5c, rePathTrav_null},
			target:      "url",
		},
		{
			cveID: "CVE-2019-CRLF", severity: "medium",
			description: "CRLF injection in URL parameters or header values",
			patterns:    []*regexp.Regexp{reCRLF_encoded, reCRLF_raw, reCRLF_header},
			target:      "all",
		},
		{
			cveID: "CVE-2023-SMUGGLE", severity: "high",
			description: "HTTP request smuggling via CL-TE or TE-CL mismatch",
			patterns:    []*regexp.Regexp{reSmuggle_clte},
			target:      "header",
		},
		{
			cveID: "CVE-2014-6271", severity: "critical",
			description: "ShellShock Bash function definition injection",
			patterns:    []*regexp.Regexp{reShellShock},
			target:      "all",
		},
		{
			cveID: "CVE-2019-HEADER-INJECT", severity: "medium",
			description: "HTTP header injection via CRLF in parameter values",
			patterns:    []*regexp.Regexp{reHeaderInject},
			target:      "all",
		},
		// 2024-2025 Critical CVEs
		{
			cveID: "CVE-2025-31324", severity: "critical",
			description: "SAP NetWeaver Visual Composer unauthenticated file upload RCE",
			patterns:    []*regexp.Regexp{reSAPMetadataUploader},
			target:      "url",
		},
		{
			cveID: "CVE-2024-4577", severity: "critical",
			description: "PHP-CGI argument injection via soft-hyphen (Best-Fit mapping bypass)",
			patterns:    []*regexp.Regexp{rePHPCGISoftHyphen, rePHPCGIArgInject},
			target:      "all",
		},
		{
			cveID: "CVE-2024-3400", severity: "critical",
			description: "PAN-OS GlobalProtect command injection via SESSID cookie traversal",
			patterns:    []*regexp.Regexp{rePANOSCookieTraversal, rePANOSGlobalProtect},
			target:      "all",
		},
		{
			cveID: "CVE-2023-22527", severity: "critical",
			description: "Confluence Server OGNL injection via template endpoint",
			patterns:    []*regexp.Regexp{reConfluenceOGNL},
			target:      "url",
		},
		{
			cveID: "CVE-2023-4966", severity: "critical",
			description: "Citrix Bleed information disclosure via path traversal",
			patterns:    []*regexp.Regexp{reCitrixBleed},
			target:      "url",
		},
		{
			cveID: "CVE-2024-53677", severity: "critical",
			description: "Apache Struts file upload path traversal RCE",
			patterns:    []*regexp.Regexp{reStrutsUpload},
			target:      "all",
		},
		{
			cveID: "CVE-2024-21887", severity: "critical",
			description: "Ivanti Connect Secure path traversal and command injection",
			patterns:    []*regexp.Regexp{reIvantiCSAPI, reIvantiCSWeb},
			target:      "url",
		},
	}
	return d
}

// Detect scans the request for general CVE exploitation attempts.
func (d *GeneralCVEDetector) Detect(req *CVERequest) []CVEMatch {
	var matches []CVEMatch

	// Special handling: HTTP request smuggling checks both CL and TE headers.
	if checkHTTPSmuggling(req) {
		matches = append(matches, CVEMatch{
			CVEID:       "CVE-2023-SMUGGLE",
			Category:    "general",
			Severity:    "high",
			Description: "HTTP request smuggling: Content-Length and Transfer-Encoding both present",
			MatchedPart: "header",
			Pattern:     "CL+TE simultaneous",
			Action:      "drop",
		})
	}

	for _, rule := range d.rules {
		if rule.cveID == "CVE-2023-SMUGGLE" {
			continue // handled above
		}
		if rule.matchAll {
			if matchAllPatterns(req, rule) {
				matches = append(matches, CVEMatch{
					CVEID:       rule.cveID,
					Category:    "general",
					Severity:    rule.severity,
					Description: rule.description,
					MatchedPart: rule.target,
					Pattern:     "conjunction match",
					Action:      "drop",
				})
			}
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
						Category:    "general",
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

// checkHTTPSmuggling detects when both Content-Length and Transfer-Encoding headers
// are present simultaneously, or TE contains malformed values.
func checkHTTPSmuggling(req *CVERequest) bool {
	hasCL := false
	hasTE := false
	for k, v := range req.Headers {
		kl := strings.ToLower(k)
		if kl == "content-length" {
			hasCL = true
		}
		if kl == "transfer-encoding" {
			hasTE = true
			// Check for obfuscated chunked value.
			vl := strings.ToLower(v)
			if strings.Contains(vl, " chunked") || strings.Contains(vl, "\tchunked") ||
				strings.Contains(vl, "chunked ") || strings.Contains(vl, ",chunked") {
				return true // obfuscated TE
			}
		}
	}
	return hasCL && hasTE
}

// matchAllPatterns returns true only if ALL patterns in the rule match.
func matchAllPatterns(req *CVERequest, rule generalCVERule) bool {
	targets := resolveTargets(req, rule.target)
	combined := strings.Join(targets, "\n")
	for _, pat := range rule.patterns {
		if !pat.MatchString(combined) {
			return false
		}
	}
	return true
}
