package waf

import (
	"encoding/base64"
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

// CVERequest holds the normalised request data for CVE scanning.
type CVERequest struct {
	Path        string
	RawQuery    string
	Headers     map[string]string
	Body        string
	ContentType string
	// Decoded variants for multi-pass detection.
	DecodedPath  string
	DecodedQuery string
	DecodedBody  string
	AllTargets   []string // aggregated targets (path+query+header values+body)
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

	var targets []string
	targets = append(targets, path, decodedPath)
	if rawQuery != "" {
		targets = append(targets, rawQuery, decodedQuery)
	}
	for _, v := range headers {
		targets = append(targets, v)
	}
	if bodyStr != "" {
		targets = append(targets, bodyStr, decodedBody)
	}

	return &CVERequest{
		Path:         path,
		RawQuery:     rawQuery,
		Headers:      headers,
		Body:         bodyStr,
		ContentType:  contentType,
		DecodedPath:  decodedPath,
		DecodedQuery: decodedQuery,
		DecodedBody:  decodedBody,
		AllTargets:   targets,
	}
}

// Detect runs all sub-detectors and custom rules, returning all matches.
func (d *CVEDetector) Detect(req *CVERequest) []CVEMatch {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		matches []CVEMatch
	)

	collect := func(m []CVEMatch) {
		if len(m) > 0 {
			mu.Lock()
			matches = append(matches, m...)
			mu.Unlock()
		}
	}

	wg.Add(4)
	go func() { defer wg.Done(); collect(d.phpDetector.Detect(req)) }()
	go func() { defer wg.Done(); collect(d.javaDetector.Detect(req)) }()
	go func() { defer wg.Done(); collect(d.nodeDetector.Detect(req)) }()
	go func() { defer wg.Done(); collect(d.generalDetector.Detect(req)) }()
	wg.Wait()

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

	return matches
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
