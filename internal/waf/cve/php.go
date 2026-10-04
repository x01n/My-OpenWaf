package cve

import (
	"regexp"
	"strings"

	"My-OpenWaf/internal/pkg/snippet"
)

func init() {
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-php-cgi-softyhphen",
		Name:     "PHP-CGI 软连字符参数注入",
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
					Description: "PHP-CGI 通过软连字符以及 auto_prepend/allow_url_include 进行参数注入",
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
		Name:     "WordPress 任意文件读取",
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
					Description: "通过 admin-ajax.php 进行 WordPress 任意文件读取",
					MatchedPart: "url",
					Pattern:     "wp-file-read",
					Action:      "drop",
				}
			}
			return nil
		},
	})
}

// PHPCVEDetector 检测 PHP 技术栈特有的 CVE 利用尝试。
type PHPCVEDetector struct {
	rules []phpCVERule
}

type phpCVERule struct {
	cveID       string
	severity    string
	description string
	patterns    []*regexp.Regexp
	target      string // 取值："all"、"url"、"body"、"header"、"cookie"
}

// 正则表达式在 init 阶段编译，运行时不再编译。
var (
	// PHP 对象反序列化（CVE-2015-6835 及相关）
	rePHPSerObj      = regexp.MustCompile(`(?i)O:\d+:"`)
	rePHPSerArray    = regexp.MustCompile(`(?i)a:\d+:\{`)
	rePHPUnserialize = regexp.MustCompile(`(?i)unserialize\s*\(`)

	// PHP 流包装器 / 文件包含（CVE-2018-xxxx 系列）
	rePHPFilterStream = regexp.MustCompile(`(?i)php://filter/`)
	rePHPInputStream  = regexp.MustCompile(`(?i)php://input`)
	rePHPDataStream   = regexp.MustCompile(`(?i)data://text/plain;base64,`)
	rePHPExpect       = regexp.MustCompile(`(?i)expect://`)
	rePHPPhar         = regexp.MustCompile(`(?i)phar://`)

	// ThinkPHP RCE（CVE-2018-20062 及相关）
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

	// Webshell 上传检测
	rePHPTag       = regexp.MustCompile(`(?i)<\?php`)
	rePHPEval      = regexp.MustCompile(`(?i)\beval\s*\(`)
	rePHPSystem    = regexp.MustCompile(`(?i)\bsystem\s*\(`)
	rePHPExec      = regexp.MustCompile(`(?i)\bexec\s*\(`)
	rePHPPassthru  = regexp.MustCompile(`(?i)\bpassthru\s*\(`)
	rePHPShellExec = regexp.MustCompile(`(?i)\bshell_exec\s*\(`)
	rePHPExtUpload = regexp.MustCompile(`(?i)\.(php[345s7]?|phtml|pht|phps|phar)\b`)

	// Drupal Drupalgeddon2（CVE-2018-7600）
	reDrupal1 = regexp.MustCompile(`(?i)#post_render.*#type\s*=\s*markup`)
	reDrupal2 = regexp.MustCompile(`(?i)#lazy_builder`)

	// PHPUnit RCE（CVE-2017-9841）
	rePHPUnit = regexp.MustCompile(`(?i)/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php`)

	// 通过软连字符的 PHP-CGI 参数注入（CVE-2024-4577）
	rePHPCGI_SoftHyphenArg = regexp.MustCompile(`(?i)%[aA][dD].*-[drnfem]`)
	rePHPCGI_AutoPrepend   = regexp.MustCompile(`(?i)auto_prepend_file\s*=\s*php://`)
	rePHPCGI_AllowInclude  = regexp.MustCompile(`(?i)allow_url_include\s*=\s*[1oOyY]`)

	// WordPress 任意文件读取（CVE-2024-2961）
	reWPFileRead = regexp.MustCompile(`(?i)/wp-admin/admin-ajax\.php.*action=.*file`)

	// Craft CMS RCE（CVE-2023-41892）
	reCraftCMS = regexp.MustCompile(`(?i)/actions/conditions/render.*configObject`)
)

// NewPHPCVEDetector 创建带全部内置规则的 PHP CVE 检测器。
func NewPHPCVEDetector() *PHPCVEDetector {
	d := &PHPCVEDetector{}
	d.rules = []phpCVERule{
		{
			cveID: "CVE-2015-6835", severity: "high",
			description: "通过序列化对象模式进行 PHP 对象反序列化",
			patterns:    []*regexp.Regexp{rePHPSerObj, rePHPSerArray, rePHPUnserialize},
			target:      "all",
		},
		{
			cveID: "CVE-2018-14884", severity: "high",
			description: "PHP 流包装器文件包含（php://filter、php://input、data://、expect://、phar://）",
			patterns:    []*regexp.Regexp{rePHPFilterStream, rePHPInputStream, rePHPDataStream, rePHPExpect, rePHPPhar},
			target:      "all",
		},
		{
			cveID: "CVE-2018-20062", severity: "critical",
			description: "通过 invokefunction 进行 ThinkPHP 远程代码执行",
			patterns:    []*regexp.Regexp{reThinkPHP1, reThinkPHP2, reThinkPHP3, reThinkPHP4, reThinkPHP5},
			target:      "all",
		},
		{
			cveID: "CVE-2021-3129", severity: "critical",
			description: "通过 _ignition/execute-solution 进行 Laravel Ignition RCE",
			patterns:    []*regexp.Regexp{reLaravel1, reLaravel2, reLaravel3, reLaravel4},
			target:      "all",
		},
		{
			cveID: "CVE-2016-WEBSHELL", severity: "critical",
			description: "检测到 PHP WebShell 上传（上传的 PHP 文件中包含 eval/system/exec）",
			patterns:    []*regexp.Regexp{rePHPTag, rePHPEval, rePHPSystem, rePHPExec, rePHPPassthru, rePHPShellExec},
			target:      "body",
		},
		{
			cveID: "CVE-2016-WEBSHELL-EXT", severity: "high",
			description: "文件上传中的可疑 PHP 扩展名",
			patterns:    []*regexp.Regexp{rePHPExtUpload},
			target:      "all",
		},
		{
			cveID: "CVE-2018-7600", severity: "critical",
			description: "通过 render API 进行 Drupal Drupalgeddon2 RCE",
			patterns:    []*regexp.Regexp{reDrupal1, reDrupal2},
			target:      "all",
		},
		{
			cveID: "CVE-2017-9841", severity: "high",
			description: "通过 eval-stdin.php 进行 PHPUnit RCE",
			patterns:    []*regexp.Regexp{rePHPUnit},
			target:      "url",
		},
		{
			cveID: "CVE-2024-4577", severity: "critical",
			description: "通过 Windows 软连字符 Best-Fit 映射进行 PHP-CGI 参数注入",
			patterns:    []*regexp.Regexp{rePHPCGI_SoftHyphenArg, rePHPCGI_AutoPrepend, rePHPCGI_AllowInclude},
			target:      "all",
		},
		{
			cveID: "CVE-2023-41892", severity: "critical",
			description: "通过 conditions/render 端点进行 Craft CMS RCE",
			patterns:    []*regexp.Regexp{reCraftCMS},
			target:      "url",
		},
	}
	return d
}

func shouldScanPHPRule(req *CVERequest, rule phpCVERule, hits *subDetectorHits) bool {
	switch rule.cveID {
	case "CVE-2016-WEBSHELL-EXT":
		return shouldScanPHPExtUpload(req) && subDetectorACGate(rule.cveID, rule.target, hits)
	case "CVE-2015-6835", "CVE-2018-14884", "CVE-2018-20062", "CVE-2021-3129",
		"CVE-2016-WEBSHELL", "CVE-2018-7600",
		"CVE-2017-9841", "CVE-2024-4577", "CVE-2023-41892":
		return subDetectorACGate(rule.cveID, rule.target, hits)
	default:
		return true
	}
}

func shouldScanPHPExtUpload(req *CVERequest) bool {
	if strings.Contains(lowerCVERawTarget(req.ContentType), "multipart/form-data") {
		return true
	}
	return requestTargetContainsAny(req, "all", "filename=", "content-disposition")
}

func (d *PHPCVEDetector) Detect(req *CVERequest, hits *subDetectorHits) []CVEMatch {
	var matches []CVEMatch
	for _, rule := range d.rules {
		if !shouldScanPHPRule(req, rule, hits) {
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
						Snippet:     snippet.Extract([]*regexp.Regexp{pat}, t),
					})
					goto nextRule // 每条规则命中一次即可
				}
			}
		}
	nextRule:
	}
	return matches
}

func (d *PHPCVEDetector) DetectFirst(req *CVERequest, hits *subDetectorHits) (CVEMatch, bool) {
	for _, rule := range d.rules {
		if !shouldScanPHPRule(req, rule, hits) {
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
						Snippet:     snippet.Extract([]*regexp.Regexp{pat}, t),
					}, true
				}
			}
		}
	}
	return CVEMatch{}, false
}

// resolveTargets 按 target 类型返回待扫描字符串集合。
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
	default: // "all"（全目标视图）
		return req.AllTargets
	}
}

// guessMatchedPart 推断命中落在请求的哪个部分。
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
