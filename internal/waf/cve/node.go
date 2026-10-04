package cve

import (
	"regexp"
	"strings"

	"My-OpenWaf/internal/pkg/snippet"
)

func init() {
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-rsc-flight-rce",
		Name:     "React Server Components Flight 协议 RCE",
		CVE:      "CVE-2025-55182",
		Severity: "critical",
		Category: "cve_node",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			// 在 body 中检测 Flight 协议与原型链组合
			if reRSCFlightRef.MatchString(body) &&
				(reRSCProtoConstructor.MatchString(body) || reRSCConstructorChain.MatchString(body)) {
				return &CVEMatch{
					CVEID:       "CVE-2025-55182",
					Category:    "cve_node",
					Severity:    "critical",
					Description: "React2Shell：RSC Flight 协议原型链攻击",
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
		Name:     "Next.js 中间件授权绕过",
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
						Description: "Next.js 通过 x-middleware-subrequest 请求头的中间件授权绕过",
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

// NodeCVEDetector 检测 Node.js / React / Express 技术栈特有的 CVE 利用尝试。
type NodeCVEDetector struct {
	rules []nodeCVERule
}

type nodeCVERule struct {
	cveID       string
	severity    string
	description string
	patterns    []*regexp.Regexp
	// gates 与 patterns 一一对应:patterns[i] 命中的必要条件 DNF 门。
	// 门为必要条件(正则命中 ⇒ 门必真),因此门前置不改变判定,只省正则。
	target string
	gates  []nodePatternGate
}

type nodePatternGate struct {
	musts []string
	alts  []string
}

// Node.js CVE 正则，在 init 阶段编译。
var (
	// 原型污染（CVE-2019-10744、CVE-2020-28469 等）
	reProtoPollution1 = regexp.MustCompile(`(?i)"__proto__"\s*:`)
	reProtoPollution2 = regexp.MustCompile(`(?i)__proto__\[`)
	reProtoPollution3 = regexp.MustCompile(`(?i)__proto__=`)
	reProtoPollution4 = regexp.MustCompile(`(?i)constructor\s*\[\s*"?prototype"?\s*\]`)
	reProtoPollution5 = regexp.MustCompile(`(?i)constructor\.prototype`)

	// React SSR 注入
	reReactSSR1 = regexp.MustCompile(`(?i)dangerouslySetInnerHTML`)
	reReactSSR2 = regexp.MustCompile(`(?i)__NEXT_DATA__`)
	reReactSSR3 = regexp.MustCompile("(?i)`[^`]*\\$\\{[^}]+\\}[^`]*`") // 模板字面量注入

	// Node.js 命令注入
	reNodeCmd1 = regexp.MustCompile(`(?i)child_process`)
	reNodeCmd2 = regexp.MustCompile(`(?i)require\s*\(\s*['"]child_process['"]`)
	// 命令词后必须跟空白、shell 分隔符或串尾。仅用 \b 不够：URL 参数形态
	// ";cat=wac-v0"（Google Analytics 批量上报）中 '=' 同样构成词边界，会被误命中。
	// 边界口径与 owasp:cmd:001 / owasp:cmd:008 保持一致。
	// Go RE2 不支持 lookaround，故用字符类加串尾锚点表达。
	reNodeCmd3 = regexp.MustCompile("(?i);\\s*(ls|cat|id|whoami|uname|pwd|wget|curl)(?:[\\s;|&`]|$)")
	reNodeCmd4 = regexp.MustCompile(`(?i)\|\s*(cat|id|whoami|uname)\s+/`)
	// backtick command substitution：命令词两侧要求词边界，否则混淆串里偶然出现的
	// 两字母子串（"InSlSsypULSAUx" 含 ls、"Cwtid0ulK3" 含 id）会在零边界下命中。
	// 词边界不削弱真实形态：`ls`、`whoami`、`cat /etc/passwd`、`id` 均仍命中。
	reNodeCmd5 = regexp.MustCompile("(?i)`[^`]*\\b(ls|cat|id|whoami|uname|pwd)\\b[^`]*`")

	// Express/Koa 路径遍历（CVE-2017-14849 等）
	reNodePathTrav1 = regexp.MustCompile(`(?i)\.\.%2[fF]`)
	reNodePathTrav2 = regexp.MustCompile(`(?i)\.\.%5[cC]`)
	reNodePathTrav3 = regexp.MustCompile(`(?i)\.\.[;/]`)
	reNodePathTrav4 = regexp.MustCompile(`(?i)\.\.\\`)

	// EJS 模板注入（CVE-2022-29078）
	reEJS1 = regexp.MustCompile(`(?i)<%-?\s*(include|require|process|global|root|console)\b|<%=\s*(process|require|global|root|console)\b`)
	reEJS2 = regexp.MustCompile(`(?i)settings\s*\[\s*['"]view\s*options`)

	// vm2 沙箱逃逸（CVE-2023-32314）
	reVM2_1 = regexp.MustCompile(`(?i)this\.constructor\.constructor`)
	reVM2_2 = regexp.MustCompile(`(?i)Function\s*\(\s*['"]return\s+process['"]`)

	// Next.js SSRF（CVE-2024-34351）
	reNextSSRF1 = regexp.MustCompile(`(?i)x-middleware-subrequest`)

	// React2Shell / React Server Components RCE（CVE-2025-55182，CVSS 10.0）
	reRSCFlightRef        = regexp.MustCompile(`\$\d+:[A-Z]`)
	reRSCProtoConstructor = regexp.MustCompile(`(?i)__proto__\s*[\[.]\s*["']?constructor`)
	reRSCConstructorChain = regexp.MustCompile(`(?i)constructor\s*[\[.]\s*["']?constructor`)
	reRSCFunctionNew      = regexp.MustCompile(`(?i)Function\s*\(\s*['"][^'"]*(?:require|process|child_process|exec|spawn)`)
	reRSCBlobHandler      = regexp.MustCompile(`(?i)new\s+Blob\s*\(.*new\s+Response`)
	reRSCChildProcess     = regexp.MustCompile(`(?i)require\s*\(\s*['"]child_process['"].*(?:exec|spawn|fork)`)
	reRSCPromiseExec      = regexp.MustCompile(`(?i)\.then\s*\(.*(?:eval|Function|require)\s*\(`)
	reRSCDynamicImport    = regexp.MustCompile(`(?i)import\s*\(\s*['"](?:child_process|fs|net|http|os)['"]`)

	// Next.js 中间件绕过（CVE-2025-29927）
	reNextMiddlewareBypass = regexp.MustCompile(`(?i)x-middleware-subrequest:\s*middleware`)

	// Next.js Server Actions 路径混淆（CVE-2025-55184）
	reNextServerAction = regexp.MustCompile(`(?i)/_next/data/.*\.json\?.*__nextDataReq`)
)

var nodePatternGates = [][]nodePatternGate{
	// 对应 [0] CVE-2019-10744（5 条正则）
	{
		{musts: []string{`"__proto__"`, ":"}},
		{musts: []string{"__proto__["}},
		{musts: []string{"__proto__="}},
		{musts: []string{"constructor", "[", "prototype", "]"}},
		{musts: []string{"constructor.prototype"}},
	},
	// 对应 [1] CVE-2020-REACT-SSR（3 条正则）
	{
		{musts: []string{"dangerouslysetinnerhtml"}},
		{musts: []string{"__next_data__"}},
		// "`...`" 间要求 ${...}:`、'$'、'{' 任一形态均以 "${" 为字面窗口,
		// 反引号成对也是必须字面量。
		{musts: []string{"${", "`"}},
	},
	// 对应 [2] CVE-2019-NODE-CMD（5 条正则）
	{
		{musts: []string{"child_process"}},
		{musts: []string{"require", "(", "child_process"}},
		{musts: []string{";"}, alts: []string{"ls", "cat", "id", "whoami", "uname", "pwd", "wget", "curl"}},
		{musts: []string{"|", "/"}, alts: []string{"cat", "id", "whoami", "uname"}},
		{musts: []string{"`"}, alts: []string{"ls", "cat", "id", "whoami", "uname", "pwd"}},
	},
	// 对应 [3] CVE-2017-14849（4 条正则）
	{
		{musts: []string{"..%2f"}},
		{musts: []string{"..%5c"}},
		{musts: []string{".."}, alts: []string{";", "/"}},
		{musts: []string{`..\`}},
	},
	// 对应 [4] CVE-2022-29078（2 条正则）
	{
		{musts: []string{"<%"}, alts: []string{"include", "require", "process", "global", "root", "console"}},
		// \s* 允许 "settings" 与 "["、"[" 与 "view" 间存在空白,拆独立字面。
		{musts: []string{"settings", "[", "view", "options"}},
	},
	// 对应 [5] CVE-2023-32314（2 条正则）
	{
		{musts: []string{"this.constructor.constructor"}},
		// \s* 允许 "function" 与 "(" 间存在空白,故拆为两个独立必须字面量。
		{musts: []string{"function", "(", "return", "process"}},
	},
	// 对应 [6] CVE-2024-34351（1 条正则）
	{
		{musts: []string{"x-middleware-subrequest"}},
	},
	{
		{musts: []string{"__proto__", "constructor"}, alts: []string{"[", "."}},
		{musts: []string{"constructor"}, alts: []string{"[", "."}},
		{musts: []string{"function", "("}, alts: []string{"require", "process", "child_process", "exec", "spawn"}},
		{musts: []string{"new", "blob", "new", "response"}},
		{musts: []string{"require", "(", "child_process"}, alts: []string{"exec", "spawn", "fork"}},
		{musts: []string{"then", "("}, alts: []string{"eval", "function", "require"}},
		{musts: []string{"import", "("}, alts: []string{"child_process", "fs", "net", "http", "os"}},
	},
	{
		{musts: []string{"$", ":"}},
	},
	{
		{musts: []string{"x-middleware-subrequest", ":", "middleware"}},
	},
	{
		{musts: []string{"/_next/data/", ".json?", "__nextdatareq"}},
	},
}

func NewNodeCVEDetector() *NodeCVEDetector {
	d := &NodeCVEDetector{}
	d.rules = []nodeCVERule{
		{
			cveID: "CVE-2019-10744", severity: "critical",
			description: "通过 __proto__ 或 constructor.prototype 操作进行原型污染",
			patterns:    []*regexp.Regexp{reProtoPollution1, reProtoPollution2, reProtoPollution3, reProtoPollution4, reProtoPollution5},
			target:      "all",
			gates:       nodePatternGates[0],
		},
		{
			cveID: "CVE-2020-REACT-SSR", severity: "high",
			description: "通过 dangerouslySetInnerHTML 或 __NEXT_DATA__ 操作进行 React SSR 注入",
			patterns:    []*regexp.Regexp{reReactSSR1, reReactSSR2, reReactSSR3},
			target:      "all",
			gates:       nodePatternGates[1],
		},
		{
			cveID: "CVE-2019-NODE-CMD", severity: "critical",
			description: "通过 child_process 或 Shell 元字符进行 Node.js 命令注入",
			patterns:    []*regexp.Regexp{reNodeCmd1, reNodeCmd2, reNodeCmd3, reNodeCmd4, reNodeCmd5},
			target:      "all",
			gates:       nodePatternGates[2],
		},
		{
			cveID: "CVE-2017-14849", severity: "high",
			description: "通过编码后的点点斜杠进行 Express/Koa 路径遍历",
			patterns:    []*regexp.Regexp{reNodePathTrav1, reNodePathTrav2, reNodePathTrav3, reNodePathTrav4},
			target:      "url",
			gates:       nodePatternGates[3],
		},
		{
			cveID: "CVE-2022-29078", severity: "high",
			description: "EJS 服务端模板注入",
			patterns:    []*regexp.Regexp{reEJS1, reEJS2},
			target:      "all",
			gates:       nodePatternGates[4],
		},
		{
			cveID: "CVE-2023-32314", severity: "critical",
			description: "通过构造器链进行 vm2 沙箱逃逸",
			patterns:    []*regexp.Regexp{reVM2_1, reVM2_2},
			target:      "all",
			gates:       nodePatternGates[5],
		},
		{
			cveID: "CVE-2024-34351", severity: "high",
			description: "通过 x-middleware-subrequest 请求头进行 Next.js SSRF",
			patterns:    []*regexp.Regexp{reNextSSRF1},
			target:      "header",
			gates:       nodePatternGates[6],
		},
		{
			cveID: "CVE-2025-55182", severity: "critical",
			description: "React2Shell：RSC Flight 协议引用通过原型链遍历至 Function 构造函数 RCE",
			patterns: []*regexp.Regexp{
				reRSCProtoConstructor, reRSCConstructorChain, reRSCFunctionNew,
				reRSCBlobHandler, reRSCChildProcess, reRSCPromiseExec, reRSCDynamicImport,
			},
			target: "body",
			gates:  nodePatternGates[7],
		},
		{
			cveID: "CVE-2025-55182", severity: "critical",
			description: "React2Shell：Flight 协议线格式引用包含原型污染指示",
			patterns:    []*regexp.Regexp{reRSCFlightRef},
			target:      "body",
			gates:       nodePatternGates[8],
		},
		{
			cveID: "CVE-2025-29927", severity: "critical",
			description: "通过 x-middleware-subrequest 进行 Next.js 中间件授权绕过",
			patterns:    []*regexp.Regexp{reNextMiddlewareBypass},
			target:      "header",
			gates:       nodePatternGates[9],
		},
		{
			cveID: "CVE-2025-55184", severity: "high",
			description: "Next.js Server Actions 路径混淆",
			patterns:    []*regexp.Regexp{reNextServerAction},
			target:      "url",
			gates:       nodePatternGates[10],
		},
	}
	return d
}

func shouldScanNodeRule(req *CVERequest, rule nodeCVERule, hits *subDetectorHits) bool {
	switch rule.cveID {
	case "CVE-2019-10744", "CVE-2020-REACT-SSR", "CVE-2019-NODE-CMD",
		"CVE-2017-14849", "CVE-2022-29078", "CVE-2023-32314",
		"CVE-2024-34351", "CVE-2025-29927", "CVE-2025-55182", "CVE-2025-55184":
		if !subDetectorACGate(rule.cveID, rule.target, hits) {
			return false
		}
		return nodeRuleGate(req, rule)
	default:
		return true
	}
}

func nodeRuleGate(req *CVERequest, rule nodeCVERule) bool {
	if len(rule.gates) == 0 {
		return true // 无必要数据时不拦截(与旧行为一致)
	}
	targets := resolveTargets(req, rule.target)
	for _, g := range rule.gates {
		possible := false
		for _, t := range targets {
			lt := lowerCVERawTarget(t)
			if nodeGateSatisfied(lt, g) {
				possible = true
				break
			}
		}
		if possible {
			return true
		}
	}
	return false
}

func nodeGateSatisfied(lower string, g nodePatternGate) bool {
	for _, m := range g.musts {
		if m == "" || !strings.Contains(lower, m) {
			return false
		}
	}
	if len(g.alts) == 0 {
		return true
	}
	for _, a := range g.alts {
		if strings.Contains(lower, a) {
			return true
		}
	}
	return false
}

func (d *NodeCVEDetector) Detect(req *CVERequest, hits *subDetectorHits) []CVEMatch {
	var matches []CVEMatch
	for _, rule := range d.rules {
		if !shouldScanNodeRule(req, rule, hits) {
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
						Snippet:     snippet.Extract([]*regexp.Regexp{pat}, t),
					})
					goto nextRule
				}
			}
		}
	nextRule:
	}
	return matches
}

func (d *NodeCVEDetector) DetectFirst(req *CVERequest, hits *subDetectorHits) (CVEMatch, bool) {
	for _, rule := range d.rules {
		if !shouldScanNodeRule(req, rule, hits) {
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
						Snippet:     snippet.Extract([]*regexp.Regexp{pat}, t),
					}, true
				}
			}
		}
	}
	return CVEMatch{}, false
}
