package cve

import (
	"testing"
)

// nodeGateCase 是逐 gate 的证明数据。
// ruleIdx/gateIdx 直接索引 NewNodeCVEDetector().rules[i].gates[j]。
// hit:  该 gate 在对应视图上必须判定为真(正则必现形态)。
// miss: 该 gate 必须判定为假(最小变体,不含门字面量)。
type nodeGateCase struct {
	ruleIdx int
	gateIdx int
	hit     []string
	miss    []string
}

// nodeGateSampleWorker 逐 gate 构造证明样本。与 nodePatternGates 数据同源
// 定义,任何一条门数据改动都会在此处比对失效。
func nodeGateSampleWorker() []nodeGateCase {
	trip := func(s string) []string { return []string{s, "x" + s + "y"} }
	return []nodeGateCase{
		// [0] CVE-2019-10744
		{ruleIdx: 0, gateIdx: 0, hit: trip(`"__proto__":`), miss: []string{`"__proto__".`}},
		{ruleIdx: 0, gateIdx: 1, hit: trip(`__proto__[`), miss: []string{`__proto__ `}},
		{ruleIdx: 0, gateIdx: 2, hit: trip(`__proto__=`), miss: []string{`__proto__ `}},
		{ruleIdx: 0, gateIdx: 3, hit: []string{`constructor ["prototype"]`, `CONSTRUCTOR[ "PROTOTYPE" ]`, `constructor[prototype]`}, miss: []string{`constructor . prototype`}},
		{ruleIdx: 0, gateIdx: 4, hit: trip(`constructor.prototype`), miss: []string{"constructor . prototype", "constructor"}},
		// [1] CVE-2020-REACT-SSR
		{ruleIdx: 1, gateIdx: 0, hit: []string{"dangerouslysetinnerhtml", "DANGEROUSLYSETINNERHTML"}, miss: []string{"dangerously"}},
		{ruleIdx: 1, gateIdx: 1, hit: trip("__next_data__"), miss: []string{"next_data"}},
		{ruleIdx: 1, gateIdx: 2, hit: []string{"`a${b}`", "`${}`"}, miss: []string{"${}", "a${b"}},
		// [2] CVE-2019-NODE-CMD
		{ruleIdx: 2, gateIdx: 0, hit: trip("child_process"), miss: []string{"child process"}},
		{ruleIdx: 2, gateIdx: 1, hit: []string{`require("child_process")`, `REQUIRE ('CHILD_PROCESS')`, `require( "child_process" )`}, miss: []string{`require child_process`, "require('x')"}},
		{ruleIdx: 2, gateIdx: 2, hit: []string{"; id", ";ID", ";\t CAT ", "; pom  whoami "}, miss: []string{"; x", ";;"}},
		{ruleIdx: 2, gateIdx: 3, hit: []string{"| CAT /", "|id /", "|  WHOAMI\t/"}, miss: []string{`| cat \`, "| x /"}},
		{ruleIdx: 2, gateIdx: 4, hit: []string{"`ls`", "`x PWD y`", "`whoami`"}, miss: []string{"`look`", "`prow`"}},
		// [3] CVE-2017-14849
		{ruleIdx: 3, gateIdx: 0, hit: []string{"..%2f", "../..%2F"}, miss: []string{".%2f"}},
		{ruleIdx: 3, gateIdx: 1, hit: []string{"..%5c", "..%5C"}, miss: []string{".%5c"}},
		{ruleIdx: 3, gateIdx: 2, hit: []string{"..;", "../../", "a../b"}, miss: []string{".p", "..:"}},
		{ruleIdx: 3, gateIdx: 3, hit: []string{`..\`, `a..\b`}, miss: []string{".\\"}},
		// [4] CVE-2022-29078
		{ruleIdx: 4, gateIdx: 0, hit: []string{"<%- include", "<% PROCESS", "<%= require", "<%\tglobal", "<%- console("}, miss: []string{"<% printf"}},
		{ruleIdx: 4, gateIdx: 1, hit: []string{`settings["view options"]`, `SETTINGS [ "VIEW OPTIONS" ]`}, miss: []string{`settings["view"]`, `settings["options"]`}},
		// [5] CVE-2023-32314
		{ruleIdx: 5, gateIdx: 0, hit: []string{"this.constructor.constructor", "THIS.CONSTRUCTOR.CONSTRUCTOR"}, miss: []string{"this.constructor"}},
		{ruleIdx: 5, gateIdx: 1, hit: []string{`Function("return process")`, `function ( 'RETURN PROCESS' )`}, miss: []string{`function x process`, `function("return")`}},
		// [6] CVE-2024-34351
		{ruleIdx: 6, gateIdx: 0, hit: []string{"x-middleware-subrequest", "X-Middleware-Subrequest"}, miss: []string{"x-middleware-represent"}},
		// [7] CVE-2025-55182 React2Shell
		{ruleIdx: 7, gateIdx: 0, hit: []string{"__proto__[\"constructor\"]", "__PROTO__ . 'CONSTRUCTOR'"}, miss: []string{"__proto__ constructor", "constructor __proto__"}},
		{ruleIdx: 7, gateIdx: 1, hit: []string{"constructor[\"constructor\"]"}, miss: []string{"constructor"}},
		{ruleIdx: 7, gateIdx: 2, hit: []string{"Function('process')", `Function('spawn')`, "function ('require')"}, miss: []string{`function ("x")`}},
		{ruleIdx: 7, gateIdx: 3, hit: []string{"new Blob(x) new Response", "new blob( new response("}, miss: []string{"blob response", "new blob"}},
		{ruleIdx: 7, gateIdx: 4, hit: []string{`require('child_process').exec`, `require("child_process").spawn`}, miss: []string{`require('child_process') x`}},
		{ruleIdx: 7, gateIdx: 5, hit: []string{".then(eval(", ".then  ( Function("}, miss: []string{".then (x)"}},
		{ruleIdx: 7, gateIdx: 6, hit: []string{`import("fs")`, "import( 'HTTP' )"}, miss: []string{"import fx"}},
		// [8] CVE-2025-55182 FlightRef
		{ruleIdx: 8, gateIdx: 0, hit: []string{"$1:A", "$123:Z"}, miss: []string{"$1a", "1:A", "$"}},
		// [9] CVE-2025-29927
		{ruleIdx: 9, gateIdx: 0, hit: []string{"x-middleware-subrequest: middleware"}, miss: []string{"x-middleware-subrequest"}},
		// [10] CVE-2025-55184
		{ruleIdx: 10, gateIdx: 0, hit: []string{"/_next/data/x.json?__nextDataReq"}, miss: []string{"/_next/data/xjson?__nextDataReq"}},
	}
}

// nodeGatePlace 把样本按规则的 target 视图放入 CVERequest:
// url→Path,header→请求头值,body/all→Body,cookie→Cookie 头。
func nodeGatePlace(sample, target string) *CVERequest {
	headers := map[string]string{"Host": "x"}
	switch target {
	case "url":
		return BuildCVERequest(sample, "", headers, nil, "")
	case "header":
		headers["X-T"] = sample
		return BuildCVERequest("/", "", headers, nil, "")
	case "cookie":
		headers["Cookie"] = sample
		return BuildCVERequest("/", "", headers, nil, "")
	case "body":
		return BuildCVERequest("/", "", headers, []byte(sample), "")
	default: // all / url_body
		return BuildCVERequest("/", "", headers, []byte(sample), "")
	}
}

// nodeGateOpens 判断 target 视图上的任一条目标是否通过指定 gate。
func nodeGateOpens(req *CVERequest, rule nodeCVERule, gi int) bool {
	if gi < 0 || gi >= len(rule.gates) {
		return false
	}
	g := rule.gates[gi]
	for _, t := range resolveTargets(req, rule.target) {
		if nodeGateSatisfied(lowerCVERawTarget(t), g) {
			return true
		}
	}
	return false
}

// TestNodeGateSamples 逐 gate 证明:
//   - hit 样本(真实载荷必现形态)必须打开对应 gate;
//   - miss 样本(不含门字面量的最小变体)必须关闭对应 gate。
//
// 样本按 rule.target 放置到正确视图,断言直接作用于单个 gate,
// 不受其他规则门串扰。
func TestNodeGateSamples(t *testing.T) {
	d := NewNodeCVEDetector()
	if len(d.rules) != 11 {
		t.Fatalf("rules 组数漂移: got %d want 11", len(d.rules))
	}
	if len(nodePatternGates) != 11 {
		t.Fatalf("nodePatternGates 组数漂移: got %d want 11", len(nodePatternGates))
	}
	for i, rule := range d.rules {
		if len(rule.gates) != len(rule.patterns) {
			t.Fatalf("rules[%d] gates 与 patterns 长度不一致: %d != %d", i, len(rule.gates), len(rule.patterns))
		}
	}
	for _, tc := range nodeGateSampleWorker() {
		rule := d.rules[tc.ruleIdx]
		for _, s := range tc.hit {
			req := nodeGatePlace(s, rule.target)
			if !nodeGateOpens(req, rule, tc.gateIdx) {
				t.Errorf("rules[%d].gates[%d]: hit 样本 %q 应打开该门", tc.ruleIdx, tc.gateIdx, s)
			}
		}
		for _, s := range tc.miss {
			req := nodeGatePlace(s, rule.target)
			if nodeGateOpens(req, rule, tc.gateIdx) {
				t.Errorf("rules[%d].gates[%d]: miss 样本 %q 不应打开该门", tc.ruleIdx, tc.gateIdx, s)
			}
		}
	}
}

// TestNodeGateNeverClosesOnRegexpHit 反向证明门是必要条件(命中⇒门真):
// 把每条正则自身串按 target 放入请求,若该串命中正则,则 nodeRuleGate 必不为假。
// 正则串命中 ⇒ 对应 gate 判真 ⇒ 门不关闭 是必要条件的直接证据。
func TestNodeGateNeverClosesOnRegexpHit(t *testing.T) {
	d := NewNodeCVEDetector()
	seen := map[string]bool{}
	for _, rule := range d.rules {
		for i, pat := range rule.patterns {
			if i >= len(rule.gates) {
				continue
			}
			if seen[pat.String()] {
				continue
			}
			seen[pat.String()] = true
			if !pat.MatchString(pat.String()) {
				continue // 该正则串自身不构成匹配,不参与门证明
			}
			req := nodeGatePlace(pat.String(), rule.target)
			if !nodeRuleGate(req, rule) {
				t.Errorf("rules[%s].patterns[%d] 自身串(%q)命中正则但被门关闭", rule.cveID, i, pat.String())
			}
		}
	}
}

// TestNodeGateNeverClosesOnConstructedHits 用人工构造的真实命中串
// (覆盖正则全形态:大小写、空白、编码)逐一确认门不被关闭。
func TestNodeGateNeverClosesOnConstructedHits(t *testing.T) {
	d := NewNodeCVEDetector()
	cases := []struct {
		ruleIdx int
		samples []string
	}{
		{0, []string{`"__proto__":`, `__proto__[`, `__proto__=`, `constructor ["prototype"]`, `constructor.prototype`}},
		{1, []string{"dangerouslySetInnerHTML", "__NEXT_DATA__", "`a${x}b`"}},
		{2, []string{"child_process", `require("child_process")`, "; id", "| id /", "`ls`"}},
		{3, []string{"..%2f", "..%5c", "..;", `..\`}},
		{4, []string{"<% include", "<%= require", `settings["view options"]`}},
		{5, []string{"this.constructor.constructor", `Function("return process")`}},
		{7, []string{
			"__proto__[\"constructor\"]", "constructor[\"constructor\"]",
			`Function('process')`, "new Blob(x) new Response",
			`require('child_process').exec`, ".then(eval(", `import("fs")`,
		}},
		{6, []string{"x-middleware-subrequest"}},
		{8, []string{"$1:A"}},
		{9, []string{"x-middleware-subrequest: middleware"}},
		{10, []string{"/_next/data/x.json?__nextDataReq"}},
	}
	for _, tc := range cases {
		rule := d.rules[tc.ruleIdx]
		for _, s := range tc.samples {
			if !nodeRuleGate(nodeGatePlace(s, rule.target), rule) {
				t.Errorf("rules[%s]: 构造命中串 %q 被门关闭", rule.cveID, s)
			}
		}
	}
}
