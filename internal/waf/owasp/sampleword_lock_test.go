package owasp

// 本文件是「样本词豁免」相关行为的行为锁定测试（阶段一）。
//
// 背景：检测器内曾存在一批针对具体业务/厂商字面量的「命中即放行」判据，
// 其中一部分会构成单目标绕过面——攻击者只需在载荷任意位置拼入
// 被豁免的词，就能让该目标的整类检测失效。阶段一删除了这批字面量，
// 并以通用判据替代。本文件锁定两条行为，防止回归：
//
//  1. 任何良性标记词拼入 SSRF 载荷后，SSRF 必须仍被检出（正向+反向断言）。
//  2. 网关配置体形态的请求体不得误报 SSRF（豁免的正当目的仍被保留）。
//  3. 外链脚本标签放行必须落在「标签内容」而非域名：纯外链放行，
//     一旦出现可执行体或非白名单 src 形态必须仍报。

import "testing"

// TestSSRFBenignTokenCannotBypass 锁定「样本词不得放行 SSRF」这一行为。
//
// 正向：纯 SSRF 载荷必须检出。
// 反向（变异验证的自动化形式）：在载荷中拼入任何已删除的良性标记词后，
// 仍必须检出——若将来有人把 `某个域名 → 放行` 这类豁免加回该分支，
// 本用例会立刻变红。
func TestSSRFBenignTokenCannotBypass(t *testing.T) {
	benignTokens := []string{
		"stackblitz.com", "codepen.io", "ant.design",
		"npm.staticblitz.com", "cpwebassets.codepen.io",
	}
	base := "url=http://127.0.0.1/admin"

	for _, sens := range []string{"mid", "high"} {
		// 正向：裸载荷必须检出。
		if hits := CheckOWASP(sens, "/", base, nil, nil); len(hits) == 0 {
			t.Fatalf("sens=%s: 裸 SSRF 载荷未被检出", sens)
		}
		for _, tok := range benignTokens {
			// 同 target 拼接。
			if hits := CheckOWASP(sens, "/", base+" "+tok, nil, nil); len(hits) == 0 {
				t.Errorf("sens=%s: 拼接良性词 %q 后 SSRF 被绕过", sens, tok)
			}
			// 跨参数拼接。
			if hits := CheckOWASP(sens, "/", base+"&ref="+tok, nil, nil); len(hits) == 0 {
				t.Errorf("sens=%s: 跨参数拼接良性词 %q 后 SSRF 被绕过", sens, tok)
			}
			// body target 拼接。
			if hits := CheckOWASP(sens, "/", "", nil, []string{base + " " + tok}); len(hits) == 0 {
				t.Errorf("sens=%s: body 目标拼接良性词 %q 后 SSRF 被绕过", sens, tok)
			}
		}
	}
}

// TestSSRFConfigBodyStillBenign 锁定「配置体不误报」这一行为（降权/豁免的正当目的）。
func TestSSRFConfigBodyStillBenign(t *testing.T) {
	body := []string{`{"upstreams":["http://127.0.0.1:8889"],"server_names":["1111"]}`}
	if hits := CheckOWASP("high", "/api/Website", "", map[string]string{"Content-Type": "application/json"}, body); len(hits) != 0 {
		t.Errorf("网关配置体不应报 SSRF，got %+v", hits)
	}
}

// TestExternalScriptTagNotXSS 锁定外链脚本标签的放行行为，含反向断言。
func TestExternalScriptTagNotXSS(t *testing.T) {
	benign := []string{
		`<script src="https://cpwebassets.codepen.io/assets/editor/iframe/iframeConsoleRunner.js"></script>`,
		`<script src="https://example.com/app.js"></script>`,
		`<script src="/assets/app.js"></script>`,
	}
	for _, s := range benign {
		if hits := CheckOWASP("high", "/", "", nil, []string{s}); len(hits) != 0 {
			t.Errorf("纯外链脚本不应报 XSS：%s got %+v", s, hits)
		}
	}
	// 反向断言：同类结构里嵌入可执行体或非白名单 src 形态，必须仍报。
	malicious := []string{
		`<script src="https://example.com/app.js">alert(1)</script>`,
		`<script>alert(1)</script>`,
		`<script src="data:text/javascript;base64,YWxlcnQoMSk="></script>`,
		`<script src="javascript:alert(1)"></script>`,
		`<script src=x></script>`,
		`<script src=/a.js></script>`,
		`<SCRIPT SRC=/BRUTELOGIC.COM.BR/1></SCRIPT>`,
	}
	for _, s := range malicious {
		if hits := CheckOWASP("high", "/", "", nil, []string{s}); len(hits) == 0 {
			t.Errorf("可执行/非白名单脚本形态必须检出：%s", s)
		}
	}
}
