package owasp

import (
	"strings"
	"testing"
)

// 本文件是 gotestwaf 剩余缺口修复线的专项回归（第四批）：
//  1. community-rce-rawrequests：PHP `${@函数(...)}` 变量函数调用（owasp:cmd:036）
//  2. community-xxe：charset=UTF-7 编码的 XML 声明（normalize 预解码）
//  3. owasp-api rest：`1e1 union select users from password`（干净目标短路）
//
// 每族给正例（payload 最小必要形态）与反例（自然文本/良性模板），
// 断言收敛到函数级判定（checkCmdInjection / checkXXE / nextSQLiHit，固定
// mid 阈值 4）与归一化输出。multipart form name 位与 form `&&` 链的修复在
// internal/core/rules（extractMultipartFieldValues / extractFormValues），
// 其回归测试见 internal/core/rules/gtw_body_extract_regression_test.go。

// TestGTWFPHPFuncCallCmd 覆盖 PHP 变量函数调用 `${@fn(...)}`：
// gotestwaf community-rce-rawrequests 的 `cmd=${@print(md5(31337))}` 属此语法，
// 原 cmd:022（`$(` 形态）不覆盖 `${@`，检出为空。
func TestGTWFPHPFuncCallCmd(t *testing.T) {
	positives := []string{
		"cmd=${@print(md5(31337))}",
		"${@print(md5(31337))}",
		"x=${@system('id')}",
		"${@assert($_GET[1])}",
		"cmd=${@assert($_POST[0])}",
	}
	for _, s := range positives {
		norm := normalizeWithDecode(s)
		hit, ok := checkCmdInjection(norm, 4)
		if !ok {
			t.Fatalf("PHP ${@ 调用形态 %q 未被命令注入检出（归一后 %q）", s, norm)
		}
		if hit.RuleID != "owasp:cmd:036" {
			t.Fatalf("%q 命中规则 = %s，期望 owasp:cmd:036", s, hit.RuleID)
		}
	}

	// 反例：常见模板/脚本变量插值，均不得触发命令注入电池。
	negatives := []string{
		"${user.name}",
		"${pageContext.request.contextPath}",
		"${item.price}",
		"${HOME}",
		"${maxSize}",
		"the value is ${x}",
		"${if (x) y}",
		"${ json.encode(t) }",
	}
	for _, s := range negatives {
		if hit, ok := checkCmdInjection(normalizeWithDecode(s), 4); ok {
			t.Fatalf("良性变量插值 %q 被误判为命令注入（%s）", s, hit.RuleID)
		}
	}

	// 规则自锁：③ hint `${@` 必须与正则命中方向一致（不得把正例剪掉）。
	pat := lookupCmdPattern(t, "owasp:cmd:036")
	for _, s := range positives {
		if !pat.re.MatchString(strings.ToLower(s)) {
			t.Fatalf("owasp:cmd:036 正则未命中正例 %q", s)
		}
		if !shouldScanCmdPattern(strings.ToLower(s), pat) {
			t.Fatalf("owasp:cmd:036 前置把正则命中的正例 %q 剪掉了", s)
		}
	}
	for _, s := range negatives {
		if pat.re.MatchString(strings.ToLower(s)) {
			t.Fatalf("owasp:cmd:036 正则误命中良性输入 %q", s)
		}
	}
}

// TestGTWFUTF7PreDecode 覆盖 UTF-7 预解码：gotestwaf community-xxe 的第二个
// payload 是 charset="UTF-7" 的 XML 声明 + `+ADwAIQ-DOCTYPE ...` 编码体。
// 修复前 URL 解码（+ → 空格）先于 UTF-7 解码执行，`+ADw-` 等标记被破坏，
// 归一结果为 " adwaiq-doctype foo afs" 之类的残渣，XXE 全电池失配。
func TestGTWFUTF7PreDecode(t *testing.T) {
	utf7Doc := "<?xml version=\"1.0\" encoding=\"UTF-7\"?>\n" +
		"+ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ELEMENT foo ANY +AD4\n" +
		"+ADwAIQ-ENTITY xxe SYSTEM +ACI-http://hack-r.be:1337+ACI +AD4AXQA+\n" +
		"+ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4"

	norm := normalizeWithDecode(utf7Doc)
	if !strings.Contains(norm, "<!doctype foo[") || !strings.Contains(norm, "<!entity") {
		t.Fatalf("UTF-7 XML 未解码为标记原文，归一结果 = %q", norm)
	}
	hit, ok := checkXXE(norm, 4)
	if !ok {
		t.Fatalf("UTF-7 编码的 XXE 文档未检出（归一结果 %q）", norm)
	}
	if hit.RuleID != "owasp:xxe:001" && hit.RuleID != "owasp:xxe:002" {
		t.Fatalf("UTF-7 XXE 命中规则 = %s，期望 001/002", hit.RuleID)
	}

	// 纯片段形态（非整文档）同样受益于预解码。
	frag := normalizeWithDecode("+ADwAIQ-DOCTYPE foo+AFs")
	if !strings.Contains(frag, "<!doctype foo[") {
		t.Fatalf("UTF-7 片段未预解码，结果 = %q", frag)
	}
	if _, ok := checkXXE(frag, 4); !ok {
		t.Fatalf("UTF-7 片段 %q 未检出", frag)
	}

	// 反例 1：普通 UTF-7 XSS 片段仍需解码（预解码不得回退既有能力）。
	xssNorm := normalizeWithDecode("+ADw-script+AD4-alert(1)+ADw-/script+AD4-")
	if !strings.Contains(xssNorm, "<script>") {
		t.Fatalf("既有 UTF-7 XSS 解码回退，归一结果 = %q", xssNorm)
	}

	// 反例 2：`+` 当空格的查询值不得被误当作 UTF-7 解成乱码。
	for _, s := range []string{
		"x=1+AND+1=1",
		"q=a+b",
		"phone +1 234",
		"value=+1",
	} {
		norm := normalizeWithDecode(s)
		if strings.ContainsRune(norm, 0x10) || strings.Contains(norm, "\x01") {
			t.Fatalf("查询串 %q 被 UTF-7 误解码为控制字符：%q", s, norm)
		}
	}
	if got := normalizeWithDecode("x=1+AND+1=1"); !strings.Contains(got, "1 and 1=1") {
		t.Fatalf("`+` 当空格的 SQLi 形态被破坏，归一结果 = %q", got)
	}

	// 反例 3：XML 正文里的 UTF-7 字面量（无 +A 编码序列）保持原样。
	plain := "<!DOCTYPE foo [ <!ENTITY data SYSTEM \"netdoc:/etc/passwd\">]><foo>&data;</foo>"
	if _, ok := checkXXE(normalizeWithDecode(plain), 4); !ok {
		t.Fatal("非 UTF-7 的常规 XXE 文档漏检")
	}
}

// TestGTWFAlnumSQLiPhrase 覆盖「干净目标短路」误杀 SQLi 的问题：
// `1e1 union select users from password` 全由字母数字与空格组成，
// isCleanTarget 判定为干净目标直接跳过扫描，而 sqli:001 恰恰依赖词边界
// 匹配这类短语。短路条件补充 hasSuspiciousKeywords 后恢复检出。
func TestGTWFAlnumSQLiPhrase(t *testing.T) {
	positives := []string{
		"1e1 union select users from password",
		"1 union select 1",
		"1 UNION SELECT null FROM users",
		"x=1 and 1=1",
		"union select users from password",
	}
	// `1 union select users`（无 from 表引用、无列值）被 hasUnionSelectAttackContext
	// 判为文档/自然语言语境，属既有的精确度取舍，不并入本轮修复面。
	for _, s := range positives {
		norm := normalizeWithDecode(s)
		if _, ok := nextSQLiHit(norm, 4); !ok {
			t.Fatalf("纯字母数字 SQLi 短语 %q 漏检（归一结果 %q）", s, norm)
		}
	}

	// 端到端：JSON body 经 rules.extractBodyTargets 抽出的值必须触发命中。
	headers := map[string]string{"content-type": "application/json", "user-agent": "Mozilla/5.0"}
	hits := CheckOWASP("mid", "/", "", headers, []string{"test", "0123456789abcdef", "1e1 union select users from password"})
	if len(hits) == 0 {
		t.Fatal("CheckOWASP 对 JSON 值内的 `1e1 union select` 无命中")
	}
	if hits[0].RuleID != "owasp:sqli:001" {
		t.Fatalf("CheckOWASP 命中规则 = %s，期望 owasp:sqli:001", hits[0].RuleID)
	}

	// 反例：同字符集的自然文本/标识符不得被 SQLi 电池误伤。
	negatives := []string{
		"John Smith",
		"the quick brown fox",
		"product name",
		"user id",
		"New York",
		"readme md",
		"alpha beta gamma",
		"2026 10 01",
		"order id",
		"a1b2c3 key",
	}
	for _, s := range negatives {
		if hit, ok := nextSQLiHit(normalizeWithDecode(s), 4); ok {
			t.Fatalf("良性字母数字文本 %q 被 SQLi 电池误判（%s）", s, hit.RuleID)
		}
		if hit, ok := checkCmdInjection(normalizeWithDecode(s), 4); ok {
			t.Fatalf("良性字母数字文本 %q 被命令注入电池误判（%s）", s, hit.RuleID)
		}
	}

	// 短路修复只放宽「关键词目标」，逐一确认纯标识符仍走快速跳过路径。
	for _, s := range []string{"John Smith", "product name", "order id"} {
		if !isCleanTarget(s) {
			t.Fatalf("%q 不再被判定为干净目标，短路修复范围过宽", s)
		}
		if hasSuspiciousKeywords(s) {
			t.Fatalf("%q 被 hasSuspiciousKeywords 误判为可疑（短路失效）", s)
		}
	}
}
