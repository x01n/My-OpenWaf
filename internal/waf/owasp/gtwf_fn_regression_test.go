package owasp

import (
	"net/url"
	"strings"
	"testing"
)

// 本文件是 gotestwaf FN 修复线的专项回归：每族修复一条或多条正例（payload
// 原文最小必要形态，取自 gotestwaf testcases 与 /tmp/gtw-fn 工件），并为
// 低碰撞新增面配反向例。断言收敛到函数级判定（checkXSS/nextSQLiHit/
// checkCRLF 等，固定 mid=4 阈值）与门级判定（hasACIndicator/hasXSSIndicator
// 只增不减）。bot UA 三字面的回归在 internal/waf/bot（bot_logic_test.go）。

// TestGTWFNXSS 系列：xss 族三处修复。
func TestGTWFNXSS(t *testing.T) {
	// xss:001 <script;alert 分号变体（原 \s> 收不下 ;）
	if _, ok := checkXSS("<script;alert(document.domain)</script>", 4); !ok {
		t.Fatal("xss:001 未检出 <script; 分号变体")
	}
	// xss:067 直接形态 (alert)(1)（no-dot，)'(' 直连）
	if _, ok := checkXSS("(alert)(1)", 4); !ok {
		t.Fatal("xss:067 未检出 (alert)(1)")
	}
	// xss:067 confirm.call 家族（原正则本已覆盖，锚定回归）
	if _, ok := checkXSS("confirm.call(null,1)", 4); !ok {
		t.Fatal("xss:067 未检出 confirm.call")
	}
	// xss:002 onauxclick 事件名
	if _, ok := checkXSS(`"onauxclick=alert`+"`xss`"+`+a`, 4); !ok {
		t.Fatal("xss:002 未检出 onauxclick")
	}
	// 原文 OnCliCk="(prompt`1`)：管线 normalize 先 lower（toLowerASCII）再进
	// battery；混合大小写的原文直喂 checkXSS 不命中属预期（门字面为精确
	// 小写）。此处按管线语义照抄：lower 后 onclick= 事件绑定命中 xss:002。
	if _, ok := checkXSS(strings.ToLower(`"OnCliCk="(prompt`+"`1`)"), 4); !ok {
		t.Fatal("xss 未检出 OnCliCk=(prompt`1`) 原文")
	}
	// 裸 (prompt`1`) 反引号模板实参形态（xss:069 新规则）。
	if _, ok := checkXSS("(prompt`1`)", 4); !ok {
		t.Fatal("xss:069 未检出 (prompt`1`)")
	}
	// 反例：反引号双括号间的普通标识符（非弹窗函数）不命中。
	if _, ok := checkXSS("foo`bar`", 4); ok {
		t.Fatal("良性反引号串被 xss:069 假阳")
	}
	// 反向：onauxclick 单词/词典词、alert) 无调用、>= 正常语境均不得命中
	for _, s := range []string{
		"onselect",
		"dblclick=2",
		"mousedown=1",
		"alert) mousedown",
		"prompt) x",
		"x === 2 && y > 0",
		"constructor x",
		"a(b) c(d)",
	} {
		if _, ok := nextXSSHit(s, 4); ok {
			t.Fatalf("良性输入 %q 被 XSS 假阳", s)
		}
	}
}

// TestGTWFNXSSConfirmLiteral 确认 confirm. 字面在门位扫描路径直通
// （xssIndicatorLiteralBytes 在 hasXSSIndicator 的公开循环；'c' 分支放行）。
func TestGTWFNXSSConfirmLiteral(t *testing.T) {
	if !hasXSSIndicator("confirm.c") {
		t.Fatal("confirm. 字面未通过门位扫描路径放行")
	}
}

// TestGTWFNShell 覆盖 shell 族三条载荷。
func TestGTWFNShell(t *testing.T) {
	// getent 载荷（|getent hosts somehost.burpcollaborator.net.&）
	if _, ok := checkCmdInjection("|getent hosts somehost.burpcollaborator.net.&", 4); !ok {
		t.Fatal("shell 未检出 |getent")
	}
	// set /a 载荷（| set /a 3482*7301）
	if _, ok := checkCmdInjection("| set /a 3482*7301", 4); !ok {
		t.Fatal("shell 未检出 | set /a")
	}
	// 反向：set 单独、set /x、Let's set it、Set-Cookie 等良性语境
	for _, s := range []string{
		"set",
		"set /x 1",
		"let's set it",
		"set-cookie: a=1",
		"x=reset okay",
	} {
		if _, ok := checkCmdInjection(s, 4); ok {
			t.Fatalf("良性输入 %q 被 shell 假阳", s)
		}
	}
}

// TestGTWFNSSTI 覆盖 ssti 两条载荷与反向例。
func TestGTWFNSSTI(t *testing.T) {
	// #{16*8787} 算术（经 '%2b 拼接路径）
	if _, ok := checkTemplateInjection("#{16*8787}", 4); !ok {
		t.Fatal("ssti 未检出 #{16*8787}")
	}
	// FreeMarker 载荷 ${ex("id")}
	if _, ok := checkTemplateInjection(`<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}`, 4); !ok {
		t.Fatal("ssti 未检出 FreeMarker 载荷")
	}
	// 反向：${x} 纯标识模板、CSS 花括号、#{ 无算术
	for _, s := range []string{
		"${name}",
		"{{name}}",
		"body { color: red; }",
		"#{color}",
		"#include <stdio.h>",
	} {
		if _, ok := checkTemplateInjection(s, 4); ok {
			t.Fatalf("良性输入 %q 被 SSTI 假阳", s)
		}
	}
}

// TestGTWFNLDAPAttrOID 覆盖 ldap_attr 载荷（userPassword:2.5.13.18:=123）。
func TestGTWFNLDAPAttrOID(t *testing.T) {
	if _, ok := checkLDAPInjection("userPassword:2.5.13.18:=123", 4); !ok {
		t.Fatal("ldap 未检出 2.5.13.18 OID")
	}
	// 反向：普通版本号 2.5.13.1、UUID、ip 形态
	for _, s := range []string{
		"guest",
		"2.5.13.1",
		"2.5.13.17",
		"192.168.1.1",
		"::",
	} {
		if _, ok := checkLDAPInjection(s, 4); ok {
			t.Fatalf("良性输入 %q 被 LDAP 假阳", s)
		}
	}
}

// TestGTWFNRCEMarker 覆盖 rce-urlparam 的 !!python 标签载荷。
func TestGTWFNRCEMarker(t *testing.T) {
	// !!python 标签 → ES/EL 族 RegExp 命中（类别取 CatExprLang）
	_, ok := checkExprLang("!!python/object/new:exec [import socket; socket.gethostbyname('somehost.burpcollaborator.net')]", 4)
	if !ok {
		t.Fatal("rce 未检出 !!python 标签载荷")
	}
	// 反向：!! / !!1 若匹配前需带语族（此处只测 exclamation）
	for _, s := range []string{
		"hello",
		"bang",
		"fn",
		"a && b",
	} {
		if _, ok := checkExprLang(s, 4); ok {
			t.Fatalf("良性输入 %q 被 EL 假阳", s)
		}
	}
}

// TestGTWFNSQLiJSONExtract 覆盖 sqlwaf_json_or 载荷。
func TestGTWFNSQLiJSONExtract(t *testing.T) {
	// 管线语义：normalize 会把 payload 全量 lower，再进 nextSQLiHit。
	// 门判按真实链路断言（upper 直喂也成立），电池按 lower 后输入跑。
	s := `-1134')  OR JSON_EXTRACT('{''aKER'': 9648}', '$.aKER') = 9648*7799 AND ('QlYa' LIKE 'QlYa`
	if !hasSQLiIndicator(s) {
		t.Fatal("sqli 门未认领 JSON_EXTRACT 载荷")
	}
	if _, ok := nextSQLiHit(normalize(s), 4); !ok {
		t.Fatal("sqli 未检出 JSON_EXTRACT 载荷")
	}
}

// TestGTWFNCRLF 覆盖 crlf 双编码 + mail-injection 载荷。
// 管线语义：主循环先对 raw 做 url.PathUnescape + ToLower 再进 checkCRLF，
// 此处照抄（Scene 门是字节级小写字面）。
func TestGTWFNCRLF(t *testing.T) {
	for _, c := range []struct {
		s string
	}{
		{"%25%30%41%25%30%44Set-cookie:crlf=injection"},
		{"%25%30%44%25%30%41Set-cookie:crlf=injection"},
		{"%25%30%41Set-cookie:crlf=injection"},
		{"\nRCPT TO: test@evil.com\n"},
		{"\r\nV100 CAPABILITY\r\nV101 FETCH 4791"},
		{"\r\nQUIT\r\n"},
		{"to: a@b.c\ncc: evil@evil.com"},
	} {
		s := c.s
		if d, err := url.PathUnescape(s); err == nil {
			s = d
		}
		s = strings.ToLower(s)
		if _, ok := checkCRLF(s, 4); !ok {
			t.Fatalf("crlf 未检出 %q", c.s)
		}
	}
	// 反向：非头接续的裸 \r\n 文本、'a' 形 to:
	for _, s := range []string{
		"line one\r\nline two",
		"plain text",
		"x=to:someone@example.com",
	} {
		if _, ok := checkCRLF(s, 4); ok {
			t.Fatalf("良性输入 %q 被 CRLF 假阳", s)
		}
	}
}

// TestGTWFNPathUNC 覆盖 path_unc 载荷（含 b64 解码路径）。
func TestGTWFNPathUNC(t *testing.T) {
	if !hasACIndicator(famPathTrav, `\\::1\c$\users\default\ntuser.dat`) {
		t.Fatal("path 未检出 UNC 载荷")
	}
	// 反向：普通 shell 提示符、s/// 替换形态、无 c$
	for _, s := range []string{
		"home/user/notes.txt",
		"foo bar",
		"let's go",
		"ubuntu@host:~$",
	} {
		if hasACIndicator(famPathTrav, s) {
			t.Fatalf("良性输入 %q 被 path 假阳", s)
		}
	}
}

// TestGTWFNXXEXSInclude 覆盖 xs:include / xs:import / xs:schemaLocation。
func TestGTWFNXXEXSInclude(t *testing.T) {
	s := `<?xml version="1.0" encoding="utf-8" standalone="no" ?><xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:include namespace="http://xxe-xsinclude-namespace.yourdomain[.]com/"/></xs:schema>`
	if _, ok := checkXXE(s, 4); !ok {
		t.Fatal("xxe 未检出 xs:include 载荷")
	}
	// AC 门是字节级精确字面，只认小写三条（XSD 中这些指令必须小写，
	// 大写不是合法 XSD，电池的 (?i) 宽松仅防串扰）。
	for _, frag := range []string{"xs:include", "xs:import", "xs:schemalocation"} {
		if !hasACIndicator(famXXE, frag) {
			t.Fatalf("xxe 门未认领 %q", frag)
		}
	}
	// 反向：xs:model 等非注入属性、纯 <xs> 标签
	if hasACIndicator(famXXE, "xs:model group") {
		t.Fatal("xs:model 被误认领")
	}
}

// TestGTWFNNosqlEntityOr 覆盖 nosql $apos;or 实体变体。
func TestGTWFNNosqlEntityOr(t *testing.T) {
	for _, s := range []string{`$apos;or`, `x='$apos;or'`, `"name": "$apos;or"`} {
		if !hasACIndicator(famNoSQLi, s) {
			t.Fatalf("nosql 门未认领 %q", s)
		}
	}
	// 反向：普通 or / apos 文本
	for _, s := range []string{"apos", "for each", "oracle"} {
		if hasACIndicator(famNoSQLi, s) {
			t.Fatalf("nosql 门假阳 %q", s)
		}
	}
}

// TestGTWFNSQLiUnionPlusBacktick 覆盖 sql 语法非本线形态的脱敏回归：
// 1 UNION SELECT 仍由 sqli:001 命中，不因 command() 门新窗引入假阴。
func TestGTWFNSQLiUnionPlusBacktick(t *testing.T) {
	// normalized 输入（真实管线先 normalize 再进 nextSQLiHit）。
	if _, ok := nextSQLiHit(normalize("1 UNION SELECT NULL--"), 4); !ok {
		t.Fatal("sqli 未检出 1 UNION SELECT")
	}
}

// TestGTWFNIndicatorNoRegressions 逐门增量后的净变化断言：
// confirm. / c$ / !! / #{ / $apos;or / 2.5.13.18 只增不减。
func TestGTWFNIndicatorNoRegressions(t *testing.T) {
	for _, c := range []struct {
		s  string
		fn func(string) bool
	}{
		{"confirm.call(null,1)", hasXSSIndicator},
		{`\\::1\c$`, func(s string) bool { return hasACIndicator(famPathTrav, s) }},
		{"!!python", func(s string) bool { return hasACIndicator(famEL, s) }},
		{"#{16}", func(s string) bool { return hasACIndicator(famTemplate, s) }},
		{"$apos;or", func(s string) bool { return hasACIndicator(famNoSQLi, s) }},
		{"2.5.13.18", func(s string) bool { return hasACIndicator(famLDAP, s) }},
	} {
		if !c.fn(c.s) {
			t.Fatalf("增量门 %q 未被认领", c.s)
		}
	}
	if !strings.Contains(strings.Join(owaspACFamilies[famXXE].orNeedles, "|"), "xs:include") {
		t.Fatal("xxe 门缺少 xs:include")
	}
	if !strings.Contains(strings.Join(owaspACFamilies[famXXE].orNeedles, "|"), "xs:import") {
		t.Fatal("xxe 门缺少 xs:import")
	}
	if !strings.Contains(strings.Join(owaspACFamilies[famXXE].orNeedles, "|"), "xs:schemalocation") {
		t.Fatal("xxe 门缺少 xs:schemalocation")
	}
}
