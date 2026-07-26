package cve

import (
	"strings"
	"testing"
)

func TestACMatcherMatchAny(t *testing.T) {
	b := newACBuilder()
	needles := []string{"jndi:", "ldap://", "../", "<?php", "union select"}
	for _, n := range needles {
		b.addPattern(n)
	}
	ac := b.build()

	cases := []struct {
		target string
		want   bool
	}{
		{"", false},
		{"nothing here", false},
		{"x=${jndi:ldap://evil}", true},
		{"path=../../etc/passwd", true},
		{"safe query string", false},
		{"<?php echo 1; ?>", true},
		{"' union select 1,2 --", true},
		{"ldap", false},
		{"jndi", false},
	}
	for _, c := range cases {
		got := ac.matchAny(c.target)
		if got != c.want {
			t.Errorf("matchAny(%q)=%v want %v", c.target, got, c.want)
		}
	}
}

func TestACMatcherMatchMask(t *testing.T) {
	b := newACBuilder()
	needles := []string{"abc", "bcd", "xyz"}
	indices := make([]int32, len(needles))
	for i, n := range needles {
		indices[i] = b.addPattern(n)
	}
	ac := b.build()

	target := "1abcde_xyz2"
	hit := ac.matchMask(target)

	var mask0 acGateMask
	mask0.set(indices[0]) // "abc"
	if !hit.intersects(&mask0) {
		t.Fatal("应命中 abc")
	}
	var mask1 acGateMask
	mask1.set(indices[1]) // "bcd"
	if !hit.intersects(&mask1) {
		t.Fatal("应命中 bcd(abc 的后续)")
	}
	var mask2 acGateMask
	mask2.set(indices[2]) // "xyz"
	if !hit.intersects(&mask2) {
		t.Fatal("应命中 xyz")
	}

	miss := ac.matchMask("nothing")
	if miss.intersects(&mask0) || miss.intersects(&mask1) || miss.intersects(&mask2) {
		t.Fatal("不应有命中")
	}
}

func TestACMatcherMatchMaskSliceNoCrossBoundary(t *testing.T) {
	b := newACBuilder()
	idx := b.addPattern("avas")
	ac := b.build()

	// "java" + "script" 拼起来含 "avas"(java|script → ava|s),但逐条扫不应命中。
	targets := []string{"java", "script"}
	hit := ac.matchMaskSlice(targets)
	var mask acGateMask
	mask.set(idx)
	if hit.intersects(&mask) {
		t.Fatal("matchMaskSlice 不应跨 target 边界拼接匹配")
	}

	targets2 := []string{"has avas inside"}
	hit2 := ac.matchMaskSlice(targets2)
	if !hit2.intersects(&mask) {
		t.Fatal("matchMaskSlice 应在单条 target 内匹配")
	}
}

// TestACMatcherFuzzEquivalence 用真实 CVE needle 集做密集对拍:
// AC matchAny vs 逐 needle strings.Contains,确保每个 target 判定一致。
func TestACMatcherFuzzEquivalence(t *testing.T) {
	needles := []string{
		"() {", "solrsearch", "media=rss", "groovy", "{{async", "{{ async",
		"loginok.html", "%00", "io.popen", "lua",
		"swupdatefileuploader", "filename=", "magicinfo", "../",
		"fwbcgi", "cgiinfo",
		"unlicensed.xhtml", "garequestaction=activate", "javax.faces.viewstate",
		"actuator/gateway", "addresponseheader", "#{", "spel",
		"themeeditor", "customcss", "expression=",
		"webinterface/function", "aws4-hmac-sha256", "crushftp",
		"hostcheck_validate", "authhash",
		"json-patch", "application/patch+json", "t(",
		"<java", "<sorted-set", "<dynamic-proxy", "xstream", "processbuilder", "runtime",
		"jndi:", "ldap://", "rmi://", "iiop://", "jdbc:", "dns://",
		"utf-7", "+adw-", "+adi-", "+afw-",
		"objectclass=", ")(|", ")(uid=", "*)(", "ldap",
		"/.env", "/.git/config", "/.htaccess", "/wp-config.php", "/web.config", "/etc/passwd",
		"<!doctype", "<!entity", "<!element", "system", "public",
		"php://", "data://", "expect://", "phar://", "zip://",
		"eval(", "assert(", "system(", "exec(", "passthru(", "shell_exec(",
		"__proto__", "constructor", "prototype", "this[", "window[",
		"union select", "select ", "insert into", "update ", "delete from", "drop table",
		"%2e%2e", "....//", "%252e",
		"<script", "javascript:", "onerror=", "onload=", "alert(",
		"cmd=", "exec=", "command=", "run=", "/bin/sh", "/bin/bash",
	}
	b := newACBuilder()
	for _, n := range needles {
		b.addPattern(n)
	}
	ac := b.build()

	naive := func(target string) bool {
		for _, n := range needles {
			if strings.Contains(target, n) {
				return true
			}
		}
		return false
	}

	targets := []string{
		"",
		"completely clean no punctuation",
		"get /api/v1/users?id=1234&name=alice&filter=(status:active)&sort=desc",
		"${jndi:ldap://evil/a}",
		"../../../etc/passwd",
		"payload=eval(base64_decode('test'))",
		"x=1&__proto__=polluted",
		"POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data\r\n\r\nfile=test.php.jpg",
		"q=<script>alert(1)</script>",
		"x=' union select 1,2,3 -- &y=normal",
		"() { :; }; /bin/bash -c 'cat /etc/passwd'",
		"jnd",     // 截断不应匹配
		"ldap",    // 仅 ldap(无 :// 也无 objectclass=)但 ldap 本身是 needle
		"sys",     // 不是 system
		"system",  // 是 needle
		"/bin/s",  // 截断
		"/bin/sh", // 完整
		"<java version='1.0'>",
		"javascript:void(0)",
		"{{async function test(){}}",
	}
	for _, target := range targets {
		got := ac.matchAny(target)
		want := naive(target)
		if got != want {
			t.Errorf("target=%q: AC=%v naive=%v", target, got, want)
		}
	}
}
