package cve

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/ac"
)

func TestACMatcherMatchAny(t *testing.T) {
	b := ac.NewBuilder()
	needles := []string{"jndi:", "ldap://", "../", "<?php", "union select"}
	for _, n := range needles {
		b.AddPattern(n)
	}
	m := b.Build()

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
		got := m.MatchAny(c.target)
		if got != c.want {
			t.Errorf("MatchAny(%q)=%v want %v", c.target, got, c.want)
		}
	}
}

func TestACMatcherMatchMask(t *testing.T) {
	b := ac.NewBuilder()
	needles := []string{"abc", "bcd", "xyz"}
	indices := make([]int32, len(needles))
	for i, n := range needles {
		indices[i] = b.AddPattern(n)
	}
	m := b.Build()

	target := "1abcde_xyz2"
	hit := m.MatchMask(target)

	var mask0 ac.Mask
	mask0.Set(indices[0]) // 匹配字面 "abc"
	if !hit.Intersects(&mask0) {
		t.Fatal("应命中 abc")
	}
	var mask1 ac.Mask
	mask1.Set(indices[1]) // 匹配字面 "bcd"
	if !hit.Intersects(&mask1) {
		t.Fatal("应命中 bcd(abc 的后续)")
	}
	var mask2 ac.Mask
	mask2.Set(indices[2]) // 匹配字面 "xyz"
	if !hit.Intersects(&mask2) {
		t.Fatal("应命中 xyz")
	}

	miss := m.MatchMask("nothing")
	if miss.Intersects(&mask0) || miss.Intersects(&mask1) || miss.Intersects(&mask2) {
		t.Fatal("不应有命中")
	}
}

func TestACMatcherMatchMaskSliceNoCrossBoundary(t *testing.T) {
	b := ac.NewBuilder()
	idx := b.AddPattern("avas")
	m := b.Build()

	// "java" + "script" 拼起来含 "avas"(java|script → ava|s),但逐条扫不应命中。
	targets := []string{"java", "script"}
	hit := m.MatchMaskSlice(targets)
	var mask ac.Mask
	mask.Set(idx)
	if hit.Intersects(&mask) {
		t.Fatal("MatchMaskSlice 不应跨 target 边界拼接匹配")
	}

	targets2 := []string{"has avas inside"}
	hit2 := m.MatchMaskSlice(targets2)
	if !hit2.Intersects(&mask) {
		t.Fatal("MatchMaskSlice 应在单条 target 内匹配")
	}
}

// AC MatchAny vs 逐 needle strings.Contains,确保每个 target 判定一致。
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
	b := ac.NewBuilder()
	for _, n := range needles {
		b.AddPattern(n)
	}
	m := b.Build()

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
		got := m.MatchAny(target)
		want := naive(target)
		if got != want {
			t.Errorf("target=%q: AC=%v naive=%v", target, got, want)
		}
	}
}
