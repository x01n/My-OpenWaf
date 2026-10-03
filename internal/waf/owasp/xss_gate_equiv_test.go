package owasp

import (
	"math/rand"
	"strings"
	"testing"
)

// refHasXSSIndicator 是 hasXSSIndicator 旧实现的镜像参考（提交 251fa61 之前的
// 字面量版本），用于对拍证明 C1 合并刀（IndexByte 头部门 + 单趟位扫描）判定不变。
// C2 增量（confirm. 字面入表、alert)(/prompt)(/confirm)( 门级直通）同步收录，
// 保持参照与生产的判定一致。
func refHasXSSIndicator(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '<' {
			return true
		}
	}
	if strings.Contains(s, "alert)(") ||
		strings.Contains(s, "prompt)(") ||
		strings.Contains(s, "confirm)(") {
		return true
	}
	var seenJ, seenF, seenO bool
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 'j':
			seenJ = true
		case 'f':
			seenF = true
		case 'o':
			seenO = true
		}
	}
	if seenJ && strings.Index(s, "javascript:") >= 0 {
		return true
	}
	if seenF {
		if strings.Index(s, "fetch(") >= 0 ||
			strings.Index(s, "frames[") >= 0 ||
			strings.Index(s, "fromcharcode") >= 0 {
			return true
		}
	}
	for _, flagB := range xssIndicatorLiteralBytes {
		if len(flagB) == 0 {
			continue
		}
		switch flagB[0] {
		case 'o':
			if !seenO {
				continue
			}
		case 'j', 'f':
			continue
		}
		if strings.Index(s, flagB) >= 0 {
			return true
		}
	}
	if strings.Contains(s, "function(") {
		return true
	}
	return false
}

func TestXSSIndicatorMaskEquiv(t *testing.T) {
	// 定向清单：覆盖 C1 证明注释里逐条 XSS 规则的必要字面量形态
	// （<script / onclick / o 开头事件 / javascript: / data: / 反引号 ${ / function( 等）。
	fixed := []string{
		"", "<", "=", "`",
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"onclick=alert(document.cookie)",
		"<svg onload=alert(1)>",
		"<math><mglyph>",
		"javascript:alert(1)",
		"vbscript:msgbox",
		"data:text/html,<b>x</b>",
		"data:image/svg+xml;base64,PHN2Zz4=",
		"document.cookie",
		"window['location']",
		"self[alert(1)]",
		"top[0]",
		"parent['x']",
		"frames['a']",
		"globalthis[0]",
		"this['x']",
		"fetch('http://evil/x')",
		"eval('alert(1)')",
		"setTimeout('x')",
		"setInterval(atob('eA=='))",
		"expression(document.cookie)",
		"srcdoc=<b>",
		"{{constructor}}",
		"alert(1)",
		"confirm.constructor", // C2 已改：confirm. 进入字面量表，参照表同步收录
		"prompt(document.domain)",
		"alert.call(window,1)",
		"alert apply",
		"x=/a/.source",
		"atob(",
		"![]",
		"+{}",
		"+[]",
		"@import",
		"(function(){return 1})()",
		"new function('a')",
		"`${document.cookie}`",
		"plain hello world",
		"k=v&a=b&c=d",
		"http://example.com/?q=1",
		"j s a m",
		"alert",
		" `",
		"<ok:script",
		"onformdata=",
		"whoami",
		"fromcharcode",
	}

	rng := rand.New(rand.NewSource(20260928))
	const pool = "<>=`()[]{}'\"&;:.,/\\|!+@$%#*^~-_ abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const (
		randN = 100_000
		randL = 24
	)

	for _, s := range fixed {
		if got, want := hasXSSIndicator(s), refHasXSSIndicator(s); got != want {
			t.Fatalf("fixed %q: got %v want %v", s, got, want)
		}
	}
	for n := 0; n < randN; n++ {
		l := rng.Intn(randL + 1)
		b := make([]byte, l)
		for i := range b {
			b[i] = pool[rng.Intn(len(pool))]
		}
		s := string(b)
		if got, want := hasXSSIndicator(s), refHasXSSIndicator(s); got != want {
			t.Fatalf("random %q: got %v want %v", s, got, want)
		}
	}
}

// TestNextXSSHitGateKeepsHitSet 验证 C1 合并刀后 nextXSSHit 在固定输入集上的
// 命中规则集合不变（门 only-skip 约束下的整体等价锁）。
func TestNextXSSHitGateKeepsHitSet(t *testing.T) {
	inputs := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(document.cookie)",
		"<svg onload=alert(1)>",
		"data:text/html,<script>alert(1)</script>",
		"`${document.cookie}`",
		"eval('alert(1)')",
		"document.write('<b>')",
		"http://example.com/?a=1&b=2",
		"<form action=\"javascript:alert(1)\">",
		"\"+'A'+'\"",
		"+A1/",
		"window['location']",
	}
	want := make([][]string, len(inputs))
	for i, s := range inputs {
		h, ok := nextXSSHit(s, 1)
		if ok {
			want[i] = append(want[i], h.RuleID)
		}
		if got := hasXSSIndicator(s); !got {
			// 门为必要条件：未放行的输入必然无 hit，用于在前置断言层复核。
			if ok {
				t.Fatalf("input %q: gate false but hit %v", s, h.RuleID)
			}
		}
	}
	for i, s := range inputs {
		h, ok := nextXSSHit(s, 1)
		if ok != (len(want[i]) > 0) {
			t.Fatalf("input %q: hit-ok changed to %v (want %d hits)", s, ok, len(want[i]))
		}
		if ok && h.RuleID != want[i][0] {
			t.Fatalf("input %q: rule changed %q -> %q", s, want[i][0], h.RuleID)
		}
	}
}
