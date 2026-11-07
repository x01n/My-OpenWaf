package owasp

import "testing"

// crlfGatePayloads 覆盖 CRLF 各规则的代表性载荷与常见良性输入。
// 用于验证「门」只跳过正则不可能命中的输入，不会改变任何命中。
var crlfGatePayloads = []string{
	// 规则代表性载荷。
	"x\r\nset-cookie: sid=1",
	"x\nx-evil: 1",
	"%0d%0alocation: http://evil",
	"%0d%0a%0d%0a",
	"a\r\n\r\nb",
	"x\r\n\r\ndate: today",
	"%0d%0a%0d%0aset-cookie: a=1",
	"%0aset-cookie: a=1",
	"\r\nto: victim@example.test",
	"\r\nrcpt to: <victim@example.test>",
	"\r\nV100 CAPABILITY",
	" v100 capability imap4rev1",
	" x; rcpt to: <victim@example.test>",
	"a\nQUIT\n",
	// 良性输入：族指示器命中但无换行锚点。
	"location: https://example.test/page",
	"content-type: application/json",
	"/api/fetch?name=alice",
	"please quit the session",
	"select the plan you like",
	// 良性输入：含换行与冒号、但不含任何响应头名的普通 JSON / 表单正文。
	"{\n\"a\": 1,\n\"b\": 2\n}",
	"a=1\nb=2",
}

/**
 * TestCRLFPatternGatesAreNecessaryConditions 验证每条 CRLF 规则的必要条件门
 * 都真的是「正则可命中」的必要条件：只要正则命中，门就必须通过。
 *
 * 该不变量是性能优化不引入漏检的形式化保证——门失败只能发生在正则必然
 * 不命中的输入上。
 */
func TestCRLFPatternGatesAreNecessaryConditions(t *testing.T) {
	for _, payload := range crlfGatePayloads {
		for _, p := range crlfPatterns {
			if !p.re.MatchString(payload) {
				continue
			}
			gate, exists := owaspPatternGates[p.id]
			if !exists {
				continue
			}
			if !gate.passes(payload) {
				t.Fatalf("gate for %s rejects payload %q that the regex matches", p.id, payload)
			}
		}
	}
}

/**
 * TestCRLFPatternGatesPreserveDetection 固定每条 CRLF 规则的最小可命中形态，
 * 防止门写得过窄导致端到端漏检。
 */
func TestCRLFPatternGatesPreserveDetection(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"crlf:001 裸换行 + set-cookie", "x\r\nset-cookie: sid=1"},
		{"crlf:001 裸换行 + 自定义头", "x\nx-evil: 1"},
		{"crlf:002 编码换行 + location", "%0d%0alocation: http://evil"},
		{"crlf:003 双编码换行对", "%0d%0a%0d%0a"},
		{"crlf:007 乱序双编码", "%0d%0a%0d%0aset-cookie: a=1"},
		{"crlf:009 单层残余编码", "%0aset-cookie: a=1"},
		{"crlf:008 邮件收件人", "\r\nto: victim@example.test"},
		{"crlf:008 RCPT TO", "\r\nrcpt to: <victim@example.test>"},
		{"crlf:008 大写协议命令", "\r\nV100 CAPABILITY"},
		{"crlf:010 折叠协议命令", " v100 capability imap4rev1"},
		{"crlf:010 折叠 RCPT TO", " x; rcpt to: <victim@example.test>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := checkCRLF(tc.payload, 2, nil); !ok {
				t.Fatalf("payload %q no longer detected after gate change", tc.payload)
			}
		})
	}
}

/**
 * TestCRLFPatternGatesSkipBenignBroadIndicators 验证换行锚点门在良性输入上
 * 全部失败，从而跳过整组正则；同时断言这些输入不会被误报。
 */
func TestCRLFPatternGatesSkipBenignBroadIndicators(t *testing.T) {
	newlineAnchored := []string{
		"owasp:crlf:001",
		"owasp:crlf:004",
		"owasp:crlf:007",
		"owasp:crlf:009",
	}
	for _, payload := range []string{
		"location: https://example.test/page",
		"content-type: application/json",
		"/api/fetch?name=alice",
		"acquit the plan and capability list",
		"select the plan you like",
		"{\n\"a\": 1,\n\"b\": 2\n}",
		"a=1\nb=2",
	} {
		for _, id := range newlineAnchored {
			if gate, exists := owaspPatternGates[id]; exists && gate.passes(payload) {
				t.Fatalf("gate for %s should reject benign payload %q", id, payload)
			}
		}
		if _, ok := checkCRLF(payload, 2, nil); ok {
			t.Fatalf("benign payload %q must not be flagged", payload)
		}
	}
}

/**
 * TestCRLFHeaderNameGateIsNecessary 验证「响应头名」必要条件组确实是
 * crlf:001/007/009 三条正则可命中的必要条件：只要正则命中，该组必须通过。
 */
func TestCRLFHeaderNameGateIsNecessary(t *testing.T) {
	for _, p := range crlfPatterns {
		switch p.id {
		case "owasp:crlf:001", "owasp:crlf:007", "owasp:crlf:009":
		default:
			continue
		}
		gate, ok := owaspPatternGates[p.id]
		if !ok {
			t.Fatalf("missing gate for %s", p.id)
		}
		if len(gate.anyOf2) == 0 {
			t.Fatalf("gate for %s lost its header-name requirement", p.id)
		}
		for _, payload := range crlfGatePayloads {
			if !p.re.MatchString(payload) {
				continue
			}
			if !gate.anyContained(payload, gate.anyOf2) {
				t.Fatalf("gate for %s rejects payload %q that the regex matches", p.id, payload)
			}
		}
	}
}
