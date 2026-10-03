package owasp

import (
	"strings"
	"testing"
)

// 本文件是 sqliGate / hasSuspicious 早停链的微基准。
// 样本按奇偶交替两个变体，避免编译器把 inspect 常量化；结果落到包级
// sink 变量，防止整个循环被优化消去。

var (
	gateBenchSink    bool
	gateBenchSinkInt int
)

// benchSQliGateMiss 以不带信号推进字节的良性串跑「信号计算 + 全规则门」，
// 与 nextSQLiHit 命中路径前的生产调用形状一致（hint 门 + 信号门后 break）。
func benchSQliGateMiss(b *testing.B, sample string) {
	b.Helper()
	for i := 0; i < b.N; i++ {
		in := sample
		if i%2 == 1 {
			in = sample + "-" + sample
		}
		signals := collectSQLiPatternSignals(in)
		hit := false
		for _, p := range sqliPatterns {
			if p.hint != "" && !strings.Contains(in, p.hint) {
				continue
			}
			if shouldScanSQLiPatternWithSignals(in, p, signals) {
				hit = true
				break
			}
		}
		gateBenchSink = hit
	}
}

// benchSQliGateHit 以恶意串跑同一路径，hit 命中后 break。
func benchSQliGateHit(b *testing.B, sample string) {
	b.Helper()
	for i := 0; i < b.N; i++ {
		in := sample
		if i%2 == 1 {
			in = sample + " "
		}
		signals := collectSQLiPatternSignals(in)
		hit := false
		for _, p := range sqliPatterns {
			if p.hint != "" && !strings.Contains(in, p.hint) {
				continue
			}
			if shouldScanSQLiPatternWithSignals(in, p, signals) {
				hit = true
				break
			}
		}
		gateBenchSink = hit
	}
}

func BenchmarkSQliGateMiss(b *testing.B) {
	b.Run("plain", func(b *testing.B) {
		benchSQliGateMiss(b, "hello world this is a normal request")
	})
	b.Run("long-alpha", func(b *testing.B) {
		benchSQliGateMiss(b, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz")
	})
	b.Run("long-noisy", func(b *testing.B) {
		benchSQliGateMiss(b, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	})
}

func BenchmarkSQliGateHit(b *testing.B) {
	b.Run("union-select", func(b *testing.B) {
		benchSQliGateHit(b, "id=1 union select 1,2,3--")
	})
	b.Run("chr-chain", func(b *testing.B) {
		benchSQliGateHit(b, "id=chr(65)+chr(66)+chr(67)")
	})
	b.Run("all-visible", func(b *testing.B) {
		benchSQliGateHit(b, "abc or and select xp_ like")
	})
}

// benchHasSuspiciousMiss 干净串走 hasSuspiciousContent（字符表扫描 + keywords 掩码）。
func benchHasSuspiciousMiss(b *testing.B, sample string) {
	b.Helper()
	for i := 0; i < b.N; i++ {
		in := sample
		if i%2 == 1 {
			in = sample + "x"
		}
		gateBenchSink = hasSuspiciousContent(in)
	}
}

// benchHasSuspiciousHit 关键字命中串走同一入口，落到组内 Contains 链。
func benchHasSuspiciousHit(b *testing.B, sample string) {
	b.Helper()
	for i := 0; i < b.N; i++ {
		in := sample
		if i%2 == 1 {
			in = sample + " "
		}
		gateBenchSink = hasSuspiciousContent(in)
	}
}

func BenchmarkHasSuspiciousMiss(b *testing.B) {
	b.Run("plain-space-chars", func(b *testing.B) {
		benchHasSuspiciousMiss(b, "hello world this is a normal request")
	})
	b.Run("pure-alpha", func(b *testing.B) {
		benchHasSuspiciousMiss(b, "abcdefghijklmnopqrstuvwxyz1234567890")
	})
}

func BenchmarkHasSuspiciousHit(b *testing.B) {
	b.Run("select-space", func(b *testing.B) {
		benchHasSuspiciousHit(b, "x select * from users")
	})
	b.Run("union-space", func(b *testing.B) {
		benchHasSuspiciousHit(b, "x union all select")
	})
}

// TestBenchSanityGate 固定形状正反面 quick-check，避免基准函数本身写歪。
func TestBenchSanityGate(t *testing.T) {
	if !hasSuspiciousContent("select ") {
		t.Fatal("select 空格必须命中 hasSuspiciousContent")
	}
	if hasSuspiciousContent("abc") {
		t.Fatal("abc 不应命中 hasSuspiciousContent")
	}
	signals := collectSQLiPatternSignals("id=union select")
	if !shouldScanSQLiPatternWithSignals("id=union select", findSQLiPatternForTest("owasp:sqli:028"), signals) {
		t.Fatal("union select 样本应推进 sqli:028 信号门")
	}
	gateBenchSinkInt++
}
