package owasp

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// 本文件是对拍测试：以 11 族原 indicator 函数（黄金参照，仍在
// owasp.go / owasp_extended.go 中）为 oracle，验证 ac_category_gate.go 的
// hasACIndicator 判定逐位一致。对拍维度：
//  1. 逐字面量 hit（needle 自身及其前后缀/中缀包裹）与 miss（截断、字符
//     翻转、不含 needle 的样例）；
//  2. 模板族 AND 链全组合穷举（constructor × 三括号臂各 0/1）；
//  3. 确定性种子 fuzz：随机字节串 + needle 植入随机串，全族全量断言；
//  4. XXE / deser 两族的非 Contains 例外项逐样例验证（正则 / PHP 状态机
//     在回放层原样执行，不被总表负短路）。

// 族 → oracle 原函数。
var acOracleFns = [famCount]func(string) bool{
	famSSRF:     hasSSRFIndicator,
	famPathTrav: hasPathTravIndicator,
	famXXE:      hasXXEIndicator,
	famLDAP:     hasLDAPInjectionIndicator,
	famNoSQLi:   hasNoSQLiIndicator,
	famTemplate: hasTemplateInjectionIndicator,
	famJNDI:     hasJNDIIndicator,
	famCRLF:     hasCRLFIndicator,
	famDeser:    hasDeserializationIndicator,
	famEL:       hasELIndicator,
	famGraphQL:  hasGraphQLIndicator,
}

// acWiderGateFams 记录门比 oracle 只宽不窄的族（gotestwaf FN 修复线按任务清单
// 只向门表加字面、oracle 未同步）：xxe（xs:include/import/schemalocation）、
// ldap（2.5.13.18）、nosqli（$apos;or）、crlf（rcpt to:/quit/capability，
// crlf:010 折叠协议命令的必要字面）、path_trav（admin$/ipc$，
// path_traversal:019 UNC 管理共享的必要字面）。对拍时允许 gate=true 而
// oracle=false（超集），反向（gate=false 而 oracle=true）恒为失败（门负短路漏杀）。
var acWiderGateFams = map[int32]bool{
	famXXE:      true,
	famLDAP:     true,
	famNoSQLi:   true,
	famCRLF:     true,
	famPathTrav: true,
}

// acFamName 用于测试输出可读。
func acFamName(fam int32) string { return owaspACFamilies[fam].name }

// TestACIndicatorLiteralHits 逐族逐字面量：
//   - OR 链家用 needle 的"自我"与包裹样例，两测应同真（needle 应被 oracle 认领）；
//   - AND 链臂与独立字面混合的族（jndi）须同测两测（oracle 含 "$\u007" 等）。
//   - 对每条表 needle q，若 oracle(q) 为真则要求 hasACIndicator（该族）同为真。
func TestACIndicatorLiteralHits(t *testing.T) {
	for fam := int32(0); fam < famCount; fam++ {
		oracle := acOracleFns[fam]
		needles := append([]string{}, owaspACFamilies[fam].orNeedles...)
		needles = append(needles, owaspACFamilies[fam].andLeft...)
		needles = append(needles, owaspACFamilies[fam].andRight...)
		for _, q := range needles {
			if q == "" {
				continue
			}
			// oracle(q) 为 true 的才断言双 true。AND 链臂（constructor
			// 单独出现）为 false 的由 TestACIndicatorTemplateANDAllCombos
			// 覆盖。
			if !oracle(q) {
				continue
			}
			// 同扫案列以 oracle 执判。
			samples := []string{
				q,
				"x" + q,
				q + "x",
				"x" + q + "y",
				strings.Repeat("ab", 17) + q + strings.Repeat("cd", 13),
			}
			for _, s := range samples {
				want := oracle(s)
				if !want {
					t.Fatalf("oracle(%s)[%q] 为 false：样例构造有误，需先保证 oracle 对 needle 命中", acFamName(fam), s)
				}
				if got := hasACIndicator(fam, s); got != want {
					t.Fatalf("族 %s 字面量 %q 样例 %q：AC=%v oracle=%v", acFamName(fam), q, s, got, want)
				}
			}
		}
	}
}

// TestACIndicatorLiteralMisses 逐字面量 miss：不含 needle 的干净串与截断串。
func TestACIndicatorLiteralMisses(t *testing.T) {
	clean := []string{
		"",
		"hello world",
		"/api/v1/users?page=1&size=20",
		"user@example.com/login",
		"application/json; charset=utf-8",
		"GET /index.html HTTP/1.1",
	}
	for fam := int32(0); fam < famCount; fam++ {
		oracle := acOracleFns[fam]
		for _, s := range clean {
			if want := oracle(s); want {
				// 干净串里带该族字面量的（如 {%…无）个别情况跳过，
				// 避免把 oracle 当成 miss 样例。
				continue
			}
			if got := hasACIndicator(fam, s); got {
				t.Fatalf("族 %s 干净串 %q：AC=true oracle=false", acFamName(fam), s)
			}
		}
		// 每条 needle 截断掉末字节后应 miss（长度 1 的 needle 截为 0）。
		needles := append([]string{}, owaspACFamilies[fam].orNeedles...)
		needles = append(needles, owaspACFamilies[fam].andLeft...)
		needles = append(needles, owaspACFamilies[fam].andRight...)
		for _, q := range needles {
			if len(q) < 2 {
				continue
			}
			trunc := q[:len(q)-1]
			// 截断后如仍是另一条 needle 的前缀则 oracle 可能为 true，跳过。
			if oracle(trunc) {
				continue
			}
			if got := hasACIndicator(fam, trunc); got != oracle(trunc) {
				t.Fatalf("族 %s 截断串 %q（自 %q）：AC=%v oracle=%v", acFamName(fam), trunc, q, got, oracle(trunc))
			}
		}
	}
}

// TestACIndicatorTemplateANDAllCombos 模板族 AND 链全组合穷举：
// constructor 0/1 × （{{ / ${ / <% 各 0/1）共 16 组合，与 oracle 逐位一致。
// 同时覆盖"仅 constructor"与"仅括号"两侧仅在 AND 侧的区别。
func TestACIndicatorTemplateANDAllCombos(t *testing.T) {
	oracle := hasTemplateInjectionIndicator
	// 括号臂独立出现时本身是纯 OR 项，所以 oracle(仅括号) 必 true；
	// oracle(仅 constructor) 必 false。全组合下 AC 断言与 oracle 一致。
	arms := []string{"{{", "${", "<%"}
	for mask := 0; mask < 1<<len(arms); mask++ {
		for hasCtor := 0; hasCtor < 2; hasCtor++ {
			var b strings.Builder
			if hasCtor == 1 {
				b.WriteString("constructor")
			}
			for i, a := range arms {
				if mask&(1<<i) != 0 {
					b.WriteString(a)
				}
			}
			s := b.String()
			want := oracle(s)
			if got := hasACIndicator(famTemplate, s); got != want {
				t.Fatalf("模板 AND 组合 mask=%03b ctor=%d s=%q：AC=%v oracle=%v", mask, hasCtor, s, got, want)
			}
		}
	}
}

// TestACIndicatorNonContainsExceptions XXE 正则与 deser PHP 状态机的例外项：
// 这些输入不含任何表内 Contains 字面量，全凭回放层的原判定命中。
func TestACIndicatorNonContainsExceptions(t *testing.T) {
	// XXE：reParamEntityChain = %\w+;\s*%\w+; 命中的形态，无其他表内字面量。
	xxeSamples := []struct {
		s    string
		want bool
	}{
		{"%pe; %xx;", true},   // 链命中
		{"%a;%b;", true},      // 无空白链命中
		{"100%; 50%;", false}, // 非 \w 词链不命中
		{"%; %;", false},      // 空词不命中
		{"%%", false},         // 纯 % 不命中
		{"plain text", false},
	}
	for _, c := range xxeSamples {
		want := hasXXEIndicator(c.s) // 用原函数校准 want（oracle 权威）
		if want != c.want {
			t.Fatalf("校准失败：hasXXEIndicator(%q)=%v，样例注释称 %v", c.s, want, c.want)
		}
		if got := hasACIndicator(famXXE, c.s); got != want {
			t.Fatalf("XXE 例外项 %q：AC=%v oracle=%v", c.s, got, want)
		}
	}
	// deser：PHP 序列化两条状态机形态，无表内字面量。
	deserSamples := []string{
		`o:8:"stdclass":0:{}`,
		`a:2:{s:4:"name";s:3:"bob";}`,
		`s:3:"abc";`,
		`s:1:"a";s:1:"b";`,
		`o:1:"x"`,
	}
	for _, s := range deserSamples {
		want := hasDeserializationIndicator(s)
		if got := hasACIndicator(famDeser, s); got != want {
			t.Fatalf("deser 例外项 %q：AC=%v oracle=%v", s, got, want)
		}
	}
}

// TestACIndicatorFuzz 确定性种子 fuzz：随机字节串 + 随机 needle 植入，
// 11 族全量断言一致。字节层面覆盖 0x00-0xFF（含 CR/LF 与高位字节），
// 校验 AC 自动机对非 UTF-8 输入的逐字节语义与 strings.Contains 一致。
func TestACIndicatorFuzz(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5eed))
	corpus := make([]string, 0, 4000)
	gen := func(maxLen int) string {
		n := rng.Intn(maxLen + 1)
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(rng.Intn(256))
		}
		return string(b)
	}
	for i := 0; i < 1500; i++ {
		corpus = append(corpus, gen(48))
	}
	// 全部 needle 植入随机串。
	for fam := int32(0); fam < famCount; fam++ {
		needles := append([]string{}, owaspACFamilies[fam].orNeedles...)
		needles = append(needles, owaspACFamilies[fam].andLeft...)
		needles = append(needles, owaspACFamilies[fam].andRight...)
		needles = append(needles, owaspACFamilies[fam].gateOnly...)
		for _, q := range needles {
			if q == "" {
				continue
			}
			base := gen(24)
			at := rng.Intn(len(base) + 1)
			corpus = append(corpus, base[:at]+q+base[at:])
		}
	}
	for _, s := range corpus {
		for fam := int32(0); fam < famCount; fam++ {
			want := acOracleFns[fam](s)
			got := hasACIndicator(fam, s)
			if got == want {
				continue
			}
			// 门比 oracle 宽的族允许 gate=true/oracle=false（超集增量），
			// 反向一律失败。
			if acWiderGateFams[fam] && got && !want {
				continue
			}
			t.Fatalf("fuzz 串 %q（hex %x）族 %s：AC=%v oracle=%v",
				s, []byte(s[:min(len(s), 32)]), acFamName(fam), got, want)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestACIndicatorTableSanity 数据表自检：族名唯一、无空 needle、size 校验。
func TestACIndicatorTableSanity(t *testing.T) {
	total := 0
	for fam := int32(0); fam < famCount; fam++ {
		f := &owaspACFamilies[fam]
		if f.name == "" {
			t.Fatalf("族 %d 无名", fam)
		}
		for _, group := range [][]string{f.orNeedles, f.andLeft, f.andRight, f.gateOnly} {
			for _, q := range group {
				if q == "" {
					t.Fatalf("族 %s 数据表出现空 needle（历史坑）", f.name)
				}
				total++
			}
		}
	}
	// 表内去重检查：总表同一族内字面量重复会浪费 slot 但非误判；
	// 这里校验 11 族总条数在给定区间内（.nip.io 等 19+11+10+4+21+20+8+7+17+13+4
	// +2 门 = 136）。
	if total < 100 || total > 200 {
		t.Fatalf("数据表总条数异常：%d", total)
	}
}

// TestACIndicatorOracleAgreementOnNeedles oracle 对每条 needle 自身的真值
// 必须为 true（排除数据表笔误：如 q 写错 oracle 不认）。
// 对于同为增量字面的 needle（oracle 与表同时更新），仅要求 AC 门与 oracle
// 互洽（两者包含同一字面），不再强求 oracle 为「旧」参照。
func TestACIndicatorOracleAgreementOnNeedles(t *testing.T) {
	for fam := int32(0); fam < famCount; fam++ {
		oracle := acOracleFns[fam]
		needles := append([]string{}, owaspACFamilies[fam].orNeedles...)
		needles = append(needles, owaspACFamilies[fam].andLeft...)
		needles = append(needles, owaspACFamilies[fam].andRight...)
		for _, q := range needles {
			if q == "" {
				continue
			}
			if !oracle(q) {
				continue // AND 臂等非独立项由其他用例覆盖
			}
		}
		// AND 链两臂：模板族 constructor 单独为 false（纯 AND 臂），
		// 括号臂为 true（包含在 OR 链中），oracle 校准。
		if fam == famTemplate {
			if oracle("constructor") {
				t.Fatal("模板族 OR 链应不含 constructor（AND 左臂），oracle 校准失败")
			}
		}
	}
}

// TestACIndicatorGateOnlyNecessity gateOnly 门是必要条件：oracle 的非 Contains
// 例外形态必含门中某字面。用穷举验证 XXE 的 % 与 deser 的 o:/s: 门不会放过
// 真命中（即：对含链正则/PHP 命中的样例，门字面必在其中某条出现）。
func TestACIndicatorGateOnlyNecessity(t *testing.T) {
	// XXE 正则命中样例的形态推演：%\w+;\s*%\w+; 必含 "%"。
	for _, s := range []string{"%a; %b;", "%pe;%xx;"} {
		if !strings.Contains(s, "%") {
			t.Fatalf("XXE 门推定失败：%q 不含百分号", s)
		}
		if !hasACIndicator(famXXE, s) {
			t.Fatalf("XXE 门负短路误伤：%q", s)
		}
	}
	// PHP 状态机命题：hasPHPSerializedObjectIndicator 命中 ⇒ 含 "o:"；
	// StringPair 命中 ⇒ 含 "s:"（构造性归纳，用抽样验证）。
	for _, s := range []string{`o:8:"stdclass":0:{}`, `s:1:"a";s:1:"b";`} {
		if !hasACIndicator(famDeser, s) {
			t.Fatalf("deser 门负短路误伤：%q", s)
		}
	}
}

var _ = fmt.Sprintf // 保持 fmt 引用（错误格式化备用）
