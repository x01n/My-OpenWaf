package owasp

import (
	"fmt"
	"regexp/syntax"
	"strings"
	"sync"

	"My-OpenWaf/internal/ac"
)

// scanGate 是单个检测目标的一次性扫描证据，供该目标的全部检测器共享。
type scanGate struct {
	hits ac.Mask

	// SQLi 布尔比较缓存：sqli:010/011/036 三条规则对同一目标各扫一遍全串，
	// 首次调用时一次扫描同时算出三类结果，后续规则直接读位。
	sqlBoolDone        bool
	sqlBoolNumeric     bool
	sqlBoolQuoted      bool
	sqlBoolEmptyQuoted bool
}

// ensureSQLBooleanComparisons 惰性执行一次合并扫描并缓存三类结果。
func (g *scanGate) ensureSQLBooleanComparisons(s string) {
	if g.sqlBoolDone {
		return
	}
	g.sqlBoolNumeric, g.sqlBoolQuoted, g.sqlBoolEmptyQuoted = sqlBooleanComparisonKinds(s)
	g.sqlBoolDone = true
}

// sqlBooleanNumeric 返回 sqli:010 的数值布尔比较判定。
func (g *scanGate) sqlBooleanNumeric(s string) bool {
	g.ensureSQLBooleanComparisons(s)
	return g.sqlBoolNumeric
}

// sqlBooleanQuoted 返回 sqli:011 的引号布尔比较判定。
func (g *scanGate) sqlBooleanQuoted(s string) bool {
	g.ensureSQLBooleanComparisons(s)
	return g.sqlBoolQuoted
}

// sqlBooleanEmptyQuoted 返回 sqli:036 的空引号布尔比较判定。
func (g *scanGate) sqlBooleanEmptyQuoted(s string) bool {
	g.ensureSQLBooleanComparisons(s)
	return g.sqlBoolEmptyQuoted
}

// patternGateBits 是单条规则门控条件的位集合形式。
type patternGateBits struct {
	must   ac.Mask           // 必须全部命中
	groups []ac.Mask         // 每个非空组至少命中一位
	check  func(string) bool // 可选：位集合无法表达的位置类必要条件
}

var (
	scanGateM    *ac.Matcher        // 统合扫描自动机
	scanFamBits  [famCount]ac.Mask  // 各族 orNeedles
	scanFamAll   ac.Mask            // 全部族字面量（含 AND 两臂与 gateOnly）
	scanAndLeft  [famCount]ac.Mask  // 各族 AND 左臂（仅模板族非空）
	scanAndRight [famCount]ac.Mask  // 各族 AND 右臂（仅模板族非空）
	scanHintBits map[string]ac.Mask // 规则 id → hint 位
	scanMustBits map[string]ac.Mask // 规则 id → 全部必需字面量（hint ∪ 正则派生）
	scanGateBits map[string]patternGateBits

	// 指示器字面量位集合：把原先散落在 indicators.go 的逐条 strings.Contains
	// 折叠成一次统合扫描的位测试。每组语义见对应 has*Indicator 的注释。
	xssIndicatorBits      ac.Mask // hasXSSIndicator：全部判定项（纯 OR）
	sqliIndicatorBits     ac.Mask // hasSQLiIndicator：全部判定项（纯 OR）
	webshellIndicatorBits ac.Mask // hasWebshellIndicator：全部判定项（纯 OR）
	revshellIndicatorBits ac.Mask // hasRevShellIndicator：全部判定项（纯 OR）
	cmdIndicatorBits      ac.Mask // hasCmdIndicator：无附加条件的判定项
	cmdWordIndicatorBits  ac.Mask // hasCmdIndicator：需配合 shell 命令词的包装器形态

	scanGateOnce  sync.Once
	scanGateReady bool
)

// ZZRuleStats 是临时诊断表：规则 id → [门通过次数, 正则命中次数, 正则耗时ns]。
// 仅在测试里置为非 nil；生产路径恒为 nil，热路径只多一次全局变量判空。
var ZZRuleStats map[string]*[3]int64

func zzRuleGate(id string) {
	if ZZRuleStats == nil {
		return
	}
	v := ZZRuleStats[id]
	if v == nil {
		v = new([3]int64)
		ZZRuleStats[id] = v
	}
	v[0]++
}

func zzRuleHit(id string) {
	if ZZRuleStats == nil {
		return
	}
	v := ZZRuleStats[id]
	if v == nil {
		v = new([3]int64)
		ZZRuleStats[id] = v
	}
	v[1]++
}

func zzRuleCost(id string, ns int64) {
	if ZZRuleStats == nil {
		return
	}
	v := ZZRuleStats[id]
	if v == nil {
		v = new([3]int64)
		ZZRuleStats[id] = v
	}
	v[2] += ns
}

// owaspPatternTables 返回全部按类别组织的规则表。
//
// 新增规则表时必须同步加入此列表，否则该表的 hint 与门控不会进入统合自动机
// （退化为逐规则 strings.Contains，只损失性能，不影响检测结果）。
func owaspPatternTables() [][]owaspPattern {
	return [][]owaspPattern{
		sqliPatterns,
		webshellPatterns,
		revshellPatterns,
		xssPatterns,
		pathTravPatterns,
		ssrfPatterns,
		cmdInjectPatterns,
		xxePatterns,
		ldapiPatterns,
		nosqliPatterns,
		tmplInjectPatterns,
		graphqlPatterns,
		jndiPatterns,
		crlfPatterns,
		exprLangPatterns,
		deserialPatterns,
	}
}
func requiredLiterals(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 || re.Flags&syntax.FoldCase != 0 {
			return nil
		}
		return []string{string(re.Rune)}
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiterals(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min < 1 {
			return nil
		}
		return requiredLiterals(re.Sub[0])
	case syntax.OpConcat:
		var out []string
		var run strings.Builder
		flush := func() {
			if run.Len() > 0 {
				out = append(out, run.String())
				run.Reset()
			}
		}
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral && sub.Flags&syntax.FoldCase == 0 && len(sub.Rune) > 0 {
				run.WriteString(string(sub.Rune))
				continue
			}
			flush()
			out = append(out, requiredLiterals(sub)...)
		}
		flush()
		return out
	}
	return nil
}

// ruleMustLiterals 汇总单条规则的全部必需字面量（hint 与正则派生字面量取并集）。
//
// 二者都是「规则命中则必然出现」的条件，因此可以合并为一个 Includes 门；
// 派生字面量常常比 hint 更长更具体（例如 hint 为 "http" 的规则其正则要求
// "://0"），合并后能把大量无害目标挡在正则之前。
func ruleMustLiterals(p owaspPattern) []string {
	var out []string
	seen := make(map[string]bool, 4)
	push := func(s string) {
		if len(s) < 2 || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	push(p.hint)
	parsed, err := syntax.Parse(p.re.String(), syntax.Perl)
	if err != nil {
		return out
	}
	for _, s := range requiredLiterals(parsed.Simplify()) {
		push(s)
	}
	return out
}

// scanGateInit 构建统合自动机与全部位集合。首帧检测时惰性执行一次。
func scanGateInit() {
	scanGateOnce.Do(func() {
		b := ac.NewBuilder()
		idx := make(map[string]int32, 320)
		add := func(s string) (ac.Mask, bool) {
			var m ac.Mask
			if s == "" {
				return m, false
			}
			i, ok := idx[s]
			if !ok {
				i = b.AddPattern(s)
				idx[s] = i
			}
			m.Set(i)
			return m, true
		}
		orMask := func(needles []string) ac.Mask {
			var out ac.Mask
			for _, q := range needles {
				if m, ok := add(q); ok {
					out.MergeFrom(m)
				}
			}
			return out
		}

		for fam := int32(0); fam < famCount; fam++ {
			f := &owaspACFamilies[fam]
			scanFamBits[fam] = orMask(f.orNeedles)
			scanAndLeft[fam] = orMask(f.andLeft)
			scanAndRight[fam] = orMask(f.andRight)
			scanFamAll.MergeFrom(scanFamBits[fam])
			scanFamAll.MergeFrom(scanAndLeft[fam])
			scanFamAll.MergeFrom(scanAndRight[fam])
			scanFamAll.MergeFrom(orMask(f.gateOnly))
		}

		scanHintBits = make(map[string]ac.Mask, 320)
		for _, table := range owaspPatternTables() {
			for _, p := range table {
				if p.hint == "" {
					continue
				}
				if m, ok := add(p.hint); ok {
					scanHintBits[p.id] = m
				}
			}
		}

		// 规则级必需字面量门：hint 与「从正则语法树派生的必然子串」合并成
		// 一个 Includes 门。派生字面量往往比 hint 更具体，能在正则之前挡掉
		// 大量无害目标；若 needle 预算超出 MaxPatterns 则整体放弃派生部分，
		// 退化为仅 hint 门（只损失性能，不影响正确性）。
		perRuleLits := make(map[string][]string, 320)
		newNeedles := 0
		seenNeedle := make(map[string]bool, 128)
		for _, table := range owaspPatternTables() {
			for _, p := range table {
				lits := ruleMustLiterals(p)
				if len(lits) == 0 {
					continue
				}
				perRuleLits[p.id] = lits
				for _, s := range lits {
					if seenNeedle[s] {
						continue
					}
					seenNeedle[s] = true
					if _, ok := idx[s]; !ok {
						newNeedles++
					}
				}
			}
		}
		if len(idx)+newNeedles <= ac.MaxPatterns {
			scanMustBits = make(map[string]ac.Mask, len(perRuleLits))
			for id, lits := range perRuleLits {
				scanMustBits[id] = orMask(lits)
			}
		}

		scanGateBits = make(map[string]patternGateBits, len(owaspPatternGates))
		for id, g := range owaspPatternGates {
			// 折叠门控在字符串层面判定（containsASCIIFold），不进自动机。
			if g.fold {
				continue
			}
			var bits patternGateBits
			bits.check = g.check
			for _, s := range g.musts {
				if m, ok := add(s); ok {
					bits.must.MergeFrom(m)
				}
			}
			for _, group := range [][]string{g.anyOf, g.anyOf2, g.anyOf3} {
				if len(group) == 0 {
					continue
				}
				bits.groups = append(bits.groups, orMask(group))
			}
			scanGateBits[id] = bits
		}

		// 指示器字面量：原实现逐条 strings.Contains，占 OWASP 扫描 CPU 的
		// 很大比例。它们都与规则门控共享同一个检测目标，因此一并进入本
		// 自动机，运行期退化为一次（或少数几次）位集合相交测试。
		xssLits := make([]string, 0, len(xssIndicatorLiteralBytes)+len(xssIndicatorExtraLiterals))
		xssLits = append(xssLits, xssIndicatorLiteralBytes...)
		xssLits = append(xssLits, xssIndicatorExtraLiterals...)
		xssIndicatorBits = orMask(xssLits)
		sqliIndicatorBits = orMask(sqliIndicatorLiterals)
		webshellIndicatorBits = orMask(webshellIndicatorLiterals)
		revshellIndicatorBits = orMask(revshellIndicatorLiterals)
		cmdIndicatorBits = orMask(cmdIndicatorLiterals)
		cmdWordIndicatorBits = orMask(cmdWordIndicatorLiterals)

		// SQLi 信号字段：原实现逐字段 strings.Contains，41 个字段要重复
		// 扫描同一目标串。并入统合自动机后每个字段退化为一次位集合查询。
		for i, lits := range sqliSignalLiterals {
			for _, lit := range lits {
				if m, ok := add(lit); ok {
					sqliSignalMasks[i].MergeFrom(m)
				}
			}
		}
		sqliUnionSelectBits = orMask([]string{"unionselect"})
		sqliTautologyShortcutBits = orMask([]string{"and1=1", "or1=1"})

		if len(idx) > ac.MaxPatterns {
			// 静态模式集超出 Mask 位宽时必须立即失败：Set 对越界索引静默
			// 丢弃，会直接表现为漏检。扩容量只需改 ac.MaxPatterns/
			// MaskWordCount 两个常量。
			panic(fmt.Sprintf("owasp: 统合扫描自动机需要 %d 个模式，超过 ac.MaxPatterns=%d", len(idx), ac.MaxPatterns))
		}

		scanGateM = b.Build()
		scanGateReady = true
	})
}

// scanGateOf 对目标串执行一次统合扫描，返回该目标的共享证据。
//
// @param s 归一化后的检测目标（检测主循环内均为小写，但本函数不做该假设：
//
//	模式与判定都是逐字节精确匹配）。
//
// @return 共享证据；调用方在目标扫描结束后即丢弃。
func scanGateOf(s string) *scanGate {
	scanGateInit()
	return &scanGate{hits: scanGateM.MatchMask(s)}
}

// firstGate 返回调用方传入的统合扫描证据；未提供时按 s 现场构建。
//
// 调用方必须保证传入的 gate 是对同一目标串 s 构建的；生产路径中
// gate 由 scanGateOf(normalized) 生成后一路传递，满足该前提。
//
// @param s     检测目标串。
// @param gates 可选的门控证据（0 或 1 个）。
// @return 可直接用于位测试的扫描证据。
func firstGate(s string, gates []*scanGate) *scanGate {
	if len(gates) > 0 && gates[0] != nil {
		return gates[0]
	}
	return scanGateOf(s)
}

// hit 判定某个位集合是否至少命中一位。
func (g *scanGate) hit(m *ac.Mask) bool {
	return g.hits.Intersects(m)
}

// family 判定族指示器是否命中，语义与 hasACIndicator 一致。
//
// @param fam 族编号。
// @param s   原始目标串，供 XXE / 反序列化族的兜底判定使用。
// @return 族指示器是否命中。
func (g *scanGate) family(fam int32, s string) bool {
	switch fam {
	case famXXE:
		// 兜底正则的 "%" 必要门只以 gateOnly 形式存在于总表，故先要求总表命中。
		if !g.hit(&scanFamAll) {
			return false
		}
		if g.hit(&scanFamBits[fam]) {
			return true
		}
		return reParamEntityChain.MatchString(s)
	case famDeser:
		// 同理："o:"/"s:" 是 PHP 序列化状态机的必要条件。
		if !g.hit(&scanFamAll) {
			return false
		}
		if g.hit(&scanFamBits[fam]) {
			return true
		}
		return hasPHPSerializedObjectIndicator(s) || hasPHPSerializedStringPairIndicator(s)
	}
	if g.hit(&scanFamBits[fam]) {
		return true
	}
	// 模板族 AND 链：constructor ∧ ({{|${|<%)。
	return g.hit(&scanAndLeft[fam]) && g.hit(&scanAndRight[fam])
}

// hintPass 判定规则的 hint 前置条件是否满足。
//
// @param p 规则。
// @param s 目标串，仅在 hint 未进入统合自动机时用于回退子串比较。
// @return 是否允许对该目标执行该规则的正则。
func (g *scanGate) hintPass(p owaspPattern, s string) bool {
	if p.hint == "" {
		return true
	}
	if m, ok := scanHintBits[p.id]; ok {
		return g.hit(&m)
	}
	return strings.Contains(s, p.hint)
}

// patternGate 判定规则的全部必要条件门（hint + 门控）。
//
// @param p 规则。
// @param s 目标串，供折叠门控与未入自动机的 hint 回退。
// @return 门是否通过；未通过则该规则不可能命中。
func (g *scanGate) patternGate(p owaspPattern, s string) bool {
	// 必需字面量门：hint ∪ 正则派生字面量，一次 Includes 完成。
	// 该集合的每一项都是「规则命中则必然出现」的条件，故与逐项判定等价，
	// 且派生字面量常常更长更具体，能把无害目标挡在正则之前。
	if m, ok := scanMustBits[p.id]; ok {
		if !g.hits.Includes(&m) {
			return false
		}
	} else if !g.hintPass(p, s) {
		return false
	}
	if bits, ok := scanGateBits[p.id]; ok {
		if !g.hits.Includes(&bits.must) {
			return false
		}
		for i := range bits.groups {
			if !g.hit(&bits.groups[i]) {
				return false
			}
		}
		return bits.check == nil || bits.check(s)
	}
	// 折叠门控保留字符串层面判定（大小写不敏感语义无法用精确位集合表达）。
	if gate, ok := owaspPatternGates[p.id]; ok {
		return gate.passes(s)
	}
	return true
}

// patternGateMustsOnly 只判定规则的正则派生必需字面量门。
//
// hint 与派生字面量同属「正则命中的必要条件」。对 shouldScan* 已自行
// 完成 hint 与结构判定的检测器，这里只补上派生部分，避免重复 hint 检查。
//
// @param p 规则。
// @return 必需字面量是否全部出现。
func (g *scanGate) patternGateMustsOnly(p owaspPattern) bool {
	if m, ok := scanMustBits[p.id]; ok {
		return g.hits.Includes(&m)
	}
	return true
}

// patternGateBitsOnly 只判定规则的字面量门（scanGateBits /
// owaspPatternGates），不叠加 hint 与正则派生字面量门。
//
// 供已有独立预检、暂不启用派生门的检测器使用，避免与自身 hintPass
// 重复执行，同时让新增门控共享统合自动机的位集合。
//
// @param p 规则。
// @param s 目标串，供折叠门控与 check 回退。
// @return 门是否通过。
func (g *scanGate) patternGateBitsOnly(p owaspPattern, s string) bool {
	if bits, ok := scanGateBits[p.id]; ok {
		if !g.hits.Includes(&bits.must) {
			return false
		}
		for i := range bits.groups {
			if !g.hit(&bits.groups[i]) {
				return false
			}
		}
		return bits.check == nil || bits.check(s)
	}
	if gate, ok := owaspPatternGates[p.id]; ok {
		return gate.passes(s)
	}
	return true
}
