package score

// Hit 是一次判据命中的记录（归因用）。
type Hit struct {
	ID     string
	Weight int
	Detail string // 可选
}

// seen 是查重索引的值位掩码：同一 ID 可以在分数通道与危险通道上各占用一次，
// 两条通道各自去重，互不吞并。位掩码而非两个 map，是为了让 Add 与 MarkDanger
// 共享同一份 map 实例（一个请求一份，降低分配与哈希开销）。
const (
	seenScored uint8 = 1 << iota // 该 ID 已计入分数通道（Add/AddDetail）
	seenDanger                   // 该 ID 已登记为危险标记（MarkDanger）
)

type Accumulator struct {
	total     int
	threshold int
	hits      []Hit
	seen      map[string]uint8 // 惰性分配：仅当出现重复 ID 时才建

	// 危险标记来源 ID，按标记顺序排列。危险标记与分数正交：不计入 total，
	// 也不受 weight<=0 忽略规则约束。切片不经预分配——危险标记只出现在
	// 攻击流量上，不应让常规路径为这条罕见路径垫付容量。
	dangerIDs []string

	// 归因：使总分首次跨过阈值的最后一条规则及其加入后的累计分。
	// 用独立字段而非 *Hit，是为了让过阈路径也不产生任何堆分配。
	attributionID     string
	attributionScore  int
	attributionLocked bool
}

// initialHitsCap 是 hits 的初始容量：一条规则集里同时计分的判据通常为个位数，
// 预置容量可让 Add 在常见路径上完全零分配。
const initialHitsCap = 8

// NewAccumulator 创建一个阈值判定累加器。threshold 为闭区间阈值，
// 即 total >= threshold 视为过阈（与 OWASP 现有语义一致）。
func NewAccumulator(threshold int) *Accumulator {
	return &Accumulator{
		threshold: threshold,
		hits:      make([]Hit, 0, initialHitsCap),
	}
}

// Add 记入一条命中判据的权重。同一 ID 重复调用只计一次。
//
// weight <= 0 时忽略：规则配置错误给出的零分/负分既不应产生无贡献的命中
// 记录（归因会指向一条零分规则而误导排查），也不应把总分打成负数后吞掉
// 后续规则的真命中。该忽略规则只作用于计分通道，不影响 MarkDanger。
func (a *Accumulator) Add(id string, weight int) { a.add(id, weight, "") }

// AddDetail 与 Add 相同，但额外记录归因明细。重复 ID 只保留首次的明细，
// 后续调用既不计分也不覆盖明细。
func (a *Accumulator) AddDetail(id string, weight int, detail string) {
	a.add(id, weight, detail)
}

func (a *Accumulator) add(id string, weight int, detail string) {
	if weight <= 0 {
		return
	}
	if !a.claim(id, seenScored) {
		return
	}
	a.hits = append(a.hits, Hit{ID: id, Weight: weight, Detail: detail})
	a.total += weight
	// 归因只认首次跨阈，此后追加的命中不得改写。
	if !a.attributionLocked && a.total >= a.threshold {
		a.attributionLocked = true
		a.attributionID = id
		a.attributionScore = a.total
	}
}

// MarkDanger 标记该请求已被判定为危险。危险标记与分数正交：
// 它不受权重影响，也不会被低分模块稀释。消费方据此保证
// 「只要危险就必须终止」，具体档位由总分决定。
//
// 与分数通道各自去重：同一 ID 在任一通道上重复调用都不产生任何效果
// （分数侧只计一次分，危险侧只记一次）。危险标记不计入 Total，也不受
// weight<=0 忽略规则约束——标记本身没有权重概念。
func (a *Accumulator) MarkDanger(id string) { a.mark(id) }

// mark 登记一次危险标记，去重语义见 MarkDanger。
func (a *Accumulator) mark(id string) {
	if !a.claim(id, seenDanger) {
		return
	}
	a.dangerIDs = append(a.dangerIDs, id)
}

// Dangerous 报告是否已存在危险标记。危险标记一旦存在就必须终止请求，
// 该结论与 Total 无关。
func (a *Accumulator) Dangerous() bool { return len(a.dangerIDs) > 0 }

// DangerIDs 返回全部危险标记的来源 ID，按标记顺序排列。
// 返回的是内部切片的别名（零分配）；调用方只读，不得修改，也不得在
// Reset 之后继续持有。
func (a *Accumulator) DangerIDs() []string { return a.dangerIDs }

// claim 在 ID 上尚未设置 mask 位时设置之并返回 true；已设置则返回 false。
// 分数通道（seenScored）与危险通道（seenDanger）共用同一份 seen map，
// 各自独立去重，互不吞并。
func (a *Accumulator) claim(id string, mask uint8) bool {
	if a.seen != nil {
		if a.seen[id]&mask != 0 {
			return false
		}
		a.seen[id] |= mask
		return true
	}
	if a.hasClaim(id, mask) {
		// 首次出现重复 ID：建立索引并回填已有标记，后续查重走 O(1)。
		a.buildSeen()
		return false
	}
	return true
}

// hasClaim 线性查找某一通道上是否已占用该 ID，仅在尚未建立 seen 索引时使用。
// 记录数通常为个位数，线性扫描成本远低于 map 的分配与哈希开销。
func (a *Accumulator) hasClaim(id string, mask uint8) bool {
	if mask == seenScored {
		for i := range a.hits {
			if a.hits[i].ID == id {
				return true
			}
		}
		return false
	}
	for _, marked := range a.dangerIDs {
		if marked == id {
			return true
		}
	}
	return false
}

// buildSeen 建立查重索引并回填两条通道上已占用的 ID。
func (a *Accumulator) buildSeen() {
	a.seen = make(map[string]uint8, len(a.hits)+len(a.dangerIDs)+1)
	for i := range a.hits {
		a.seen[a.hits[i].ID] |= seenScored
	}
	for _, id := range a.dangerIDs {
		a.seen[id] |= seenDanger
	}
}

// Total 返回当前累计分。
func (a *Accumulator) Total() int { return a.total }

// Threshold 返回当前阈值。
func (a *Accumulator) Threshold() int { return a.threshold }

// SetThreshold 调整判定阈值。
//
// 若新阈值高于当前总分，既有归因锁定对应的跨阈点在新阈值下不再成立，
// 锁定被清除，等待后续规则重新跨阈；否则若总分已达标而尚未锁定，
// 归因锁定到最后一条已计分规则（它把分数推到了当前水平），hits 为空时
// 保持未锁定，Attribution 返回空 ID。
func (a *Accumulator) SetThreshold(t int) {
	a.threshold = t
	if a.total < t {
		a.clearAttribution()
		return
	}
	if a.attributionLocked {
		return
	}
	if n := len(a.hits); n > 0 {
		a.attributionLocked = true
		a.attributionID = a.hits[n-1].ID
		a.attributionScore = a.total
	}
}

// clearAttribution 清除归因锁定，回到「尚未有规则跨阈」的状态。
func (a *Accumulator) clearAttribution() {
	a.attributionID = ""
	a.attributionScore = 0
	a.attributionLocked = false
}

// Exceeded 报告总分是否达到阈值，等价于 total >= threshold（闭区间）。
func (a *Accumulator) Exceeded() bool { return a.total >= a.threshold }

// Hits 返回本次累加已计分的命中记录，按计分顺序排列。
// 返回的是内部切片的别名（零分配）；调用方只读，不得修改，也不得在
// Reset 之后继续持有。
func (a *Accumulator) Hits() []Hit { return a.hits }

// Attribution 返回使总分首次跨过阈值的最后一条规则的 ID 与该规则加入后的
// 累计分；未过阈或尚无规则锁定时返回 ("", 0)。
//
// 语义澄清（对现有 OWASP checkNoSQLi 归因缺陷的修正）：现有实现取「首个
// 命中的规则」作为归因，当该规则恒被 FP 抑制器拦下时，整类判定被丢弃，
// 后续规则的分数贡献随之被吞掉。这里改为在累加过程中一旦 total >= threshold
// 就立即锁定当前规则，归因始终指向真正把总分推过阈值的那一条。
func (a *Accumulator) Attribution() (string, int) {
	if !a.attributionLocked || !a.Exceeded() {
		return "", 0
	}
	return a.attributionID, a.attributionScore
}

// Reset 清空累加状态与危险标记以便复用。hits、dangerIDs 与 seen 的容量保留，
// 但会清除元素引用，避免池化复用时长期持有上一次请求的字符串。
// 注意：hits 与 dangerIDs 都是就地清空并截断的，Reset 之后调用方不得再使用
// 先前 Hits() / DangerIDs() 返回的切片——其中元素已被清零。
func (a *Accumulator) Reset() {
	a.total = 0
	if a.hits != nil {
		clear(a.hits)
		a.hits = a.hits[:0]
	}
	if a.dangerIDs != nil {
		clear(a.dangerIDs)
		a.dangerIDs = a.dangerIDs[:0]
	}
	if a.seen != nil {
		clear(a.seen)
	}
	a.clearAttribution()
}

// Count 子条件计数裁决：results 中 true 的个数 >= min 即成立。
// min <= 0 时恒成立；min > len(results) 时恒不成立。
func Count(min int, results []bool) bool {
	if min <= 0 {
		return true
	}
	n := 0
	for _, ok := range results {
		if ok {
			n++
			if n >= min {
				return true
			}
		}
	}
	return false
}
