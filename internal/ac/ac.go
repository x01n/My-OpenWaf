package ac

const (
	MaxPatterns   = 1024
	MaskWordCount = 16
)

// acTerminalBit 是扁平转移表里「目标状态含输出」的标记位。
//
// 把终态判断内联进转移值，使匹配内层循环每次转移只需一次内存读；
// 此前每个状态是一个 1048 字节的结构体（256×int32 转移表 + 24 字节
// 切片头），内层循环读 `next[c]` 之后还要再读 `outputs` 切片头，
// 两次读跨越不同 cache line，实测占 MatchAny 内层耗时的绝大部分。
const acTerminalBit uint32 = 1 << 31

// acStateMask 从转移值中取出状态号（低 31 位）。
const acStateMask uint32 = acTerminalBit - 1

// State 是构建期的单状态三元组（转移表 + 输出集）。
// 构建完成后被 Build 物化进 Matcher 的平行数组，运行期不再被引用。
type State struct {
	next    [256]int32
	outputs []int32
}

// Matcher 是构建完成的只读自动机。
type Matcher struct {
	next        []uint32  // 长度 numStates*256；值 = 状态号 | acTerminalBit
	outputs     [][]int32 // 按状态索引，仅终态非空
	numStates   int       // 状态数量
	numPatterns int32
}

func (m *Matcher) Empty() bool { return m == nil || m.numPatterns == 0 }

type Mask struct {
	words [MaskWordCount]uint64
}

func (m *Mask) Set(idx int32) {
	if idx >= 0 && idx < MaxPatterns {
		m.words[idx/64] |= 1 << (uint(idx) % 64)
	}
}

func (m *Mask) Intersects(other *Mask) bool {
	for i := range m.words {
		if m.words[i]&other.words[i] != 0 {
			return true
		}
	}
	return false
}

// Includes 判定 other 的全部位是否都在 m 中（other 为 m 的子集）。
//
// 用于表达「全部必要条件字面都命中」：门控把每条 must 字面量折成一位，
// 命中集合必须完整覆盖该位集合。空 other 恒为真。
func (m *Mask) Includes(other *Mask) bool {
	for i := range m.words {
		if m.words[i]&other.words[i] != other.words[i] {
			return false
		}
	}
	return true
}

// Empty 判定命中集合是否为空。
func (m *Mask) Empty() bool {
	for i := range m.words {
		if m.words[i] != 0 {
			return false
		}
	}
	return true
}

type Builder struct {
	states []State
	count  int32
}

func NewBuilder() *Builder {
	return &Builder{
		states: []State{{}}, // 根状态 = 状态 0
	}
}

func (b *Builder) AddPattern(pattern string) int32 {
	idx := b.count
	b.count++
	cur := int32(0)
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		nxt := b.states[cur].next[c]
		if nxt == 0 {
			nxt = int32(len(b.states))
			b.states = append(b.states, State{})
			b.states[cur].next[c] = nxt
		}
		cur = nxt
	}
	b.states[cur].outputs = append(b.states[cur].outputs, idx)
	return idx
}

func (b *Builder) Build() *Matcher {
	states := b.states
	var queue []int32
	for c := 0; c < 256; c++ {
		if v := states[0].next[c]; v != 0 {
			queue = append(queue, v)
			// states[v].fail = 0 (root), 通过 next 默认值隐含
		}
	}
	fail := make([]int32, len(states))
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if f := fail[cur]; f != 0 {
			states[cur].outputs = append(states[cur].outputs, states[f].outputs...)
		}
		for c := 0; c < 256; c++ {
			nxt := states[cur].next[c]
			if nxt != 0 {
				fail[nxt] = states[fail[cur]].next[c]
				queue = append(queue, nxt)
			} else {
				states[cur].next[c] = states[fail[cur]].next[c]
			}
		}
	}
	// 物化为扁平转移表 + 输出索引：先收集全部输出（终态位需要先于转移表
	// 确定，否则前向引用会读到尚未填充的槽），再逐状态摊平转移表。
	n := len(states)
	outputs := make([][]int32, n)
	for i := 0; i < n; i++ {
		if len(states[i].outputs) > 0 {
			outputs[i] = states[i].outputs
		}
	}
	flat := make([]uint32, n<<8)
	for i := 0; i < n; i++ {
		base := i << 8
		for c := 0; c < 256; c++ {
			v := uint32(states[i].next[c])
			if len(outputs[v]) > 0 {
				v |= acTerminalBit
			}
			flat[base|c] = v
		}
	}
	return &Matcher{next: flat, outputs: outputs, numStates: n, numPatterns: b.count}
}

func (m *Matcher) MatchAny(target string) bool {
	if m.Empty() {
		return false
	}
	next := m.next
	cur := uint32(0)
	for i := 0; i < len(target); i++ {
		cur = next[(cur&acStateMask)<<8|uint32(target[i])]
		if cur&acTerminalBit != 0 {
			return true
		}
	}
	return false
}

func (m *Matcher) MatchMask(target string) Mask {
	var hit Mask
	if m.Empty() {
		return hit
	}
	next, outputs := m.next, m.outputs
	cur := uint32(0)
	for i := 0; i < len(target); i++ {
		cur = next[(cur&acStateMask)<<8|uint32(target[i])]
		if cur&acTerminalBit != 0 {
			for _, idx := range outputs[cur&acStateMask] {
				hit.Set(idx)
			}
		}
	}
	return hit
}

func (m *Matcher) MatchMaskSlice(targets []string) Mask {
	var hit Mask
	if m.Empty() {
		return hit
	}
	next, outputs := m.next, m.outputs
	for _, t := range targets {
		cur := uint32(0)
		for i := 0; i < len(t); i++ {
			cur = next[(cur&acStateMask)<<8|uint32(t[i])]
			if cur&acTerminalBit != 0 {
				for _, idx := range outputs[cur&acStateMask] {
					hit.Set(idx)
				}
			}
		}
	}
	return hit
}

func (m *Mask) MergeFrom(other Mask) {
	for i := range m.words {
		m.words[i] |= other.words[i]
	}
}

func (m *Matcher) NumPatterns() int32 { return m.numPatterns }
func (m *Matcher) NumStates() int     { return m.numStates }
