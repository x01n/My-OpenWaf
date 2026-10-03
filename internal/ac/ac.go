package ac

const (
	MaxPatterns   = 512
	MaskWordCount = 8
)

type State struct {
	next    [256]int32
	outputs []int32
}

type Matcher struct {
	states      []State
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

type Builder struct {
	states []State
	count  int32
}

func NewBuilder() *Builder {
	return &Builder{
		states: []State{{}}, // root = state 0
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
	return &Matcher{states: states, numPatterns: b.count}
}

func (m *Matcher) MatchAny(target string) bool {
	if m.Empty() {
		return false
	}
	cur := int32(0)
	nodes := m.states
	for i := 0; i < len(target); i++ {
		cur = nodes[cur].next[target[i]]
		if len(nodes[cur].outputs) > 0 {
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
	cur := int32(0)
	nodes := m.states
	for i := 0; i < len(target); i++ {
		cur = nodes[cur].next[target[i]]
		for _, idx := range nodes[cur].outputs {
			hit.Set(idx)
		}
	}
	return hit
}

func (m *Matcher) MatchMaskSlice(targets []string) Mask {
	var hit Mask
	if m.Empty() {
		return hit
	}
	nodes := m.states
	for _, t := range targets {
		cur := int32(0)
		for i := 0; i < len(t); i++ {
			cur = nodes[cur].next[t[i]]
			for _, idx := range nodes[cur].outputs {
				hit.Set(idx)
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
func (m *Matcher) NumStates() int     { return len(m.states) }
