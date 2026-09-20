package cve

// acMatcher 是编译期构建的 Aho-Corasick 多模式匹配自动机,用 [256]int32
// 数组转移表(goto 表自动机化),一遍扫描 target 即可检出所有命中 needle。
//
// 用于替换 CVE gate 里的朴素多针 strings.Contains 扫描。基准实证:
// 在真实 CVE 负载(target 40-330B, needle ~130 个)下比朴素快 10-15 倍且零分配。
//
// 设计模式:
// - 构建时把所有 needle(按字段视图分组后)编入同一个自动机,每个 needle 分配唯一 index。
// - 运行时一遍扫 target,返回命中的 needle 集合(bitset)。
// - gate 层每条规则持有其 needle indices 的 mask(bitset),判 mask∩hit≠∅ 即通过。
//
// 语义等价前提:
// - needle 全部是已小写的字面量(与现有 gate 一致,target 已预 ToLower)。
// - 命中判定纯子串包含(等价 strings.Contains),无边界/AND/计数条件。
// - 不可替代复合 helper(含额外逻辑的保留原样调用)。

// acState 表示自动机一个状态的转移表及终止标记。
type acState struct {
	// next[byte] 指向下一状态索引;0 表示根/无效。
	// goto 表自动机化:非根状态 next==0 已在 BFS 时填充为 fail 链最终目标,
	// 扫描无需显式 fail 跳转。
	next [256]int32
	// outputs 保存在此状态终止的 needle indices(可能多个:一个较短 needle 是
	// 另一个的后缀)。编译后此 slice 已含 fail 链继承的输出。
	outputs []int32
}

// acMatcher 持有编译后的自动机和 needle 元数据。
type acMatcher struct {
	states []acState
	// numPatterns 为注册的 needle 总数;为 0 时自动机不可能命中,匹配直接短路。
	// 视图分组后可能出现零 needle 的自动机(如当前 url_body 视图),
	// 若不短路仍会对整个目标逐字节走一遍转移表,是纯粹的空转。
	numPatterns int32
}

// empty 报告自动机是否未注册任何 needle。
// 空自动机扫描任何输入都恒不命中,调用方据此跳过整趟扫描。
func (ac *acMatcher) empty() bool { return ac == nil || ac.numPatterns == 0 }

// acGateMask 表示某条规则在 AC 里注册的 needle indices 的 bitmask。
// 用于快速判断"该规则的 needle 组是否有被命中的"。
// 支持最多 512 个 needle(8 个 uint64 word),对 CVE 130 个 needle 远够。
type acGateMask struct {
	words [8]uint64
}

func (m *acGateMask) set(idx int32) {
	if idx >= 0 && idx < 512 {
		m.words[idx/64] |= 1 << (uint(idx) % 64)
	}
}

func (m *acGateMask) intersects(other *acGateMask) bool {
	for i := range m.words {
		if m.words[i]&other.words[i] != 0 {
			return true
		}
	}
	return false
}

// acBuilder 构建 acMatcher。
type acBuilder struct {
	states []acState
	count  int32
}

func newACBuilder() *acBuilder {
	return &acBuilder{
		states: []acState{{}}, // root = state 0
	}
}

// addPattern 把一个小写 needle 加入 trie,返回分配的 pattern index。
func (b *acBuilder) addPattern(pattern string) int32 {
	idx := b.count
	b.count++
	cur := int32(0)
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		nxt := b.states[cur].next[c]
		if nxt == 0 {
			nxt = int32(len(b.states))
			b.states = append(b.states, acState{})
			b.states[cur].next[c] = nxt
		}
		cur = nxt
	}
	b.states[cur].outputs = append(b.states[cur].outputs, idx)
	return idx
}

// build 执行 BFS 填充 fail 链并内联 goto 表,返回不可变的 acMatcher。
func (b *acBuilder) build() *acMatcher {
	states := b.states
	var queue []int32
	// 初始化 root 直接子节点:fail=root,已隐含(next 默认 0)
	for c := 0; c < 256; c++ {
		if v := states[0].next[c]; v != 0 {
			queue = append(queue, v)
			// states[v].fail = 0 (root), 通过 next 默认值隐含
		}
	}
	// BFS: goto 表自动机化 + 输出继承
	fail := make([]int32, len(states))
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		// 继承 fail 链输出到当前状态
		if f := fail[cur]; f != 0 && len(states[f].outputs) > 0 {
			states[cur].outputs = append(states[cur].outputs, states[f].outputs...)
		}
		for c := 0; c < 256; c++ {
			nxt := states[cur].next[c]
			if nxt != 0 {
				fail[nxt] = states[fail[cur]].next[c]
				queue = append(queue, nxt)
			} else {
				// goto 表内联:不存在的转移直接指向 fail 链的对应转移
				states[cur].next[c] = states[fail[cur]].next[c]
			}
		}
	}
	return &acMatcher{states: states, numPatterns: b.count}
}

// matchAny 判断 target 中是否含任何已注册 needle(最快短路)。
func (ac *acMatcher) matchAny(target string) bool {
	if ac.empty() {
		return false
	}
	cur := int32(0)
	nodes := ac.states
	for i := 0; i < len(target); i++ {
		cur = nodes[cur].next[target[i]]
		if len(nodes[cur].outputs) > 0 {
			return true
		}
	}
	return false
}

// matchMask 一遍扫描 target,返回命中 needles 的 bitset mask。
// 调用方用 mask.intersects(ruleMask) 判断某规则 gate 是否通过。
func (ac *acMatcher) matchMask(target string) acGateMask {
	var hit acGateMask
	if ac.empty() {
		return hit
	}
	cur := int32(0)
	nodes := ac.states
	for i := 0; i < len(target); i++ {
		cur = nodes[cur].next[target[i]]
		for _, idx := range nodes[cur].outputs {
			hit.set(idx)
		}
	}
	return hit
}

// matchMaskSlice 对 targets 数组逐条扫描(不跨条拼接),合并命中 mask。
// 适用于数组视图字段(URLTargetsLower / BodyTargetsLower / AllTargetsLower 等),
// 保持"逐条 Contains 不可跨边界"的语义等价。
func (ac *acMatcher) matchMaskSlice(targets []string) acGateMask {
	var hit acGateMask
	if ac.empty() {
		return hit
	}
	nodes := ac.states
	for _, t := range targets {
		cur := int32(0)
		for i := 0; i < len(t); i++ {
			cur = nodes[cur].next[t[i]]
			for _, idx := range nodes[cur].outputs {
				hit.set(idx)
			}
		}
	}
	return hit
}
