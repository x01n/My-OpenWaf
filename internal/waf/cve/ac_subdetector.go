package cve

import "strings"

// subDetectorNeedleEntry 定义一条子检测器 gate 的 needle 组。
type subDetectorNeedleEntry struct {
	cveID   string
	target  string // "url","body","url_body","header","cookie","all"
	needles []string
}

// subDetectorHits 一次性计算的各视图 AC 命中 mask,在 CVEDetector.DetectFirst
// 入口对 CVERequest 计算一次,传给所有四子检测器复用。
type subDetectorHits struct {
	all     acGateMask
	url     acGateMask
	body    acGateMask
	header  acGateMask
	cookie  acGateMask
	urlBody acGateMask
}

// subDetectorACSet 持有按字段视图分组的 AC 自动机与规则 mask。
type subDetectorACSet struct {
	allAC     *acMatcher
	urlAC     *acMatcher
	bodyAC    *acMatcher
	headerAC  *acMatcher
	cookieAC  *acMatcher
	urlBodyAC *acMatcher

	// masks[kindIndex(target)] 是单一 target 视图上 (cveID → mask) 的索引,
	// mask 值为构建期一次性固定、只读共享的位图。
	masks [6]subDetectorMaskKind
}

// subDetectorMaskKind 是单一 target 视图上 (cveID → *acGateMask) 的索引。
// mask 值为构建期固定、此后只读共享,绝不写回。
type subDetectorMaskKind struct {
	mask map[string]*acGateMask
}

var globalSubDetectorAC subDetectorACSet

func init() {
	buildSubDetectorAC()
}

func buildSubDetectorAC() {
	type viewBuilder struct {
		b       *acBuilder
		byCVEID map[string]*acGateMask
	}
	views := []*viewBuilder{
		{b: newACBuilder()}, {b: newACBuilder()}, {b: newACBuilder()},
		{b: newACBuilder()}, {b: newACBuilder()}, {b: newACBuilder()},
	}

	// 把 subDetectorNeedleEntries 归入所属视图,并按 (cveID+"|"+target) 与旧
	// masks map 相同的键空间合并 mask。旧实现用字符串键;这里改按归一化
	// 视图归组,同 cveID 在该视图内的多个条目共享 mask。
	// 实测数据(60 条目)证实每个 (cveID, target) 组合唯一,两种归组完全等价。
	for _, entry := range subDetectorNeedleEntries {
		vb := views[subDetectorMaskKindIndex(entry.target)]
		if vb.byCVEID == nil {
			vb.byCVEID = make(map[string]*acGateMask)
		}
		mask, ok := vb.byCVEID[entry.cveID]
		if !ok {
			m := acGateMask{}
			mask = &m
			vb.byCVEID[entry.cveID] = mask
		}
		for _, n := range entry.needles {
			idx := vb.b.addPattern(n)
			mask.set(idx)
		}
	}

	set := subDetectorACSet{
		allAC:     views[0].b.build(),
		urlAC:     views[1].b.build(),
		bodyAC:    views[2].b.build(),
		headerAC:  views[3].b.build(),
		cookieAC:  views[4].b.build(),
		urlBodyAC: views[5].b.build(),
	}
	for i, vb := range views {
		set.masks[i] = subDetectorMaskKind{mask: vb.byCVEID}
	}
	globalSubDetectorAC = set
}

// subDetectorMaskKindIndex 把规则 target 归一到六个视图片的下标;未知目标
// 落入 0("all" 视图),与旧实现 buildSubDetectorAC 的 unknown→views["all"]
// 行为一致。
func subDetectorMaskKindIndex(target string) int {
	switch target {
	case "all":
		return 0
	case "url":
		return 1
	case "body":
		return 2
	case "header":
		return 3
	case "cookie":
		return 4
	case "url_body":
		return 5
	}
	return 0
}

// computeSubDetectorHits 对 CVERequest 一次性计算所有视图的 AC hit mask。
func computeSubDetectorHits(req *CVERequest) subDetectorHits {
	var h subDetectorHits
	ac := &globalSubDetectorAC
	h.all = ac.allAC.matchMaskSlice(req.AllTargetsLower)
	h.url = ac.urlAC.matchMaskSlice(req.URLTargetsLower)
	h.body = ac.bodyAC.matchMaskSlice(req.BodyTargetsLower)
	h.header = ac.headerAC.matchMaskSlice(req.HeaderTargetsLower)
	// cookie: 提取 + ToLower(与 requestTargetContainsAny "cookie" 分支等价)
	if cookie, ok := cveHeaderValueOK(req.Headers, "Cookie"); ok {
		h.cookie = ac.cookieAC.matchMask(strings.ToLower(cookie))
	}
	// url_body: URL targets + body targets 合并扫描
	h.urlBody = ac.urlBodyAC.matchMaskSlice(req.URLTargetsLower)
	bodyHit := ac.urlBodyAC.matchMaskSlice(req.BodyTargetsLower)
	for i := range h.urlBody.words {
		h.urlBody.words[i] |= bodyHit.words[i]
	}
	return h
}

// subDetectorACGate 用 AC hit mask 判断某规则 gate 是否通过。
// 等价于对应 requestTargetContainsAny(req, target, ...needles)。
func subDetectorACGate(cveID, target string, hits *subDetectorHits) bool {
	kind := &globalSubDetectorAC.masks[subDetectorMaskKindIndex(target)]
	mask, ok := kind.mask[cveID]
	if !ok {
		return true // 无 AC 数据的规则不拦截
	}
	switch target {
	case "url":
		return hits.url.intersects(mask)
	case "body":
		return hits.body.intersects(mask)
	case "header":
		return hits.header.intersects(mask)
	case "cookie":
		return hits.cookie.intersects(mask)
	case "url_body":
		return hits.urlBody.intersects(mask)
	default:
		return hits.all.intersects(mask)
	}
}
