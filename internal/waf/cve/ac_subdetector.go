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
	// (cveID + "|" + target) → mask,用于 gate 查询。
	masks map[string]acGateMask
}

var globalSubDetectorAC subDetectorACSet

func init() {
	buildSubDetectorAC()
}

func subDetectorMaskKey(cveID, target string) string {
	return cveID + "|" + target
}

func buildSubDetectorAC() {
	type viewBuilder struct {
		b *acBuilder
	}
	views := map[string]*viewBuilder{
		"all":      {b: newACBuilder()},
		"url":      {b: newACBuilder()},
		"body":     {b: newACBuilder()},
		"header":   {b: newACBuilder()},
		"cookie":   {b: newACBuilder()},
		"url_body": {b: newACBuilder()},
	}
	masks := make(map[string]acGateMask, len(subDetectorNeedleEntries))

	for _, entry := range subDetectorNeedleEntries {
		vb, ok := views[entry.target]
		if !ok {
			vb = views["all"]
		}
		key := subDetectorMaskKey(entry.cveID, entry.target)
		mask := masks[key]
		for _, n := range entry.needles {
			idx := vb.b.addPattern(n)
			mask.set(idx)
		}
		masks[key] = mask
	}

	globalSubDetectorAC = subDetectorACSet{
		allAC:     views["all"].b.build(),
		urlAC:     views["url"].b.build(),
		bodyAC:    views["body"].b.build(),
		headerAC:  views["header"].b.build(),
		cookieAC:  views["cookie"].b.build(),
		urlBodyAC: views["url_body"].b.build(),
		masks:     masks,
	}
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
	key := subDetectorMaskKey(cveID, target)
	mask, ok := globalSubDetectorAC.masks[key]
	if !ok {
		return true // 无 AC 数据的规则不拦截
	}
	switch target {
	case "url":
		return hits.url.intersects(&mask)
	case "body":
		return hits.body.intersects(&mask)
	case "header":
		return hits.header.intersects(&mask)
	case "cookie":
		return hits.cookie.intersects(&mask)
	case "url_body":
		return hits.urlBody.intersects(&mask)
	default:
		return hits.all.intersects(&mask)
	}
}
