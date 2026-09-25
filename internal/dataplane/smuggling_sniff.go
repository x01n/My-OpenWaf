package dataplane

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/store"
)

// smugglingRuleIDs 是走私原生嗅探五类判定对应的稳定规则标识。这些标识
// 会一字不差进入 SecurityEvent.RuleIDStr，管理面可据其展示与筛选。
var smugglingRuleIDs = [...]string{
	"owaf.smuggle.te_cl_coexist", // 1) TE 与 CL 共存
	"owaf.smuggle.cl_mismatch",   // 2) 多个 CL 值不一致
	"owaf.smuggle.te_multi",      // 3) 多个 TE 头行
	"owaf.smuggle.te_bad_value",  // 4) TE 值不是合法 token 序列
	"owaf.smuggle.cl_bad_value",  // 5) CL 值非数字/负数/超大
}

// smugglingCatProtoViol 是命中事件的 Category / Phase 值，与 OWASP 协议违规类
// 归属同一语义（internal/waf/owasp 的 CatProtoViol 恒为 "protocol_violation"）。
const smugglingCatProtoViol = "protocol_violation"

// SmugglingSniffResult 是一次走私嗅探的判定结果。
type SmugglingSniffResult struct {
	// Detected 是否命中五类走私证据之一。
	Detected bool
	// Reason 命中的具体描述（Detected 为 false 时为空）。
	Reason string
	// Severity 严重级别：high / medium / low（Detected 为 false 时为空）。
	Severity string
	// Category 事件分类，恒为 smugglingCatProtoViol。
	Category string
	// RuleID 五类判定对应的 smugglingRuleIDs 标识；空表示不适用。
	RuleID string
}

// SmugglingSniff 对一段请求头原始字节执行五类请求走私判定（RFC 9112 §6.3 +
// 经典走私矩阵，全部大小写不敏感）：
//
//  1. Transfer-Encoding 与 Content-Length 同存；
//  2. 多个 Content-Length 头且值不一致；
//  3. 多个 Transfer-Encoding 头行；
//  4. Transfer-Encoding 值不是单个 "chunked"（含 "chunked, chunked"、空值等畸形）；
//  5. Content-Length 值为非数字/负数/超大溢出。
//
// 诚实边界说明：hertz 的 HTTP/1 解析器在请求头被送入 handler 之前，已按同样
// 规则拒绝 TE+CL 共存、多个 TE 行、非 chunked TE、不一致 CL 与非法 CL 值（见
// hertz 依赖 pkg/protocol/http1/req/header.go 的 errBothTEAndCL / errMultipleTE /
// errUnsupportedTE / errDuplicateCL），HTTP/2 侧同样按 RFC 9113 裁决。因此从
// handler 取得的已解析头永远命中不了这五类——本函数是防御纵深审计仪器：当上游
// 通道（h2c、自研转发面或未来替换的解析器）把原始走私形态漏进 handler 时，这里
// 负责留下协议违规审计证据，而不是假装能够在解析前看到字节。
func SmugglingSniff(raw []byte) SmugglingSniffResult {
	if len(raw) == 0 {
		return SmugglingSniffResult{}
	}

	var clValues []string
	teSeen := false
	clSeen := false
	for _, lineBytes := range bytes.Split(raw, []byte("\n")) {
		line := strings.TrimRight(string(lineBytes), "\r")
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue // 请求行或畸形行，不属于本嗅探范围
		}
		key := strings.TrimSpace(line[:colon])
		value := strings.TrimSpace(line[colon+1:])
		switch {
		case strings.EqualFold(key, "Transfer-Encoding"):
			if teSeen {
				return smugglingHit(smugglingRuleIDs[2], "multiple Transfer-Encoding header lines", "high")
			}
			teSeen = true
			// 与 hertz h1 解析器同口径：仅接受单个 "chunked"。
			if !strings.EqualFold(value, "chunked") {
				return smugglingHit(smugglingRuleIDs[3], "malformed Transfer-Encoding value: "+value, "high")
			}
		case strings.EqualFold(key, "Content-Length"):
			clSeen = true
			if strings.HasPrefix(value, "-") {
				return smugglingHit(smugglingRuleIDs[4], "negative Content-Length value: "+value, "low")
			}
			if _, err := strconv.ParseUint(value, 10, 64); err != nil {
				return smugglingHit(smugglingRuleIDs[4], "invalid Content-Length value: "+value, "low")
			}
			clValues = append(clValues, value)
		}
	}
	if teSeen && clSeen {
		return smugglingHit(smugglingRuleIDs[0], "Transfer-Encoding and Content-Length coexist", "high")
	}
	if len(clValues) > 1 {
		first := clValues[0]
		for _, v := range clValues[1:] {
			if v != first {
				return smugglingHit(smugglingRuleIDs[1], "conflicting Content-Length values: "+first+" vs "+v, "medium")
			}
		}
	}
	return SmugglingSniffResult{}
}

func requestSmugglingSniff(c *app.RequestContext, opts Options, siteID uint, requestID string, host string, clientIPString string) {
	if c == nil || opts.Writer == nil {
		return
	}
	if !requestHasSmugglingRelevantHeaders(c) {
		return
	}
	// 用已解析的头名/值直接执行五类走私判定，重演输出的顺序不敏感
	// （参见 requestHeaderLines 注释），避免为同样结果额外分配一整个
	// 序列化缓冲。
	res := SmugglingSniffRequestHeader(&c.Request.Header)
	if !res.Detected {
		return
	}
	method, path, userAgent := smugglingRequestIdentity(c)
	writeSmugglingObserveEvent(c, opts, siteID, requestID, clientIPString, host, path, method, userAgent,
		res.RuleID, "severity="+res.Severity+" "+res.Reason)
	if opts.Metrics != nil {
		opts.Metrics.RecordWAFObserve()
	}
}

// 走私判定使用的静态字节比较目标，避免每次比较时字符串转 []byte 的分配。
// 仅在本包内只读使用，无写入者。
var (
	strTransferEncoding = []byte("Transfer-Encoding")
	strContentLength    = []byte("Content-Length")
)

/**
 * SmugglingSniffRequestHeader 对已解析的请求头执行五类请求走私判定（RFC 9112 §6.3 +
 * 经典走私矩阵，全部大小写不敏感）：
 *
 *  1. Transfer-Encoding 与 Content-Length 同存；
 *  2. 多个 Content-Length 头且值不一致；
 *  3. 多个 Transfer-Encoding 头行；
 *  4. Transfer-Encoding 值不是单个 "chunked"（含 "chunked, chunked"、空值等畸形）；
 *  5. Content-Length 值为非数字/负数/超大溢出。
 *
 * 注意：hertz 的 HTTP/1 解析器在请求头被送入 handler 之前，已按同样规则拒绝 TE+CL 共存、
 * 多个 TE 行、非 chunked TE、不一致 CL 与非法 CL 值（见 hertz 依赖 pkg/protocol/http1/req/header.go
 * 的 errBothTEAndCL / errMultipleTE / errUnsupportedTE / errDuplicateCL），HTTP/2 侧同样按 RFC 9113 裁决。因此从 handler
 * 取得的已解析头永远命中不了这五类——本函数是防御纵深审计仪器：当上游通道（h2c、自研转发面或未来替换的解析器）
 * 把原始走私形态漏进 handler 时，这里负责留下协议违规审计证据，而不是假装能够在解析前看到字节。
 *
 * @param h 已解析的请求头
 * @returns SmugglingSniffResult 判定结果
 */
func SmugglingSniffRequestHeader(h *protocol.RequestHeader) SmugglingSniffResult {
	if h == nil {
		return SmugglingSniffResult{}
	}
	// 预分配使得常规请求（单个 CL、无 TE）不进行任何切片扩容。
	clValues := make([]string, 0, 1)
	teCount := 0
	clCount := 0
	teDirty := false
	clDirty := false
	teValue := ""

	h.VisitAll(func(k, v []byte) {
		switch {
		case bytes.EqualFold(k, strTransferEncoding):
			if teCount == 0 {
				teValue = strings.TrimSpace(string(v))
				if !strings.EqualFold(teValue, "chunked") {
					teDirty = true
				}
			}
			teCount++
		case bytes.EqualFold(k, strContentLength):
			clCount++
			val := string(v)
			if strings.HasPrefix(val, "-") {
				clDirty = true
			} else if _, err := strconv.ParseUint(val, 10, 64); err != nil {
				clDirty = true
			}
			clValues = append(clValues, val)
		}
	})

	if teCount > 0 && clCount > 0 {
		return smugglingHit(smugglingRuleIDs[0], "Transfer-Encoding and Content-Length coexist", "high")
	}
	if teCount > 1 {
		return smugglingHit(smugglingRuleIDs[2], "multiple Transfer-Encoding header lines", "high")
	}
	if teDirty {
		return smugglingHit(smugglingRuleIDs[3], "malformed Transfer-Encoding value: "+teValue, "high")
	}
	if len(clValues) > 1 {
		first := clValues[0]
		for _, v := range clValues[1:] {
			if v != first {
				return smugglingHit(smugglingRuleIDs[1], "conflicting Content-Length values: "+first+" vs "+v, "medium")
			}
		}
	}
	if clDirty {
		return smugglingHit(smugglingRuleIDs[4], "invalid Content-Length value", "low")
	}
	return SmugglingSniffResult{}
}

func requestHasSmugglingRelevantHeaders(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	h := &c.Request.Header
	if len(h.ContentLengthBytes()) > 0 {
		return true
	}
	if h.ConnectionClose() {
		return true
	}
	found := false
	h.VisitAllCustomHeader(func(key, _ []byte) {
		switch key[0] | 0x20 {
		case 't':
			// key 由 hertz 统一规范化（首字母大写），此处大小写折叠后
			// 与 "transfer-encoding" 全串比较即可，无任何分配。
			found = found || bytes.EqualFold(key, []byte("transfer-encoding"))
		case 'c':
			found = found || bytes.EqualFold(key, []byte("content-length"))
		}
	})
	if found {
		return true
	}
	return len(h.Trailer().Peek("Transfer-Encoding")) > 0 || len(h.Trailer().Peek("Content-Length")) > 0
}

// smugglingRequestIdentity 抽取命中事件的请求签名上下文。
func smugglingRequestIdentity(c *app.RequestContext) (method, path, userAgent string) {
	method = "unknown"
	path = ""
	if len(c.Request.Header.Method()) > 0 {
		method = string(c.Request.Header.Method())
	}
	if len(c.Request.URI().PathOriginal()) > 0 {
		path = string(c.Request.URI().PathOriginal())
	} else {
		path = string(c.Request.URI().Path())
	}
	userAgent = string(c.Request.Header.UserAgent())
	return method, path, userAgent
}

// requestHeaderLines 将已解析请求头重演为 "Key: Value" 行并拼接。
//
// 注意：hertz RequestHeader.VisitAll 不保证原线序（Host/CL/CT/UA/Trailer 等
// 特殊字段先于普通字段枚举），因此这不是线级忠实的原始字节；对五类走私判定
// 而言仅「某头是否出现 + 出现几次 + 值」是输入，与线序无关，该重演足够。
func requestHeaderLines(c *app.RequestContext) []byte {
	var b strings.Builder
	c.Request.Header.VisitAll(func(k, v []byte) {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.Write(k)
		b.WriteString(": ")
		b.Write(v)
	})
	return []byte(b.String())
}

// writeSmugglingObserveEvent 写入走私审计观察事件。只记录，不拦截。
func writeSmugglingObserveEvent(c *app.RequestContext, opts Options, siteID uint, requestID, clientIP, host, path, method, userAgent, ruleID, reason string) {
	if opts.Writer == nil {
		return
	}
	opts.Writer.RecordEvent(store.SecurityEvent{
		SiteID:    siteID,
		RequestID: requestID,
		ClientIP:  clientIP,
		Host:      host,
		Path:      path,
		Method:    method,
		UserAgent: userAgent,
		RuleIDStr: ruleID,
		Phase:     smugglingCatProtoViol,
		Action:    string(action.Observe),
		Category:  smugglingCatProtoViol,
		MatchDesc: reason,
	})
}

// smugglingHit 构造统一命中结果。
func smugglingHit(ruleID, reason, severity string) SmugglingSniffResult {
	return SmugglingSniffResult{
		Detected: true,
		Reason:   reason,
		Severity: severity,
		Category: smugglingCatProtoViol,
		RuleID:   ruleID,
	}
}
