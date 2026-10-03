package luaplugin

import (
	"net/url"
	"strings"

	lua "github.com/yuin/gopher-lua"
	"golang.org/x/net/http/httpguts"
)

// parseQuery 解析查询串；供 safeMutationQuery 复用 net/url 的严格解析。
func parseQuery(raw string) (url.Values, error) {
	return url.ParseQuery(raw)
}

// 请求/响应改写的资源上限。
//
// 与 jsplugin 的同名常量取同一组数值：两个引擎的能力边界应当一致，用户在
// 两者之间迁移脚本时不会因为某一边更严而踩坑。
const (
	// maxMutationBodyBytes 限制脚本写入的请求体/响应体体积。
	maxMutationBodyBytes = 16 * 1024
	// maxMutationStringBytes 限制改写字段（method/path/query）体积。
	maxMutationStringBytes = 16 * 1024
	// maxMutationHeaders 限制单次改写增删的头数量。
	maxMutationHeaders = 32
	// maxMutationHeaderNameBytes 限制头名体积。
	maxMutationHeaderNameBytes = 256
	// maxMutationHeaderValueBytes 限制头值体积。
	maxMutationHeaderValueBytes = 2048
)

// requestMutationFromTable 从脚本返回表的 request 子表解析请求改写。
//
// 只读已知键，未知键忽略；非法条目逐项跳过而不是让整份改写失败——与
// decisionFromTable 处理响应头的方式一致，一个写错的头名不应该让脚本的
// 其余改写全部失效。用户可在 dry-run 返回值里逐项核对实际生效的内容。
func requestMutationFromTable(tbl *lua.LTable) *RequestMutation {
	if tbl == nil {
		return nil
	}
	mutation := &RequestMutation{}
	changed := false

	if value, ok := luaStringField(tbl, "method"); ok {
		if method := truncateString(strings.TrimSpace(value), maxMutationStringBytes); method != "" && isHTTPToken(method) {
			mutation.Method = &method
			changed = true
		}
	}
	if value, ok := luaStringField(tbl, "path"); ok {
		if path, valid := safeMutationPath(value); valid {
			mutation.Path = &path
			changed = true
		}
	}
	// query 是 raw_query 的别名：脚本作者更可能写 query。
	if value, ok := luaStringField(tbl, "raw_query"); ok {
		if query, valid := safeMutationQuery(value); valid {
			mutation.RawQuery = &query
			changed = true
		}
	} else if value, ok := luaStringField(tbl, "query"); ok {
		if query, valid := safeMutationQuery(value); valid {
			mutation.RawQuery = &query
			changed = true
		}
	}
	if value, ok := luaStringField(tbl, "body"); ok {
		body := truncateString(value, maxMutationBodyBytes)
		mutation.Body = &body
		changed = true
	}
	if headers := requestHeadersFromTable(tbl); len(headers) > 0 {
		mutation.SetHeaders = headers
		changed = true
	}
	if deleted := headerNamesFromValue(tbl.RawGetString("delete_headers"), allowedRequestHeader); len(deleted) > 0 {
		mutation.DeleteHeaders = deleted
		changed = true
	}

	if !changed {
		return nil
	}
	return mutation
}

// responseMutationFromTable 从脚本返回表的 response 子表解析响应改写。
//
// 与 request 子表对称：status_code / body / headers / delete_headers。
func responseMutationFromTable(tbl *lua.LTable) *ResponseMutation {
	if tbl == nil {
		return nil
	}
	mutation := &ResponseMutation{}
	changed := false

	if n, ok := tbl.RawGetString("status_code").(lua.LNumber); ok {
		status := int(n)
		if n == lua.LNumber(status) && status >= minDecisionStatusCode && status <= maxDecisionStatusCode {
			mutation.StatusCode = status
			changed = true
		}
	}
	if value, ok := luaStringField(tbl, "body"); ok {
		if !containsSensitiveDecisionText(value) {
			body := truncateString(value, maxMutationBodyBytes)
			mutation.Body = &body
			changed = true
		}
	}
	// headers 与 set_headers 都接受：response 子表沿用 Decision 顶层的 headers
	// 写法，同时兼容 jsplugin 的 set_headers。
	if headers := responseHeadersFromTable(tbl); len(headers) > 0 {
		mutation.SetHeaders = headers
		changed = true
	}
	if deleted := headerNamesFromValue(tbl.RawGetString("delete_headers"), allowedDecisionHeader); len(deleted) > 0 {
		mutation.DeleteHeaders = deleted
		changed = true
	}

	if !changed {
		return nil
	}
	return mutation
}

// luaStringField 读取字符串字段；字段缺失或类型不符时返回 ok=false。
func luaStringField(tbl *lua.LTable, key string) (string, bool) {
	value, ok := tbl.RawGetString(key).(lua.LString)
	if !ok {
		return "", false
	}
	return string(value), true
}

// requestHeadersFromTable 解析 request 子表的 set_headers / headers。
//
// 两个键名都接受：set_headers 是 jsplugin 的写法，headers 是 Lua 判定表顶层
// 的写法，用户在两个引擎之间迁移时不必记忆差异。
func requestHeadersFromTable(tbl *lua.LTable) map[string]string {
	for _, key := range []string{"set_headers", "headers"} {
		if headers, ok := tbl.RawGetString(key).(*lua.LTable); ok {
			if parsed := collectHeaders(headers, allowedRequestHeader, false); len(parsed) > 0 {
				return parsed
			}
		}
	}
	return nil
}

// responseHeadersFromTable 解析 response 子表的 headers / set_headers。
func responseHeadersFromTable(tbl *lua.LTable) map[string]string {
	for _, key := range []string{"headers", "set_headers"} {
		if headers, ok := tbl.RawGetString(key).(*lua.LTable); ok {
			if parsed := collectHeaders(headers, allowedDecisionHeader, true); len(parsed) > 0 {
				return parsed
			}
		}
	}
	return nil
}

// collectHeaders 把 Lua 表收集为头映射。
//
// filter 决定哪些头名允许；redactText 为 true 时额外拒绝明显带认证秘密的值
// （响应体会回给客户端，不能把 Authorization 之类的内容反射出去）。
func collectHeaders(tbl *lua.LTable, filter func(string) bool, redactText bool) map[string]string {
	if tbl == nil {
		return nil
	}
	headers := make(map[string]string, maxMutationHeaders)
	visited := 0
	tbl.ForEach(func(key, value lua.LValue) {
		if len(headers) >= maxMutationHeaders || visited >= maxDecisionTableEntries {
			return
		}
		visited++
		name, nameOK := key.(lua.LString)
		raw, valueOK := value.(lua.LString)
		if !nameOK || !valueOK || len(name) == 0 || len(name) > maxMutationHeaderNameBytes {
			return
		}
		headerName := string(name)
		headerValue := string(raw)
		if !httpguts.ValidHeaderFieldName(headerName) || !filter(headerName) {
			return
		}
		if strings.ContainsAny(headerValue, "\r\n") {
			return
		}
		if redactText && containsSensitiveDecisionText(headerValue) {
			return
		}
		headers[headerName] = truncateString(headerValue, maxMutationHeaderValueBytes)
	})
	if len(headers) == 0 {
		return nil
	}
	return headers
}

// headerNamesFromValue 解析 delete_headers。
//
// 数组形态是 Lua 里最自然的写法（{ "X-A", "X-B" }）；对象形态
// （{ ["X-A"] = true }）同样接受，与 jsplugin 的 delete_headers 语义对齐。
// 对象形态的标记按真值判定：false / 0 / "" 的键不删除。
//
// filter 决定哪些头名允许删除：请求侧与响应侧各有一张保留头表，删掉 Host 或
// Content-Length 会破坏代理层的请求构造，比删一个普通头危险得多。
func headerNamesFromValue(value lua.LValue, filter func(string) bool) []string {
	tbl, ok := value.(*lua.LTable)
	if !ok || tbl == nil {
		return nil
	}
	names := make([]string, 0, maxMutationHeaders)

	// 对象形态。数字键属于数组部分，留给下面的顺序遍历。
	visited := 0
	tbl.ForEach(func(key, val lua.LValue) {
		if len(names) >= maxMutationHeaders || visited >= maxDecisionTableEntries {
			return
		}
		visited++
		if _, numeric := key.(lua.LNumber); numeric {
			return
		}
		name, isString := key.(lua.LString)
		if !isString || !isTruthyMarker(val) {
			return
		}
		if sanitized, valid := normalizeHeaderName(string(name)); valid && filter(sanitized) {
			names = append(names, sanitized)
		}
	})

	// 数组形态。
	for i := 1; i <= tbl.Len() && len(names) < maxMutationHeaders; i++ {
		raw, isString := tbl.RawGetInt(i).(lua.LString)
		if !isString {
			continue
		}
		if sanitized, valid := normalizeHeaderName(string(raw)); valid && filter(sanitized) {
			names = append(names, sanitized)
		}
	}

	if len(names) == 0 {
		return nil
	}
	return names
}

// isTruthyMarker 判定对象形态的删除标记是否为真。
func isTruthyMarker(value lua.LValue) bool {
	switch typed := value.(type) {
	case lua.LBool:
		return bool(typed)
	case lua.LNumber:
		return typed != 0
	case lua.LString:
		return typed != ""
	default:
		return false
	}
}

// normalizeHeaderName 校验并返回头名；不合法时 ok=false。
func normalizeHeaderName(name string) (string, bool) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || len(trimmed) > maxMutationHeaderNameBytes {
		return "", false
	}
	if !httpguts.ValidHeaderFieldName(trimmed) {
		return "", false
	}
	return trimmed, true
}

// allowedRequestHeader 限制脚本能增删的请求头。
//
// 与 jsplugin 的 isForbiddenJSHeader 同一张表：Host 决定路由与站点匹配，
// Content-Length 与 Transfer-Encoding 决定消息边界，逐跳头由传输层生成——
// 脚本改动这些会破坏代理层的请求构造，而不是表达策略。
func allowedRequestHeader(name string) bool {
	switch strings.ToLower(name) {
	case "host", "content-length", "transfer-encoding", "connection", "keep-alive",
		"te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization", "proxy-connection":
		return false
	default:
		return true
	}
}

// safeMutationPath 校验脚本给出的新路径。
//
// 与 jsplugin 的 validateJSPath 同规则：必须是单个 / 开头的相对路径，不得携带
// query、fragment、控制字符或绝对 URL，避免脚本把请求改写到本站之外。
func safeMutationPath(raw string) (string, bool) {
	path := truncateString(raw, maxMutationStringBytes)
	if path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return "", false
	}
	if strings.ContainsAny(path, "?#\r\n") {
		return "", false
	}
	for i := 0; i < len(path); i++ {
		if path[i] < 0x20 || path[i] == 0x7f {
			return "", false
		}
	}
	return path, true
}

// safeMutationQuery 校验脚本给出的新查询串。
func safeMutationQuery(raw string) (string, bool) {
	query := truncateString(raw, maxMutationStringBytes)
	if strings.ContainsAny(query, "#\r\n") {
		return "", false
	}
	if _, err := parseQuery(query); err != nil {
		return "", false
	}
	return query, true
}

// isHTTPToken 报告字符串是否是合法的 HTTP token（方法名、头名共用）。
func isHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		default:
			return false
		}
	}
	return true
}
