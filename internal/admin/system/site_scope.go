package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
)

// errInvalidSiteScope 表示 site_id 字段既不是 null 也不是合法的正整数。
var errInvalidSiteScope = errors.New("site_id must be null or a positive integer")

/**
 * parseSiteScope 解析 site_id 字段的三态语义。
 *
 * `**uint` 无法表达这个三态：encoding/json 对 JSON null 的定义是「不修改目标」，
 * 因此显式 null 与字段缺省都会让外层指针保持 nil，站点级条目无法被改回全局作用域。
 * 改用 json.RawMessage 在绑定后再判别原始字节即可区分三者。
 *
 * @param raw 请求体中 site_id 字段的原始 JSON；字段缺省时为 nil 或空。
 * @return present 字段是否出现在请求体中；siteID 目标作用域，显式 null 时为 nil；err 取值非法。
 */
func parseSiteScope(raw json.RawMessage) (present bool, siteID *uint, err error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false, nil, nil
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return true, nil, nil
	}
	v, convErr := strconv.ParseUint(string(trimmed), 10, 64)
	if convErr != nil || v == 0 {
		return true, nil, errInvalidSiteScope
	}
	id := uint(v)
	return true, &id, nil
}
