package jsplugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"My-OpenWaf/internal/core/action"
)

/**
 * mutationPlanAliases 描述两个阶段各自接受的脚本侧别名键。
 *
 * 别名存在的原因是两套运行时对同一语义用了不同的名字：请求阶段的裁决用
 * status_code（与 Lua 的判定表一致），而 response 阶段改写的本来就是响应
 * 状态码，规范键用 status。两个方向都接受，字段名不一致不再让用户踩坑——
 * 踩坑的表现是执行期校验失败，脚本不生效，请求照常放行。
 *
 * 返回的映射是 alias -> canonical；canonical 始终是该阶段结构上真实存在的
 * json 键。
 *
 * 请求阶段的 body 不做别名：它在本阶段已有唯一含义（改写请求体），不能再
 * 兼任响应体。响应体在请求阶段用 response_body，与 Lua 的判定表逐字一致。
 *
 * @param isResponse 为 true 时返回 response 阶段的别名表。
 * @return alias 到 canonical 键的映射。
 */
func mutationPlanAliases(isResponse bool) map[string]string {
	if isResponse {
		return map[string]string{
			"status_code":   "status",
			"response_body": "body",
			"headers":       "set_headers",
		}
	}
	return map[string]string{
		"headers": "set_headers",
		"status":  "status_code",
	}
}

/**
 * canonicalizeMutationPlan 把脚本返回的计划对象折叠为规范形态。
 *
 * 输入是脚本返回对象的 JSON 序列化结果，输出是可以直接反序列化进
 * MutationPlan / ResponseMutationPlan 的规范 JSON。做两件事：
 *
 *  1. 别名键折叠为规范键；规范键与别名同时出现时报错，不静默取舍——
 *     两者冲突本身就是用户笔误的信号，静默选一个会让脚本行为无法从源码推断。
 *  2. delete_headers 接受数组与对象两种形态：数组原样保留；对象取「真值」键
 *     （{name: true} / {name: "1"} / {name: 1}）展开为数组，值为
 *     false / 0 / "" / null 的键不删除。这是 JavaScript 的常规真值语义，
 *     既满足 {"x-internal": true} 的直觉，也满足 {x: false} 的不删除语义。
 *
 * 折叠在 JSON 层完成而不是在 Go 类型上：MutationPlan / ResponseMutationPlan
 * 保持单一规范形状，数据面与校验逻辑无需知道别名的存在；同时整条路径是纯
 * Go，可在无 cgo 的构建里直接测试。
 *
 * @param raw 脚本返回对象的 JSON 序列化结果。
 * @param isResponse 为 true 时按 response 阶段处理。
 * @return 规范化的计划 JSON。
 */
func canonicalizeMutationPlan(raw string, isResponse bool) ([]byte, error) {
	var plan map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &plan); err != nil {
		return nil, fmt.Errorf("jsplugin: mutation plan must be a JSON object: %w", err)
	}

	for alias, canonical := range mutationPlanAliases(isResponse) {
		aliased, hasAlias := plan[alias]
		if !hasAlias {
			continue
		}
		if _, hasCanonical := plan[canonical]; hasCanonical {
			return nil, fmt.Errorf("jsplugin: mutation plan must not set both %q and its alias %q", canonical, alias)
		}
		plan[canonical] = aliased
		delete(plan, alias)
	}

	if rawDelete, ok := plan["delete_headers"]; ok {
		folded, err := foldDeleteHeaders(rawDelete)
		if err != nil {
			return nil, err
		}
		plan["delete_headers"] = folded
	}

	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("jsplugin: mutation plan encoding failed: %w", err)
	}
	return encoded, nil
}

/**
 * allowedMutationPlanField 返回字段是否属于对应阶段的计划形状（含别名）。
 *
 * 形状检查只拒绝「完全不属于本阶段计划」的键；规范键与别名同时出现、别名值
 * 类型不对这些更深的问题由 canonicalizeMutationPlan 与随后的结构反序列化报出，
 * 错误信息里因此能带上是哪个键写错了。白名单与别名表同源，别名不会出现
 * 「被折叠逻辑接受、却被形状检查先行拒绝」的死路。
 *
 * @param name 脚本返回对象里的字段名。
 * @param isResponse 为 true 时按 response 阶段的形状判定。
 * @return 字段属于该阶段计划时为 true。
 */
func allowedMutationPlanField(name string, isResponse bool) bool {
	if isResponse {
		switch name {
		case "status", "body", "set_headers", "delete_headers":
			return true
		}
		return mutationPlanAliases(true)[name] != ""
	}
	switch name {
	case "method", "path", "raw_query", "body", "set_headers", "delete_headers",
		"action", "status_code", "response_body", "redirect_to", "message", "tags":
		return true
	default:
		return mutationPlanAliases(false)[name] != ""
	}
}

/**
 * foldDeleteHeaders 把 delete_headers 的对象形态展开为头名数组。
 *
 * 数组形态原样返回，交给下游按 []string 反序列化——元素不是字符串时由
 * encoding/json 报出带字段路径的错误，比在这里重复一遍检查更准确。
 *
 * @param raw delete_headers 字段的原始 JSON。
 * @return 头名数组形态的 JSON。
 */
func foldDeleteHeaders(raw json.RawMessage) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(raw))
	switch {
	case trimmed == "null":
		return raw, nil
	case strings.HasPrefix(trimmed, "["):
		return raw, nil
	case !strings.HasPrefix(trimmed, "{"):
		return nil, errors.New("jsplugin: delete_headers must be an array of header names or an object of {name: true}")
	}

	var markers map[string]any
	if err := json.Unmarshal(raw, &markers); err != nil {
		return nil, fmt.Errorf("jsplugin: delete_headers object is invalid: %w", err)
	}
	names := make([]string, 0, len(markers))
	for name, marker := range markers {
		drop, err := deleteHeaderMarker(name, marker)
		if err != nil {
			return nil, err
		}
		if drop {
			names = append(names, name)
		}
	}
	// map 迭代顺序随机，规范化输出必须稳定，否则同一脚本的计划对象每次
	// 产生不同的 JSON。
	sort.Strings(names)
	encoded, err := json.Marshal(names)
	if err != nil {
		return nil, fmt.Errorf("jsplugin: delete_headers encoding failed: %w", err)
	}
	return encoded, nil
}

/**
 * deleteHeaderMarker 报告对象形态里单个键是否表示「删除该头」。
 *
 * 标记值只能是 null、布尔、数字或字符串；嵌套对象与数组不是有效的删除标记，
 * 直接报错而不是当作 false。与头名、头值校验的既有做法一致：计划里出现
 * 无法解释的值时整份计划失败，用户才能在脚本日志与 dry-run 里看到原因。
 *
 * @param name 头名，仅用于错误信息。
 * @param marker 该键对应的标记值。
 * @return 是否为「删除」标记；标记类型非法时返回错误。
 */
func deleteHeaderMarker(name string, marker any) (bool, error) {
	switch value := marker.(type) {
	case nil:
		return false, nil
	case bool:
		return value, nil
	case float64:
		return value != 0, nil
	case string:
		return value != "", nil
	default:
		return false, fmt.Errorf("jsplugin: delete_headers marker for %q must be a boolean, number, string or null", name)
	}
}

/**
 * ValidateMutationVerdict 校验请求阶段计划携带的裁决字段。
 *
 * 动作词汇与内置规则、Lua 插件完全共用 internal/core/action：未知动作被拒绝
 * 而不是静默忽略——脚本里的 action 是显式意图，一个拼错的 "blcok" 静默变成
 * 「放行」比报错危险得多。这与 Lua 侧「未知动作一律忽略」的差异是刻意的：
 * Lua 的 post 阶段可能覆盖内置判定，忽略未知动作才不会升级成误封；JS 的裁决
 * 是脚本唯一的显式输出，拒绝并让用户看到错误才是正确语义。
 *
 * @param plan 请求阶段计划。
 * @return 裁决字段越界或动作未知时返回错误。
 */
func validateMutationVerdict(plan MutationPlan) error {
	if plan.Action == nil {
		return nil
	}
	actionType := action.Normalize(action.Type(*plan.Action))
	if !action.IsValid(actionType) {
		return fmt.Errorf("jsplugin: unknown action %q", *plan.Action)
	}
	if plan.RedirectTo != nil {
		if len(*plan.RedirectTo) > MaxMutationStringBytes {
			return fmt.Errorf("jsplugin: redirect_to exceeds %d bytes", MaxMutationStringBytes)
		}
		if err := validateJSRedirectTarget(*plan.RedirectTo); err != nil {
			return err
		}
	}
	// status_code 允许 0：action.Result 用 0 表示「按动作的默认状态码」，
	// 脚本显式写 0 与不写等价，不该被当成非法值。
	if plan.StatusCode != nil && *plan.StatusCode != 0 && (*plan.StatusCode < 100 || *plan.StatusCode > 999) {
		return errors.New("jsplugin: invalid status_code mutation")
	}
	if plan.ResponseBody != nil && len(*plan.ResponseBody) > MaxMutationStringBytes {
		return fmt.Errorf("jsplugin: response_body exceeds %d bytes", MaxMutationStringBytes)
	}
	if plan.Message != nil && len(*plan.Message) > MaxMutationStringBytes {
		return fmt.Errorf("jsplugin: message exceeds %d bytes", MaxMutationStringBytes)
	}
	if plan.Tags != nil {
		if len(*plan.Tags) > MaxMutationVerdictTags {
			return fmt.Errorf("jsplugin: verdict tags exceed %d entries", MaxMutationVerdictTags)
		}
		for _, tag := range *plan.Tags {
			if len(tag) > MaxMutationVerdictTagBytes {
				return fmt.Errorf("jsplugin: verdict tag exceeds %d bytes", MaxMutationVerdictTagBytes)
			}
			if !isValidJSHeaderValue(tag) {
				return errors.New("jsplugin: invalid verdict tag")
			}
		}
	}
	return nil
}

/**
 * validateJSRedirectTarget 限制重定向目标与 Lua 的 safeRedirectTarget 同规则：
 * 只允许 http/https 绝对地址或以单个 / 开头的站内路径，拒绝协议相对地址
 * （//evil.example），避免脚本把用户导向外部站点。
 *
 * @param raw 脚本给出的重定向目标。
 * @return 目标非法时返回错误。
 */
func validateJSRedirectTarget(raw string) error {
	value := strings.TrimSpace(raw)
	if value == "" || strings.ContainsAny(value, "\r\n") || strings.HasPrefix(value, "//") {
		return errors.New("jsplugin: invalid redirect target")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return errors.New("jsplugin: invalid redirect target")
	}
	if parsed.IsAbs() && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("jsplugin: invalid redirect target")
	}
	if !parsed.IsAbs() && !strings.HasPrefix(value, "/") {
		return errors.New("jsplugin: invalid redirect target")
	}
	return nil
}
