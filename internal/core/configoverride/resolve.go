package configoverride

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

// Source 表示一个键当前生效值的来源。
type Source string

const (
	// SourceDB 表示取值来自覆盖表（界面显式保存过）。
	SourceDB Source = "db"
	// SourceEnv 表示取值来自环境变量。
	SourceEnv Source = "env"
	// SourceDefault 表示取值来自注册表里的内置默认值。
	SourceDefault Source = "default"
)

// Overrides 是覆盖表的解析结果：键名 -> 规范化取值（bool / int64 / string）。
// 只有被显式写入过的键才会出现在其中。
type Overrides map[string]any

// EnvLookup 返回环境变量原文与是否已定义。
// 传 nil 表示使用进程环境（os.LookupEnv）。
type EnvLookup func(name string) (string, bool)

// Entry 是单个键的三态解析结果。
type Entry struct {
	// Key 是注册表键名。
	Key string
	// Value 是当前生效值。
	Value any
	// Source 取值来源。
	Source Source
	// Overridden 为真表示覆盖表里存在该键。
	Overridden bool
}

// ParseStoredOverrides 解析覆盖表的存储形态：
// 形状是 {"<key>":{"value":<取值>,"set":true}}，只有被界面显式写入过的键才出现。
//
// 「set」标记是必要的：只用「值是否存在」判会把「显式设成默认值」与
// 「从未保存过」混为一谈，这正是项目里 SessionTicketsEnabled / AntiReplayEnabled
// 反复使用指针类型所规避的同一个坑。set 为 false 时该键按未覆盖处理。
//
// @param raw 覆盖表 JSON 文本；空串返回空覆盖。
// @param warns 告警累加目标；可为 nil。
// @return 解析后的覆盖表，恒非 nil。
func ParseStoredOverrides(raw string, warns *[]string) Overrides {
	out := Overrides{}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return out
	}
	var decoded map[string]struct {
		Value json.RawMessage `json:"value"`
		Set   bool            `json:"set"`
	}
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		appendWarn(warns, fmt.Sprintf("runtime_config_overrides is not valid JSON, falling back to the environment for every key: %v", err))
		return out
	}
	for key, stored := range decoded {
		if !stored.Set {
			appendWarn(warns, fmt.Sprintf("runtime_config_overrides key %q is not marked as set, ignoring it", key))
			continue
		}
		spec, ok := Lookup(key)
		if !ok {
			appendWarn(warns, fmt.Sprintf("runtime_config_overrides contains unknown key %q, ignoring it", key))
			continue
		}
		if !spec.IsWritable() {
			appendWarn(warns, fmt.Sprintf("runtime_config_overrides contains non-overridable key %q, ignoring it", key))
			continue
		}
		parsed, err := parseOverrideValue(spec, stored.Value)
		if err != nil {
			appendWarn(warns, fmt.Sprintf("runtime_config_overrides key %q is unusable, falling back to the environment: %v", key, err))
			continue
		}
		out[key] = parsed
	}
	return out
}

// EncodeStoredOverrides 把覆盖表编码成存储形态，键按字典序输出，
// 保证同一份覆盖表每次序列化结果逐字节一致（便于比对与缓存失效判定）。
//
// @param values 键名 -> 取值。
// @return 存储形态的 JSON 文本；无覆盖时返回 "{}"。
func EncodeStoredOverrides(values Overrides) (string, error) {
	if len(values) == 0 {
		return "{}", nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var buf strings.Builder
	buf.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return "", err
		}
		valueJSON, err := json.Marshal(values[key])
		if err != nil {
			return "", err
		}
		buf.Write(keyJSON)
		buf.WriteString(`:{"value":`)
		buf.Write(valueJSON)
		buf.WriteString(`,"set":true}`)
	}
	buf.WriteByte('}')
	return buf.String(), nil
}

// ParseSubmitValue 把端点提交的 JSON 原文转换为该键的规范取值。
// 校验口径与覆盖表解析完全一致，避免两条写入口产生不同的容忍度。
//
// @param spec 键的注册项。
// @param raw 提交的 JSON 原文。
// @return 规范取值；不合法时返回错误。
func ParseSubmitValue(spec Spec, raw json.RawMessage) (any, error) {
	if !spec.IsWritable() {
		return nil, fmt.Errorf("key %q is not overridable", spec.Key)
	}
	return parseOverrideValue(spec, raw)
}

// Kind 决定覆盖值的解析分支：时长类键的取值必须是可解析的 duration 文本，
// 其余三种按各自的 JSON 类型解析。
func parseOverrideValue(spec Spec, raw json.RawMessage) (any, error) {
	text := strings.TrimSpace(stripJSONQuotes(raw))
	switch spec.Kind {
	case KindBool:
		return parseOverrideBool(text, raw)
	case KindInt:
		return parseOverrideInt(spec, text, raw)
	case KindDuration:
		return parseOverrideDuration(spec, text)
	case KindString:
		return parseOverrideString(spec, text)
	default:
		return nil, fmt.Errorf("key %q has an unsupported kind %q", spec.Key, spec.Kind)
	}
}

func parseOverrideBool(text string, raw json.RawMessage) (any, error) {
	if text == "" {
		return nil, fmt.Errorf("value is empty")
	}
	// 只接受 JSON 布尔与字符串 true/false：把 0/1 之类接受下来会让
	// 「显式设成默认值」与「设了别的值」在界面与库里呈现不一致。
	if value, ok := parseStrictBool(text); ok {
		return value, nil
	}
	return nil, fmt.Errorf("value %s is not a boolean", string(raw))
}

func parseOverrideInt(spec Spec, text string, raw json.RawMessage) (any, error) {
	if text == "" {
		return nil, fmt.Errorf("value is empty")
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("value %s is not a number", text)
	}
	if math.Trunc(f) != f || f > math.MaxInt64 || f < math.MinInt64 {
		return nil, fmt.Errorf("value %s is not an integer", text)
	}
	return checkNumericRange(spec, int64(f))
}

// parseOverrideDuration 处理时长类键：取值必须是可解析的 Go duration 文本，
// 并按注册项声明的纳秒区间校验。
//
// 时长类键与字符串类键的**唯一**区别就在这里显式分支，而不是靠「Min/Max 是否非零」
// 反推：queue_write_interval 这类不设上界的键 Min/Max 都是 0，反推会把它们退化成
// 任意字符串，端点上就会放行一个不可解析的取值。
func parseOverrideDuration(spec Spec, text string) (any, error) {
	if text == "" {
		return nil, fmt.Errorf("value is empty")
	}
	d, err := time.ParseDuration(text)
	if err != nil {
		return nil, fmt.Errorf("value %q is not a valid duration", text)
	}
	if spec.Min != 0 && int64(d) < spec.Min {
		return nil, fmt.Errorf("value %s is below the minimum %s", text, time.Duration(spec.Min))
	}
	if d < 0 {
		return nil, fmt.Errorf("value %s is negative", text)
	}
	if spec.Max > 0 && int64(d) > spec.Max {
		return nil, fmt.Errorf("value %s exceeds the maximum %s", text, time.Duration(spec.Max))
	}
	// 规范化成 duration 文本，使同一份覆盖表每次序列化结果一致。
	return d.String(), nil
}

// parseOverrideString 处理字符串类键：取值原样保留（去首尾空白），
// 仅当注册项声明了白名单时按白名单校验。
func parseOverrideString(spec Spec, text string) (any, error) {
	if len(spec.EnumValues) == 0 {
		return text, nil
	}
	if text == "" {
		return nil, fmt.Errorf("value is empty")
	}
	for _, allowed := range spec.EnumValues {
		if strings.EqualFold(text, allowed) {
			return allowed, nil
		}
	}
	return nil, fmt.Errorf("value %s is not one of %s", text, strings.Join(spec.EnumValues, "|"))
}

// checkNumericRange 校验数值落在注册项声明的区间内。
//
// 口径沿用项目既有的 clampQueueInt 家族：下界越界视为不可用（回退环境变量），
// 上界越界视为不可用（拒绝写入），两条路径都由调用方记 WARN，不静默。
func checkNumericRange(spec Spec, value int64) (any, error) {
	if spec.Min != 0 && value < spec.Min {
		return nil, fmt.Errorf("value %d is below the minimum %d", value, spec.Min)
	}
	if value < 0 {
		return nil, fmt.Errorf("value %d is negative", value)
	}
	if spec.Max > 0 && value > spec.Max {
		return nil, fmt.Errorf("value %d exceeds the maximum %d", value, spec.Max)
	}
	return value, nil
}

func stripJSONQuotes(raw json.RawMessage) string {
	text := string(raw)
	if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
		var unquoted string
		if err := json.Unmarshal(raw, &unquoted); err == nil {
			return unquoted
		}
	}
	return text
}

func appendWarn(warns *[]string, message string) {
	if warns == nil {
		return
	}
	*warns = append(*warns, message)
}

// Resolve 解析单个键的三态。
//
// @param spec 键的注册项。
// @param overrides 解析后的覆盖表；nil 等价于空表。
// @param envRaw 环境变量原文（含空白；未设置时为空串）。
// @param envSet 环境变量是否已定义。用 os.LookupEnv 判定，以区分「设为空」与「未设置」：
//   - 未设置：直接采用内置默认值；
//   - 已定义但取值不可用（空串或解析失败）：同样回退默认值，但记 WARN。
//
// @param warns 告警累加目标；可为 nil。
// @return 生效值、来源与是否被覆盖。
func Resolve(spec Spec, overrides Overrides, envRaw string, envSet bool, warns *[]string) Entry {
	if value, ok := overrides[spec.Key]; ok {
		return Entry{Key: spec.Key, Value: value, Source: SourceDB, Overridden: true}
	}
	if envSet && spec.Env != "" && strings.TrimSpace(envRaw) != "" {
		if value, ok := resolveEnvValue(spec, envRaw); ok {
			return Entry{Key: spec.Key, Value: value, Source: SourceEnv}
		}
		appendWarn(warns, fmt.Sprintf("%s=%q is not a usable value, falling back to the default %v", spec.Env, envRaw, spec.DefaultValue))
	}
	return Entry{Key: spec.Key, Value: spec.DefaultValue, Source: SourceDefault}
}

// resolveEnvValue 按注册项声明的口径解析环境变量原文。
func resolveEnvValue(spec Spec, raw string) (any, bool) {
	if spec.ParseEnv == nil {
		return parseTrimmedString(raw)
	}
	return spec.ParseEnv(raw)
}

// ResolveAll 解析全部键。
//
// @param overrides 解析后的覆盖表；nil 等价于空表。
// @param lookup 环境变量查询函数；nil 表示使用进程环境。
// @param warns 告警累加目标；可为 nil。
// @return 键名 -> 三态解析结果。
func ResolveAll(overrides Overrides, lookup EnvLookup, warns *[]string) map[string]Entry {
	if overrides == nil {
		overrides = Overrides{}
	}
	if lookup == nil {
		lookup = os.LookupEnv
	}
	out := make(map[string]Entry, len(registry))
	for _, spec := range registry {
		raw, envSet := "", false
		if spec.Env != "" {
			raw, envSet = lookup(spec.Env)
		}
		out[spec.Key] = Resolve(spec, overrides, raw, envSet, warns)
	}
	return out
}
