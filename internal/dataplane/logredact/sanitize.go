package logredact

import (
	"encoding/json"
	"mime"
	"net/url"
	"regexp"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
)

var sensitiveLogHeaderLinePattern = regexp.MustCompile(`(?im)^([ \t]*(proxy-authorization|authorization|set-cookie|cookie)[ \t]*:)[^\r\n]*(\r?\n[ \t]+[^\r\n]*)*`)
var sensitiveLogObjectPattern = regexp.MustCompile(`(?is)(env)(["'\s:=]+)(\{.*)`)
var sensitiveLogValuePattern = regexp.MustCompile(`(?i)(proxy-authorization|authorization|set-cookie|cookie|password|passwd|pwd|token|secret|session|api[_-]?key|auth[_-]?token|csrf|code|ticket|env)(["'\s:=]+)([^&,"'}\r\n]+)`)

func IsDynamicProtectionKeyPath(c *app.RequestContext, loggedPath string) bool {
	if loggedPath == GroupKeyPath {
		return true
	}
	return c != nil && string(c.Path()) == GroupKeyPath
}

/**
 * GroupKeyPath 是动态保护取密钥端点的路由。该字符串是数据面内部路由约定，
 * 不是可配置项。
 *
 * 全仓仅此一处声明：父包 handler.go 的动态保护处理与请求体脱敏都引用它。
 * 早先它曾是父包的一个未导出常量，切分脱敏组时产生过「两处独立声明」的
 * 双常量状态——那种状态下任一处单独修改都会让 requestBodyPreview 不再对
 * 密钥端点返回 "[redacted]"，把动态保护密钥静默写进访问日志。因此这里保持
 * 单一声明，父包不得再自行定义一个同值常量。
 */
const GroupKeyPath = "/__owaf/dynamic/key"

/**
 * SanitizeUpstreamURL 在把上游端点写入日志之前移除 URL 中的 userinfo。
 *
 * @param raw 已配置的上游 URL。
 * @returns 去掉 userinfo 的上游 URL；解析失败时返回脱敏标记。
 */
func SanitizeUpstreamURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "[redacted]"
	}
	if parsed.User == nil {
		return raw
	}
	parsed.User = nil
	return parsed.String()
}

/**
 * SanitizeQueryString 对查询串做结构化脱敏，敏感键的取值整体遮蔽。
 *
 * @param raw 原始查询串，不含前导 '?'。
 * @return 脱敏后的查询串；无法可靠解析时返回 "[redacted]"。
 */
func SanitizeQueryString(raw string) string {
	if raw == "" {
		return ""
	}
	if !strings.ContainsAny(raw, "&=%") && !isSensitiveLogKey(raw) {
		return raw
	}
	if strings.IndexByte(raw, '&') < 0 {
		key, sanitized, changed, malformed := sanitizeQueryPair(raw)
		if malformed {
			return "[redacted]"
		}
		if !changed {
			return raw
		}
		values := make(url.Values, 1)
		values.Add(key, sanitized)
		return values.Encode()
	}
	values := make(url.Values)
	changed := false
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		key, sanitized, pairChanged, malformed := sanitizeQueryPair(pair)
		if malformed {
			return "[redacted]"
		}
		if pairChanged {
			changed = true
		}
		values.Add(key, sanitized)
	}
	if !changed {
		return raw
	}
	return values.Encode()
}

/**
 * sanitizeQueryPair 处理单个非空查询片段：按 '=' 拆分、解码、键遮蔽判定与取值脱敏。
 *
 * @param pair 已确认非空的查询片段。
 * @return key 解码后的键；sanitized 可安全写入日志的取值；changed 本片段是否被改写；
 *         malformed 为 true 表示键或取值解码失败，调用方应整体遮蔽。
 */
func sanitizeQueryPair(pair string) (key, sanitized string, changed, malformed bool) {
	rawKey, rawValue := pair, ""
	if i := strings.IndexByte(pair, '='); i >= 0 {
		rawKey, rawValue = pair[:i], pair[i+1:]
	}
	decodedKey, err := url.QueryUnescape(rawKey)
	if err != nil {
		return "", "", false, true
	}
	value, err := url.QueryUnescape(rawValue)
	if err != nil {
		return "", "", false, true
	}
	if isSensitiveLogKey(decodedKey) {
		return decodedKey, "[redacted]", true, false
	}
	sanitized = SanitizeLogText(value)
	return decodedKey, sanitized, sanitized != value, false
}

/**
 * queryParams 以与 net/url 相同的解码规则生成 Lua 可见的查询参数。
 * 重复键保留第一个值，与 dry-run 的 map 契约一致；解析失败时返回 nil。
 */
func SanitizeBodyPreview(body, contentType string) string {
	if body == "" {
		return ""
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	switch mediaType {
	case "application/x-www-form-urlencoded":
		return SanitizeQueryString(body)
	case "application/json":
		var value any
		if json.Unmarshal([]byte(body), &value) == nil {
			return marshalSanitizedJSON(value)
		}
	}
	return SanitizeLogText(body)
}

func marshalSanitizedJSON(value any) string {
	data, err := json.Marshal(sanitizeJSONValue(value))
	if err != nil {
		return ""
	}
	return string(data)
}

func sanitizeJSONValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			if isSensitiveLogKey(key) {
				out[key] = "[redacted]"
			} else {
				out[key] = sanitizeJSONValue(item)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = sanitizeJSONValue(item)
		}
		return out
	case string:
		return SanitizeLogText(v)
	default:
		return value
	}
}

/**
 * SensitiveLogValueHints 是 sensitiveLogValuePattern 首个捕获组的字面量集合。
 *
 * 正则含 (?i)，故这里全部为小写，判定前先把输入转为小写比较。任何一项都不出现时，
 * 正则必然无法匹配，可直接跳过 ReplaceAllString。
 *
 * 与正则保持同步：新增关键字时两处都要改，由 TestSensitiveLogValueHintsCoverPattern
 * 兜住漏改。
 */
var SensitiveLogValueHints = []string{
	"password", "passwd", "pwd", "token", "secret", "session",
	"api_key", "api-key", "apikey", "auth_token", "auth-token", "authtoken",
	"authorization", "proxy-authorization", "cookie", "set-cookie",
	"csrf", "code", "ticket", "env",
}

/**
 * SanitizeLogText 遮蔽文本中形如 key=value 的敏感取值。
 *
 * 绝大多数 header value 不含任何敏感关键字，而正则即使无匹配也要扫完整串。
 * 因此先做一次廉价的字面量预筛，命中才跑正则。
 *
 * @param value 待脱敏的原始文本。
 * @return 敏感取值已替换为 [redacted] 的文本；无敏感内容时原样返回。
 */
func SanitizeLogText(value string) string {
	// 快路径：只做大小写无关的字面量子串扫描（零分配），任一关键字
	// 都不出现时三个正则必然无法匹配——尤其是 (?i)(code|env|pwd|...) 这类
	// 短关键字正则确实会在错误的前提下全串回溯扫描。
	if !ContainsSensitiveLogHintFold(value) {
		return value
	}
	value = sensitiveLogHeaderLinePattern.ReplaceAllString(value, `${1} [redacted]`)
	value = sensitiveLogObjectPattern.ReplaceAllString(value, `${1}${2}[redacted]`)
	return sensitiveLogValuePattern.ReplaceAllString(value, `${1}${2}[redacted]`)
}

var sensitiveLogHintFirstFold = func() (m [256]bool) {
	for _, h := range SensitiveLogValueHints {
		if h == "" {
			continue
		}
		c := h[0]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		m[c] = true
	}
	return m
}()

// sensitiveLogHintByFirstFold 按「首字节的折叠小写值」把提示词分组。
//
// 原实现对每个可能的首字节位置遍历全部提示词做长度检查与首字节比较，
// 单值 20 次内层迭代。分组后内层只处理首字节同组的 1-3 个提示词，
// 判定条件与逐词顺序均不变（同组内保持原表顺序），逐字节等价。
var sensitiveLogHintByFirstFold = func() (m [256][]string) {
	for _, h := range SensitiveLogValueHints {
		if h == "" {
			continue
		}
		c := h[0]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		m[c] = append(m[c], h)
	}
	return m
}()

func ContainsSensitiveLogHintFold(value string) bool {
	if value == "" {
		return false
	}
	l := len(value)
	for i := 0; i < l; i++ {
		f := value[i]
		if 'A' <= f && f <= 'Z' {
			f += 'a' - 'A'
		}
		group := sensitiveLogHintByFirstFold[f]
		if len(group) == 0 {
			continue
		}
		for _, hint := range group {
			hl := len(hint)
			if i+hl > l {
				continue
			}
			if asciiFoldPrefix(value[i:i+hl], hint) {
				return true
			}
		}
	}
	return false
}

// asciiFoldPrefix 判断 s 是否与 lower 前缀（全小写）ASCII 大小写无关相等。
func asciiFoldPrefix(s, lower string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != lower[i] {
			return false
		}
	}
	return true
}

func TruncateLogValue(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "...[truncated]"
}

// sensitiveLogKeyParts 是需要整体遮蔽取值的 header 名片段（全小写）。
var sensitiveLogKeyParts = []string{
	"authorization", "cookie", "token", "secret", "password", "passwd", "pwd",
	"session", "api-key", "apikey", "csrf", "credential", "key", "ticket", "env",
}

// isSensitiveLogKey 判断 header 名是否属于敏感项。接受任意大小写。
func isSensitiveLogKey(key string) bool {
	return IsSensitiveLogKeyLowered(ToLowerASCII(key))
}

/**
 * IsSensitiveLogKeyLowered 与 isSensitiveLogKey 相同，但要求入参已是小写。
 *
 * 调用方通常已为别处算过一次小写形式，再在函数内重复转换是白做一遍 O(n) 扫描。
 *
 * @param lower 已转为小写的 header 名。
 * @return 属于敏感项则为 true。
 */
func IsSensitiveLogKeyLowered(lower string) bool {
	for _, part := range sensitiveLogKeyParts {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}
