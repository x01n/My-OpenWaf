// Package jsplugin 提供受限的 QuickJS 请求策略执行原型。
//
// 该包只负责脚本编译、请求快照输入和请求变更计划输出，不注册管理 API、
// 数据面钩子或响应处理器。
package jsplugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"My-OpenWaf/internal/store"
)

var (
	// ErrCGODisabled 表示当前原型未启用 QuickJS cgo 执行后端。
	ErrCGODisabled = errors.New("jsplugin: cgo is required for QuickJS execution")
	// ErrEngineClosed 表示引擎已经关闭。
	ErrEngineClosed = errors.New("jsplugin: engine is closed")
	// ErrNoSlot 表示有界执行槽池无法再接受请求。
	ErrNoSlot = errors.New("jsplugin: execution slot unavailable")
	// ErrScriptTimeout 表示脚本执行超过了配置的挂钟上限。
	ErrScriptTimeout = errors.New("jsplugin: script execution timed out")
	// ErrAsyncPromise 表示脚本返回了尚未完成的 Promise。
	ErrAsyncPromise = errors.New("jsplugin: asynchronous Promise is not supported")
)

const (
	// DefaultPoolSize 是默认的并发 QuickJS 槽数量。
	DefaultPoolSize = 4
	// DefaultCompiledCacheSize 是每个执行槽保留的已编译脚本数量上限。
	DefaultCompiledCacheSize = 256
	// DefaultMemoryLimit 是单个脚本运行时的默认 QuickJS 堆上限。
	DefaultMemoryLimit uint64 = 8 << 20
	// DefaultStackLimit 是单个脚本运行时的默认 QuickJS 栈上限。
	DefaultStackLimit uint64 = 512 << 10
	// DefaultTimeout 是单次脚本执行的默认挂钟上限。
	DefaultTimeout = 10 * time.Millisecond
	// MaxScriptBytes 限制脚本源码体积。
	MaxScriptBytes = 256 << 10
	// MaxMutationStringBytes 限制单个请求变更字符串字段体积。
	MaxMutationStringBytes = 16 << 10
	// MaxMutationHeaders 限制单次请求最多变更的请求头数量。
	MaxMutationHeaders = 128
	// MaxMutationHeaderValueBytes 限制单个请求头值体积。
	MaxMutationHeaderValueBytes = 8 << 10
	// MaxRequestSnapshotBodyBytes 限制传入脚本的请求体样本体积。
	MaxRequestSnapshotBodyBytes = 48 << 10
	// MaxRequestSnapshotStringBytes 限制快照中单个标量字段和 map 键值体积。
	MaxRequestSnapshotStringBytes = 16 << 10
	// MaxRequestSnapshotHeaders 限制传入脚本的请求头数量。
	MaxRequestSnapshotHeaders = 256
	// MaxRequestSnapshotQueryParams 限制传入脚本的查询参数数量。
	MaxRequestSnapshotQueryParams = 256
	// MaxRequestSnapshotBytes 限制 JSON 序列化后快照的体积，避免 Go/JS 双重放大。
	MaxRequestSnapshotBytes = 128 << 10
)

// RequestSnapshot 是传给 JavaScript 脚本的只读请求快照。
//
// 所有 map 在进入引擎前都会深拷贝并序列化，脚本无法直接修改调用方数据。
type RequestSnapshot struct {
	RequestID   string            `json:"request_id,omitempty"`
	SiteID      uint              `json:"site_id"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	RawQuery    string            `json:"raw_query,omitempty"`
	Host        string            `json:"host,omitempty"`
	ClientIP    string            `json:"client_ip,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Body        string            `json:"body,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	QueryParams map[string]string `json:"query_params,omitempty"`
}

// MutationPlan 是脚本返回的请求变更计划。
//
// 指针字段为 nil 表示不修改；非 nil（包括指向空字符串）表示显式替换。
// SetHeaders 用于新增或覆盖请求头，DeleteHeaders 用于删除请求头。该计划
// 只描述意图，不会在本包内直接修改 Hertz 或 net/http 请求。
type MutationPlan struct {
	Method        *string           `json:"method,omitempty"`
	Path          *string           `json:"path,omitempty"`
	RawQuery      *string           `json:"raw_query,omitempty"`
	Body          *string           `json:"body,omitempty"`
	SetHeaders    map[string]string `json:"set_headers,omitempty"`
	DeleteHeaders []string          `json:"delete_headers,omitempty"`
}

// ScriptOptions 配置脚本元数据和资源限制。
type ScriptOptions struct {
	// Name 用于错误信息和诊断；为空时使用默认名称。
	Name string
	// SiteIDs 为 nil 或空切片时表示全局脚本，否则只匹配列出的站点。
	SiteIDs []uint
	// MemoryLimit、StackLimit、Timeout 为零时分别使用默认值。
	MemoryLimit uint64
	StackLimit  uint64
	Timeout     time.Duration
}

// EngineOptions 配置有界的 QuickJS 槽池。
type EngineOptions struct {
	PoolSize          int
	CompiledCacheSize int
	MemoryLimit       uint64
	StackLimit        uint64
	Timeout           time.Duration
}

func (o ScriptOptions) normalized() (ScriptOptions, error) {
	if o.Name == "" {
		o.Name = "<js-plugin>"
	}
	if o.MemoryLimit == 0 {
		o.MemoryLimit = DefaultMemoryLimit
	}
	if o.StackLimit == 0 {
		o.StackLimit = DefaultStackLimit
	}
	if o.Timeout == 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Timeout < 0 {
		return ScriptOptions{}, errors.New("jsplugin: timeout must not be negative")
	}
	if len(o.SiteIDs) > 0 {
		ids := make([]uint, len(o.SiteIDs))
		copy(ids, o.SiteIDs)
		o.SiteIDs = ids
	}
	return o, nil
}

func (o EngineOptions) normalized() (EngineOptions, error) {
	if o.PoolSize == 0 {
		o.PoolSize = DefaultPoolSize
	}
	if o.PoolSize < 1 {
		return EngineOptions{}, errors.New("jsplugin: pool size must be positive")
	}
	if o.CompiledCacheSize == 0 {
		o.CompiledCacheSize = DefaultCompiledCacheSize
	}
	if o.CompiledCacheSize < 1 {
		return EngineOptions{}, errors.New("jsplugin: compiled cache size must be positive")
	}
	if o.MemoryLimit == 0 {
		o.MemoryLimit = DefaultMemoryLimit
	}
	if o.StackLimit == 0 {
		o.StackLimit = DefaultStackLimit
	}
	if o.Timeout == 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Timeout < 0 {
		return EngineOptions{}, errors.New("jsplugin: timeout must not be negative")
	}
	return o, nil
}

// AppliesTo 报告脚本是否适用于指定站点。
func (s *Script) AppliesTo(siteID uint) bool {
	if s == nil || len(s.siteIDs) == 0 {
		return s != nil
	}
	return s.siteIDs[siteID]
}

func normalizeRequestSnapshot(snapshot RequestSnapshot) (RequestSnapshot, error) {
	if _, err := encodeRequestSnapshot(snapshot); err != nil {
		return RequestSnapshot{}, err
	}

	normalized := snapshot
	if snapshot.Headers != nil {
		normalized.Headers = make(map[string]string, len(snapshot.Headers))
		for name, value := range snapshot.Headers {
			normalized.Headers[name] = value
		}
	}
	if snapshot.QueryParams != nil {
		normalized.QueryParams = make(map[string]string, len(snapshot.QueryParams))
		for name, value := range snapshot.QueryParams {
			normalized.QueryParams[name] = value
		}
	}
	return normalized, nil
}

// encodeRequestSnapshot 校验并将请求快照一次性编码为 QuickJS 输入。
func encodeRequestSnapshot(snapshot RequestSnapshot) (string, error) {
	if err := validateRequestSnapshot(snapshot); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return "", fmt.Errorf("jsplugin: request snapshot encoding failed: %w", err)
	}
	if len(encoded) > MaxRequestSnapshotBytes {
		return "", fmt.Errorf("jsplugin: request snapshot exceeds %d bytes", MaxRequestSnapshotBytes)
	}
	return string(encoded), nil
}

func validateRequestSnapshot(snapshot RequestSnapshot) error {
	for field, value := range map[string]string{
		"request_id":   snapshot.RequestID,
		"method":       snapshot.Method,
		"path":         snapshot.Path,
		"raw_query":    snapshot.RawQuery,
		"host":         snapshot.Host,
		"client_ip":    snapshot.ClientIP,
		"user_agent":   snapshot.UserAgent,
		"content_type": snapshot.ContentType,
	} {
		if len(value) > MaxRequestSnapshotStringBytes {
			return fmt.Errorf("jsplugin: request snapshot %s exceeds %d bytes", field, MaxRequestSnapshotStringBytes)
		}
	}
	if len(snapshot.Body) > MaxRequestSnapshotBodyBytes {
		return fmt.Errorf("jsplugin: request snapshot body exceeds %d bytes", MaxRequestSnapshotBodyBytes)
	}
	if len(snapshot.Headers) > MaxRequestSnapshotHeaders {
		return fmt.Errorf("jsplugin: request snapshot headers exceed %d entries", MaxRequestSnapshotHeaders)
	}
	if len(snapshot.QueryParams) > MaxRequestSnapshotQueryParams {
		return fmt.Errorf("jsplugin: request snapshot query params exceed %d entries", MaxRequestSnapshotQueryParams)
	}
	for name, value := range snapshot.Headers {
		if len(name) > MaxRequestSnapshotStringBytes || len(value) > MaxRequestSnapshotStringBytes {
			return errors.New("jsplugin: request snapshot header exceeds size limit")
		}
	}
	for name, value := range snapshot.QueryParams {
		if len(name) > MaxRequestSnapshotStringBytes || len(value) > MaxRequestSnapshotStringBytes {
			return errors.New("jsplugin: request snapshot query parameter exceeds size limit")
		}
	}
	return nil
}

// ValidateMutationPlan 在 host 应用前校验请求变更计划。
//
// 此处承载 request-stage 的完整安全边界，dry-run 与数据面必须使用同一校验，
// 防止已通过 dry-run 的计划在真实请求中被拒绝。
func ValidateMutationPlan(plan MutationPlan) error {
	if err := validateMutationPlan(plan); err != nil {
		return err
	}
	if plan.Method != nil && !isJSHTTPToken(*plan.Method) {
		return errors.New("jsplugin: invalid method mutation")
	}
	if plan.Path != nil {
		if err := validateJSPath(*plan.Path); err != nil {
			return err
		}
	}
	if plan.RawQuery != nil {
		if strings.ContainsAny(*plan.RawQuery, "#\r\n") {
			return errors.New("jsplugin: invalid raw query mutation")
		}
		if _, err := url.ParseQuery(*plan.RawQuery); err != nil {
			return fmt.Errorf("jsplugin: invalid raw query mutation: %w", err)
		}
	}
	set := make(map[string]struct{}, len(plan.SetHeaders))
	for name, value := range plan.SetHeaders {
		lower := strings.ToLower(name)
		if !isJSHTTPToken(name) || isForbiddenJSHeader(lower) || !isValidJSHeaderValue(value) {
			return errors.New("jsplugin: forbidden or invalid header mutation")
		}
		if _, exists := set[lower]; exists {
			return errors.New("jsplugin: duplicate header mutation")
		}
		set[lower] = struct{}{}
	}
	for _, name := range plan.DeleteHeaders {
		lower := strings.ToLower(name)
		if !isJSHTTPToken(name) || isForbiddenJSHeader(lower) {
			return errors.New("jsplugin: forbidden or invalid header deletion")
		}
		if _, ok := set[lower]; ok {
			return errors.New("jsplugin: header cannot be set and deleted in one mutation")
		}
	}
	return nil
}

func validateJSPath(path string) error {
	if path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\r\n") {
		return errors.New("jsplugin: invalid path mutation")
	}
	for i := 0; i < len(path); i++ {
		if path[i] < 0x20 || path[i] == 0x7f {
			return errors.New("jsplugin: invalid path mutation")
		}
	}
	parsed, err := url.ParseRequestURI(path)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("jsplugin: invalid path mutation")
	}
	return nil
}

func isJSHTTPToken(value string) bool {
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

func isForbiddenJSHeader(name string) bool {
	switch name {
	case "host", "content-length", "transfer-encoding", "connection", "keep-alive", "te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization", "proxy-connection":
		return true
	default:
		return false
	}
}

func isValidJSHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == '\t' {
			continue
		}
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}

func validateMutationPlan(plan MutationPlan) error {
	for field, value := range map[string]*string{
		"method":    plan.Method,
		"path":      plan.Path,
		"raw_query": plan.RawQuery,
		"body":      plan.Body,
	} {
		if value != nil && len(*value) > MaxMutationStringBytes {
			return fmt.Errorf("jsplugin: %s exceeds %d bytes", field, MaxMutationStringBytes)
		}
	}
	if len(plan.SetHeaders) > MaxMutationHeaders || len(plan.DeleteHeaders) > MaxMutationHeaders {
		return fmt.Errorf("jsplugin: mutation headers exceed %d entries", MaxMutationHeaders)
	}
	for name, value := range plan.SetHeaders {
		if invalidMutationHeader(name, value) {
			return errors.New("jsplugin: invalid mutation header")
		}
	}
	for _, name := range plan.DeleteHeaders {
		if invalidMutationHeader(name, "") {
			return errors.New("jsplugin: invalid deleted header")
		}
	}
	return nil
}

func Validate(stage, source string) error {
	return ValidateWithOptions(stage, source, ScriptOptions{Name: "<js-plugin-validate>"})
}

// ValidateWithOptions 使用指定的运行选项编译校验 JavaScript 插件。
func ValidateWithOptions(stage, source string, options ScriptOptions) error {
	if stage != store.JSStageRequest && stage != store.JSStageResponse {
		return errors.New("stage must be request or response")
	}
	if options.Name == "" {
		options.Name = "<js-plugin-validate>"
	}
	_, err := Compile("<validate>", source, options)
	return err
}

func invalidMutationHeader(name, value string) bool {
	return name == "" || len(name) > MaxMutationHeaderValueBytes ||
		len(value) > MaxMutationHeaderValueBytes || strings.ContainsAny(name+value, "\r\n")
}
