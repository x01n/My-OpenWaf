// Package jsplugin 提供受限的 QuickJS 请求策略执行原型。
//
// 该包只负责脚本编译、请求快照输入和请求变更计划输出，不注册管理 API、
// 数据面钩子或响应处理器。
package jsplugin

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrCGODisabled 表示当前原型未启用 QuickJS cgo 执行后端。
	ErrCGODisabled = errors.New("jsplugin: cgo is required for QuickJS execution")
	// ErrEngineClosed 表示引擎已经关闭。
	ErrEngineClosed = errors.New("jsplugin: engine is closed")
	// ErrNoSlot 表示有界执行槽池无法再接受请求。
	ErrNoSlot = errors.New("jsplugin: execution slot unavailable")
)

const (
	// DefaultPoolSize 是默认的并发 QuickJS 槽数量。
	DefaultPoolSize = 4
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
	PoolSize    int
	MemoryLimit uint64
	StackLimit  uint64
	Timeout     time.Duration
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
		if name == "" || len(name) > MaxMutationHeaderValueBytes || len(value) > MaxMutationHeaderValueBytes {
			return errors.New("jsplugin: invalid mutation header")
		}
	}
	for _, name := range plan.DeleteHeaders {
		if name == "" || len(name) > MaxMutationHeaderValueBytes {
			return errors.New("jsplugin: invalid deleted header")
		}
	}
	return nil
}
