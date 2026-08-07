package luaplugin

import (
	"context"
	"math"
	"sort"
	"time"
	"unicode/utf8"

	lua "github.com/yuin/gopher-lua"
)

const (
	// kvKeyPrefix 隔离脚本写入的键，防止脚本覆盖 WAF 自身的缓存键
	// （限速计数、挑战会话等都在同一 Redis 实例里）。
	kvKeyPrefix = "owaf:lua:"

	// kvMaxKeyLen / kvMaxValueLen 限制脚本可写入的键值体积，
	// 避免脚本把 Redis 当对象存储用。
	kvMaxKeyLen   = 256
	kvMaxValueLen = 64 * 1024

	// kvMaxTTL 是脚本可设置的最长过期时间。
	// 不允许无限期驻留：脚本被删除后其遗留数据也应自然清理。
	kvMaxTTL = 24 * time.Hour
	// kvDefaultTTL 用于脚本未指定 ttl 时。
	kvDefaultTTL = 5 * time.Minute
)

// buildContextTable 构造传给 handle(ctx) 的上下文表。
type apiBudget struct {
	calls int
}

func (b *apiBudget) allow() bool {
	if b == nil || b.calls >= maxAPICalls {
		return false
	}
	b.calls++
	return true
}

func buildContextTable(L *lua.LState, runCtx context.Context, req RequestView, kv KVBackend, budget *apiBudget) *lua.LTable {
	t := L.NewTable()

	t.RawSetString("request_id", lua.LString(req.RequestID))
	t.RawSetString("client_ip", lua.LString(req.ClientIP))
	t.RawSetString("method", lua.LString(req.Method))
	t.RawSetString("path", lua.LString(req.Path))
	t.RawSetString("query", lua.LString(req.RawQuery))
	t.RawSetString("host", lua.LString(req.Host))
	t.RawSetString("user_agent", lua.LString(req.UserAgent))
	t.RawSetString("site_id", lua.LNumber(req.SiteID))
	t.RawSetString("content_type", lua.LString(req.ContentType))
	t.RawSetString("body", lua.LString(req.Body))

	t.RawSetString("headers", stringMapToTable(L, req.Headers, false))
	t.RawSetString("query_params", stringMapToTable(L, req.QueryParams, false))
	t.RawSetString("query_values", stringSliceMapToTable(L, req.QueryValues))

	tls := L.NewTable()
	tls.RawSetString("version", lua.LString(req.TLSVersion))
	tls.RawSetString("ja3", lua.LString(req.TLSJA3))
	tls.RawSetString("ja4", lua.LString(req.TLSJA4))
	tls.RawSetString("sni", lua.LString(req.TLSSNI))
	t.RawSetString("tls", tls)

	// 内置阶段的判定结果，仅 post 阶段非空。
	t.RawSetString("phase", lua.LString(req.Phase))
	t.RawSetString("action", lua.LString(req.Action))
	verdict := L.NewTable()
	verdict.RawSetString("matched", lua.LBool(req.Verdict.Matched))
	verdict.RawSetString("phase", lua.LString(req.Verdict.Phase))
	verdict.RawSetString("action", lua.LString(req.Verdict.Action))
	verdict.RawSetString("category", lua.LString(req.Verdict.Category))
	verdict.RawSetString("rule_id", lua.LNumber(req.Verdict.RuleID))
	verdict.RawSetString("rule_id_str", lua.LString(req.Verdict.RuleIDStr))
	verdict.RawSetString("status_code", lua.LNumber(req.Verdict.StatusCode))
	verdict.RawSetString("redirect_to", lua.LString(req.Verdict.RedirectTo))
	verdict.RawSetString("tags", stringSliceToTable(L, req.Verdict.Tags))
	t.RawSetString("verdict", verdict)

	response := L.NewTable()
	response.RawSetString("status_code", lua.LNumber(req.Response.StatusCode))
	response.RawSetString("content_type", lua.LString(req.Response.ContentType))
	response.RawSetString("headers", stringMapToTable(L, req.Response.Headers, true))
	response.RawSetString("body", lua.LString(req.Response.Body))
	t.RawSetString("response", response)

	t.RawSetString("config", stringMapToTable(L, req.Config, false))
	t.RawSetString("runtime", stringMapToTable(L, req.Runtime, false))
	t.RawSetString("metrics", floatMapToTable(L, req.Metrics))
	t.RawSetString("kv", buildKVTable(L, runCtx, kv, budget))
	t.RawSetString("log", buildLogFunction(L, req.Log, budget))
	t.RawSetString("debug", buildDebugFunction(L, req.Debug, budget))
	return t
}

func stringMapToTable(L *lua.LState, m map[string]string, redact bool) *lua.LTable {
	t := L.NewTable()
	keys := sortedStringMapKeys(m)
	for i, k := range keys {
		if i >= maxAPIMapEntries {
			break
		}
		v := m[k]
		if redact && sensitiveHeader(k) {
			v = "[redacted]"
		}
		t.RawSetString(k, lua.LString(truncateString(v, maxAPIStringBytes)))
	}
	return t
}

func floatMapToTable(L *lua.LState, m map[string]float64) *lua.LTable {
	t := L.NewTable()
	keys := sortedFloatMapKeys(m)
	for i, k := range keys {
		if i >= maxAPIMapEntries {
			break
		}
		t.RawSetString(k, lua.LNumber(m[k]))
	}
	return t
}

func stringSliceMapToTable(L *lua.LState, values map[string][]string) *lua.LTable {
	t := L.NewTable()
	for i, key := range sortedStringSliceMapKeys(values) {
		if i >= maxAPIMapEntries {
			break
		}
		t.RawSetString(key, stringSliceToTable(L, values[key]))
	}
	return t
}

func stringSliceToTable(L *lua.LState, values []string) *lua.LTable {
	t := L.NewTable()
	for i, value := range values {
		if i >= maxAPIMapEntries {
			break
		}
		t.RawSetInt(i+1, lua.LString(truncateString(value, maxAPIStringBytes)))
	}
	return t
}

func sortedStringMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedFloatMapKeys(m map[string]float64) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedStringSliceMapKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func truncateString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	if limit <= 0 {
		return ""
	}
	end := limit
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end]
}

func sensitiveHeader(name string) bool {
	switch name {
	case "authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key":
		return true
	default:
		return false
	}
}

func buildLogFunction(L *lua.LState, logFn func(string, string), budget *apiBudget) *lua.LFunction {
	return L.NewFunction(func(l *lua.LState) int {
		if !budget.allow() || logFn == nil {
			return 0
		}
		level := l.CheckString(1)
		message := truncateString(l.CheckString(2), maxAPIStringBytes)
		logFn(level, message)
		return 0
	})
}

func buildDebugFunction(L *lua.LState, debugFn func(string), budget *apiBudget) *lua.LFunction {
	return L.NewFunction(func(l *lua.LState) int {
		if !budget.allow() || debugFn == nil {
			return 0
		}
		debugFn(truncateString(l.CheckString(1), maxAPIStringBytes))
		return 0
	})
}

// buildKVTable 构造 ctx.kv 的方法表。
//
// 后端不可用时各方法返回 nil/false 而非报错：Redis 故障应让策略降级，
// 而不是让脚本抛错、进而使请求判定失败。
func buildKVTable(L *lua.LState, runCtx context.Context, kv KVBackend, budget *apiBudget) *lua.LTable {
	t := L.NewTable()

	available := kv != nil && kv.Available()
	t.RawSetString("available", L.NewFunction(func(l *lua.LState) int {
		l.Push(lua.LBool(available))
		return 1
	}))

	t.RawSetString("get", L.NewFunction(func(l *lua.LState) int {
		if !available || !budget.allow() {
			l.Push(lua.LNil)
			return 1
		}
		key, ok := scriptKey(l.CheckString(1))
		if !ok {
			l.Push(lua.LNil)
			return 1
		}
		if raw, found := getKV(runCtx, kv, key); found {
			l.Push(lua.LString(raw))
		} else {
			l.Push(lua.LNil)
		}
		return 1
	}))

	t.RawSetString("set", L.NewFunction(func(l *lua.LState) int {
		if !available || !budget.allow() {
			l.Push(lua.LBool(false))
			return 1
		}
		key, ok := scriptKey(l.CheckString(1))
		value := l.CheckString(2)
		if !ok || len(value) > kvMaxValueLen {
			l.Push(lua.LBool(false))
			return 1
		}
		ttl := ttlFromArg(l, 3)
		l.Push(lua.LBool(setKV(runCtx, kv, key, []byte(value), ttl) == nil))
		return 1
	}))

	t.RawSetString("delete", L.NewFunction(func(l *lua.LState) int {
		if !available || !budget.allow() {
			return 0
		}
		if key, ok := scriptKey(l.CheckString(1)); ok {
			deleteKV(runCtx, kv, key)
		}
		return 0
	}))

	// incr 是自定义限速的基础：原子自增并在首次写入时设置过期。
	t.RawSetString("incr", L.NewFunction(func(l *lua.LState) int {
		if !available || !budget.allow() {
			l.Push(lua.LNil)
			return 1
		}
		key, ok := scriptKey(l.CheckString(1))
		if !ok {
			l.Push(lua.LNil)
			return 1
		}
		n, err := incrKV(runCtx, kv, key, ttlFromArg(l, 2))
		if err != nil {
			l.Push(lua.LNil)
			return 1
		}
		l.Push(lua.LNumber(n))
		return 1
	}))

	return t
}

func getKV(ctx context.Context, kv KVBackend, key string) ([]byte, bool) {
	if contextual, ok := kv.(ContextKVBackend); ok {
		return contextual.GetContext(ctx, key)
	}
	return kv.Get(key)
}

func setKV(ctx context.Context, kv KVBackend, key string, value []byte, ttl time.Duration) error {
	if contextual, ok := kv.(ContextKVBackend); ok {
		return contextual.SetContext(ctx, key, value, ttl)
	}
	return kv.Set(key, value, ttl)
}

func deleteKV(ctx context.Context, kv KVBackend, key string) {
	if contextual, ok := kv.(ContextKVBackend); ok {
		contextual.DeleteContext(ctx, key)
		return
	}
	kv.Delete(key)
}

func incrKV(ctx context.Context, kv KVBackend, key string, ttl time.Duration) (int64, error) {
	if contextual, ok := kv.(ContextKVBackend); ok {
		return contextual.IncrContext(ctx, key, ttl)
	}
	return kv.Incr(key, ttl)
}

// scriptKey 校验并加前缀。
// 键过长或为空时返回 false，由调用方降级为 nil/false。
func scriptKey(raw string) (string, bool) {
	if raw == "" || len(raw) > kvMaxKeyLen {
		return "", false
	}
	return kvKeyPrefix + raw, true
}

// ttlFromArg 读取可选的 TTL 参数（秒），并钳制到允许区间。
func ttlFromArg(l *lua.LState, idx int) time.Duration {
	if l.GetTop() < idx {
		return kvDefaultTTL
	}
	num, ok := l.Get(idx).(lua.LNumber)
	if !ok {
		return kvDefaultTTL
	}
	seconds := float64(num)
	if seconds <= 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return kvDefaultTTL
	}
	if seconds > float64(kvMaxTTL/time.Second) {
		return kvMaxTTL
	}
	ttl := time.Duration(math.Trunc(seconds)) * time.Second
	if ttl <= 0 {
		return kvDefaultTTL
	}
	return ttl
}
