package luaplugin

import (
	"time"

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
func buildContextTable(L *lua.LState, req RequestView, kv KVBackend) *lua.LTable {
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

	t.RawSetString("headers", stringMapToTable(L, req.Headers))
	t.RawSetString("query_params", stringMapToTable(L, req.QueryParams))

	tls := L.NewTable()
	tls.RawSetString("version", lua.LString(req.TLSVersion))
	tls.RawSetString("ja3", lua.LString(req.TLSJA3))
	tls.RawSetString("ja4", lua.LString(req.TLSJA4))
	tls.RawSetString("sni", lua.LString(req.TLSSNI))
	t.RawSetString("tls", tls)

	// 内置阶段的判定结果，仅 post 阶段非空。
	t.RawSetString("phase", lua.LString(req.Phase))
	t.RawSetString("action", lua.LString(req.Action))

	t.RawSetString("kv", buildKVTable(L, kv))
	return t
}

func stringMapToTable(L *lua.LState, m map[string]string) *lua.LTable {
	t := L.NewTable()
	for k, v := range m {
		t.RawSetString(k, lua.LString(v))
	}
	return t
}

// buildKVTable 构造 ctx.kv 的方法表。
//
// 后端不可用时各方法返回 nil/false 而非报错：Redis 故障应让策略降级，
// 而不是让脚本抛错、进而使请求判定失败。
func buildKVTable(L *lua.LState, kv KVBackend) *lua.LTable {
	t := L.NewTable()

	available := kv != nil && kv.Available()
	t.RawSetString("available", L.NewFunction(func(l *lua.LState) int {
		l.Push(lua.LBool(available))
		return 1
	}))

	t.RawSetString("get", L.NewFunction(func(l *lua.LState) int {
		if !available {
			l.Push(lua.LNil)
			return 1
		}
		key, ok := scriptKey(l.CheckString(1))
		if !ok {
			l.Push(lua.LNil)
			return 1
		}
		if raw, found := kv.Get(key); found {
			l.Push(lua.LString(raw))
		} else {
			l.Push(lua.LNil)
		}
		return 1
	}))

	t.RawSetString("set", L.NewFunction(func(l *lua.LState) int {
		if !available {
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
		l.Push(lua.LBool(kv.Set(key, []byte(value), ttl) == nil))
		return 1
	}))

	t.RawSetString("delete", L.NewFunction(func(l *lua.LState) int {
		if !available {
			return 0
		}
		if key, ok := scriptKey(l.CheckString(1)); ok {
			kv.Delete(key)
		}
		return 0
	}))

	// incr 是自定义限速的基础：原子自增并在首次写入时设置过期。
	t.RawSetString("incr", L.NewFunction(func(l *lua.LState) int {
		if !available {
			l.Push(lua.LNil)
			return 1
		}
		key, ok := scriptKey(l.CheckString(1))
		if !ok {
			l.Push(lua.LNil)
			return 1
		}
		n, err := kv.Incr(key, ttlFromArg(l, 2))
		if err != nil {
			l.Push(lua.LNil)
			return 1
		}
		l.Push(lua.LNumber(n))
		return 1
	}))

	return t
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
	if !ok || num <= 0 {
		return kvDefaultTTL
	}
	ttl := time.Duration(float64(num)) * time.Second
	if ttl > kvMaxTTL {
		return kvMaxTTL
	}
	return ttl
}
