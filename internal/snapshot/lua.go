package snapshot

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/luaplugin"
)

// luaSnapshotValidationKV 为快照构建期提供隔离的、可用的 KV 语义。
// 它只存在于当前脚本校验调用，不连接生产 Redis，也不保留跨请求状态。
type luaSnapshotValidationKV struct {
	mu     sync.Mutex
	values map[string][]byte
}

func newLuaSnapshotValidationKV() *luaSnapshotValidationKV {
	return &luaSnapshotValidationKV{values: make(map[string][]byte)}
}

func (k *luaSnapshotValidationKV) Available() bool { return k != nil }

func (k *luaSnapshotValidationKV) AvailableContext(ctx context.Context) bool {
	return k != nil && (ctx == nil || ctx.Err() == nil)
}

func (k *luaSnapshotValidationKV) Get(key string) ([]byte, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	value, ok := k.values[key]
	return append([]byte(nil), value...), ok
}

func (k *luaSnapshotValidationKV) Set(key string, value []byte, _ time.Duration) error {
	k.mu.Lock()
	k.values[key] = append([]byte(nil), value...)
	k.mu.Unlock()
	return nil
}

func (k *luaSnapshotValidationKV) Delete(key string) {
	k.mu.Lock()
	delete(k.values, key)
	k.mu.Unlock()
}

func (k *luaSnapshotValidationKV) Incr(key string, _ time.Duration) (int64, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	value := int64(1)
	if raw, ok := k.values[key]; ok {
		parsed, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("validation KV value is not an integer: %w", err)
		}
		value = parsed + 1
	}
	k.values[key] = []byte(strconv.FormatInt(value, 10))
	return value, nil
}

func (k *luaSnapshotValidationKV) GetContext(_ context.Context, key string) ([]byte, bool) {
	return k.Get(key)
}

func (k *luaSnapshotValidationKV) SetContext(_ context.Context, key string, value []byte, ttl time.Duration) error {
	return k.Set(key, value, ttl)
}

func (k *luaSnapshotValidationKV) DeleteContext(_ context.Context, key string) { k.Delete(key) }

func (k *luaSnapshotValidationKV) IncrContext(_ context.Context, key string, ttl time.Duration) (int64, error) {
	return k.Incr(key, ttl)
}

func validateLuaSnapshotScript(ctx context.Context, script *luaplugin.Script, row *store.LuaPlugin) error {
	if script == nil || row == nil {
		return nil
	}
	result := luaplugin.DryRunNContext(ctx, luaplugin.Stage(row.Stage), row.Source, luaplugin.RequestView{
		RequestID: "lua-snapshot-validation",
		ClientIP:  "192.0.2.1",
		Method:    "GET",
		Path:      "/",
		Host:      "validation.invalid",
		UserAgent: "My-OpenWaf validation",
		SiteID: func() uint {
			if row.SiteID != nil {
				return *row.SiteID
			}
			return 0
		}(),
	}, newLuaSnapshotValidationKV(), time.Duration(row.TimeoutMS)*time.Millisecond, 1)
	if result.CompileError != "" {
		return fmt.Errorf("lua compile validation failed: %s", result.CompileError)
	}
	if result.RuntimeError != "" {
		return fmt.Errorf("lua runtime validation failed: %s", result.RuntimeError)
	}
	return nil
}

/**
 * loadLuaPlugins 读取启用的 Lua 脚本、编译并执行隔离运行时契约检查。
 *
 * 单个脚本编译或运行时契约检查失败不返回错误，而是记入 errors 映射：一处脚本
 * 错误不应导致整次配置重载失败，也不应让错误脚本进入数据面执行链。调用方通过
 * Snapshot.LuaPluginErrors 把失败暴露给管理端。
 *
 * @param db 数据库句柄。
 * @return 已编译脚本、按脚本名索引的编译错误、数据库查询错误。单个脚本编译错误仍记录在 errors 映射中。
 */
func loadLuaPlugins(db *gorm.DB) ([]*luaplugin.Script, map[string]string, error) {
	if !db.Migrator().HasTable(&store.LuaPlugin{}) {
		return nil, nil, nil
	}
	var rows []store.LuaPlugin
	// 排序决定同阶段内的执行顺序，priority 相同时按 id 兜底以保证稳定。
	if err := db.Where("enabled = ?", true).
		Order("stage ASC, priority ASC, id ASC").
		Find(&rows).Error; err != nil {
		return nil, nil, err
	}
	if len(rows) == 0 {
		return nil, nil, nil
	}

	scripts := make([]*luaplugin.Script, 0, len(rows))
	var errs map[string]string

	for i := range rows {
		row := &rows[i]
		stage := luaplugin.Stage(row.Stage)
		if !stage.Valid() {
			if errs == nil {
				errs = make(map[string]string)
			}
			errs[row.Name] = "unsupported stage " + row.Stage + " (want pre or post)"
			continue
		}

		script, err := luaplugin.Compile(row.Name, stage, row.Source)
		if err != nil {
			if errs == nil {
				errs = make(map[string]string)
			}
			errs[row.Name] = err.Error()
			continue
		}
		script.SetID(row.ID)
		script.SetSiteID(row.SiteID)
		if row.TimeoutMS > 0 {
			script.SetTimeout(time.Duration(row.TimeoutMS) * time.Millisecond)
		}
		if validationErr := validateLuaSnapshotScript(context.Background(), script, row); validationErr != nil {
			if errs == nil {
				errs = make(map[string]string)
			}
			errs[row.Name] = validationErr.Error()
			continue
		}
		scripts = append(scripts, script)
	}

	return scripts, errs, nil
}
