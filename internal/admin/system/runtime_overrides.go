package system

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/gorm"

	"My-OpenWaf/internal/core/configoverride"
	"My-OpenWaf/internal/pkg/logger"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// RuntimeConfigOverrideItem 是端点返回的单个键的完整状态。
//
// 字段名与冻结契约第 2 节逐字对齐：`env` / `group` / `sensitive` / `value` /
// `label_key` / `description_key` 是前端直接消费的字段，改名等于让界面读空。
type RuntimeConfigOverrideItem struct {
	// Key 是覆盖表与写接口使用的稳定键名。
	Key string `json:"key"`
	// Env 是环境变量名；空串表示该键没有环境变量载体。
	Env string `json:"env"`
	// Group 是功能域，界面用它分组；取值见 configoverride.Group* 常量。
	Group string `json:"group"`
	// Type 是取值类型：bool / int / string / duration。
	Type string `json:"type"`
	// DefaultValue 是内置默认值，类型与 Type 一致。
	DefaultValue any `json:"default_value"`
	// EnvValue 是环境变量自身的解析取值；未设置或不可用时为 null。密钥类恒为 null。
	EnvValue any `json:"env_value"`
	// EffectiveValue 是当前真正生效的值；密钥类为空串。
	EffectiveValue any `json:"effective_value"`
	// Source 是生效值来源：env（环境变量）/ db（覆盖表）/ default（内置默认值）。
	Source string `json:"source"`
	// Overridden 为真表示覆盖表里存在该键。
	Overridden bool `json:"overridden"`
	// Value 是覆盖表里存的值；Overridden 为假时是 null。
	Value any `json:"value"`
	// Sensitive 为真时 EnvValue/Value/EffectiveValue 不回显真值。
	Sensitive bool `json:"sensitive"`
	// Editable 为真表示该键可经本端点写入覆盖表。
	Editable bool `json:"editable"`
	// Min/Max 是数值与时长键的区间；无边界时是显式 null（不得 omitempty 省略，
	// 前端按 `min !== null || max !== null` 决定是否展示区间）。
	Min *int64 `json:"min"`
	Max *int64 `json:"max"`
	// LabelKey 是该键的界面标题 i18n 键，恒为 "envOverrides.key." + Key。
	LabelKey string `json:"label_key"`
	// DescriptionKey 是该键的界面说明 i18n 键，恒为 "envOverrides.key." + Key + ".desc"。
	DescriptionKey string `json:"description_key"`

	// ---- 以下为契约允许附加、前端当前不消费的诊断字段 ----
	//
	// Scope 是可写性来源：runtime 可覆盖；delegated 走专用端点；bootstrap 必须留在
	// 环境变量；test_only 仅供测试。
	Scope string `json:"scope"`
	// DelegatedTo 是 delegated 键的专用端点路径。
	DelegatedTo string `json:"delegated_to,omitempty"`
	// EnvSet 为真表示环境变量已定义且取值可用。
	EnvSet bool `json:"env_set"`
	// SecretSet 在 Sensitive 为真时表示生效取值是否非空。
	SecretSet bool `json:"secret_set"`
	// RestartRequired 为真时覆盖要等进程重启才生效。
	RestartRequired bool `json:"restart_required"`
	// Description 是面向界面的中文说明原文。
	Description string `json:"description"`
	// EnumValues 是白名单类键的合法取值。
	EnumValues []string `json:"enum_values,omitempty"`
	// ShadowedBy 是只读诊断：本键写进覆盖表后，是否会被更具体的来源顶掉。
	// 取值 ""（未被顶掉）/ "protection_row"（全局 protection 设置行整体顶掉）/
	// "site_override"（存在启用站点带站点级 CVE 开关，不采用全局值）。
	// 只对 cve_enabled / cve_auto_drop_critical / cve_auto_drop_high 三键可能非空，
	// 且仅在 overridden=true 时有意义。前端不消费也无害。
	ShadowedBy string `json:"shadowed_by"`
}

// RuntimeConfigOverridesResponse 是覆盖清单的响应体。
//
// GET 与 POST 返回同一形状：POST 是写后回读。
type RuntimeConfigOverridesResponse struct {
	// Groups 是全部域的元数据，顺序固定。
	Groups []RuntimeConfigOverrideGroup `json:"groups"`
	// Items 是全部注册键的三态状态。
	Items []RuntimeConfigOverrideItem `json:"items"`
	// Warnings 是覆盖表解析过程中的逐键告警（未知键、类型不匹配、越界等）。
	Warnings []string `json:"warnings"`
	// Stored 是库里覆盖表的原始文本，便于界面诊断。
	Stored string `json:"stored"`
}

// RuntimeConfigOverrideGroup 是响应 groups[] 的一个元素。
type RuntimeConfigOverrideGroup struct {
	Key      string `json:"key"`
	LabelKey string `json:"label_key"`
}

// ListRuntimeConfigOverrides 返回全部注册键的三态状态。
//
// 只读端点，与 /runtime-config 同组：admin / operator / readonly 均可查看。
func ListRuntimeConfigOverrides(repo *repository.SystemSettingsRepo, db *gorm.DB) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, buildRuntimeConfigOverridesResponse(repo, db))
	}
}

// buildRuntimeConfigOverridesResponse 读取覆盖表并展开成完整的响应体。
//
// GET 与 POST 共用：两条路径返回同一形状是契约要求，各写一份必然漂移。
//
// @param repo 系统设置仓储。既是覆盖表的来源，也用于判断 protection 设置行是否存在。
// @param db   主库句柄，用于统计带站点级 CVE 开关的启用站点；nil 时该诊断退化为空。
func buildRuntimeConfigOverridesResponse(repo *repository.SystemSettingsRepo, db *gorm.DB) RuntimeConfigOverridesResponse {
	raw := readRuntimeConfigOverridesRaw(repo)
	var warns []string
	overrides := configoverride.ParseStoredOverrides(raw, &warns)
	entries := configoverride.ResolveAll(overrides, nil, &warns)
	return RuntimeConfigOverridesResponse{
		Groups:   buildRuntimeConfigOverrideGroups(),
		Items:    buildRuntimeConfigOverrideItems(entries, buildShadowState(repo, db)),
		Warnings: warns,
		Stored:   raw,
	}
}

func readRuntimeConfigOverridesRaw(repo *repository.SystemSettingsRepo) string {
	if repo == nil {
		return ""
	}
	value, err := repo.Get(store.SettingKeyRuntimeConfigOverrides)
	if err != nil {
		return ""
	}
	return value
}

// buildRuntimeConfigOverrideGroups 把域的固定顺序展开成响应 groups[]。
func buildRuntimeConfigOverrideGroups() []RuntimeConfigOverrideGroup {
	groups := configoverride.Groups()
	out := make([]RuntimeConfigOverrideGroup, 0, len(groups))
	for _, group := range groups {
		out = append(out, RuntimeConfigOverrideGroup{Key: group.Key, LabelKey: group.LabelKey})
	}
	return out
}

// buildRuntimeConfigOverrideItems 把三态解析结果展开成端点返回的清单。
func buildRuntimeConfigOverrideItems(entries map[string]configoverride.Entry, shadow shadowState) []RuntimeConfigOverrideItem {
	specs := configoverride.All()
	items := make([]RuntimeConfigOverrideItem, 0, len(specs))
	for _, spec := range specs {
		entry := entries[spec.Key]
		envValue, envSet := envValueForSpec(spec)
		item := RuntimeConfigOverrideItem{
			Key:             spec.Key,
			Env:             spec.Env,
			Group:           spec.Group,
			Type:            string(spec.Kind),
			Source:          string(entry.Source),
			Overridden:      entry.Overridden,
			EnvSet:          envSet,
			DefaultValue:    spec.DefaultValue,
			Min:             boundOrNil(spec.Min),
			Max:             boundOrNil(spec.Max),
			EnumValues:      spec.EnumValues,
			Sensitive:       spec.Secret,
			Editable:        spec.IsWritable(),
			Scope:           string(spec.Scope),
			DelegatedTo:     spec.DelegatedTo,
			RestartRequired: spec.RestartRequired,
			LabelKey:        spec.LabelKey(),
			DescriptionKey:  spec.DescriptionKey(),
			Description:     spec.Description,
			ShadowedBy:      shadowFor(spec.Key, entry, shadow),
		}
		if entry.Overridden {
			item.Value = entry.Value
		}
		if spec.Secret {
			// 密钥类一律不回显真值：只回报「已设置」，与 RedisConfigResponse.PasswordSet 同构。
			item.SecretSet = secretValuePresent(entry.Value)
			item.EffectiveValue = ""
			item.EnvValue = nil
			items = append(items, item)
			continue
		}
		item.EffectiveValue = entry.Value
		if envSet {
			item.EnvValue = envValue
		}
		items = append(items, item)
	}
	return items
}

// boundOrNil 把注册表里的「0 表示不设边界」转换成响应所需的显式 null。
//
// 不能靠 omitempty 让 0 消失：契约要求 min/max 必须出现，前端用
// `item.min !== null` 判断是否展示区间，字段缺失与「无边界」在 JSON 里
// 无法区分。
func boundOrNil(bound int64) *int64 {
	if bound == 0 {
		return nil
	}
	value := bound
	return &value
}

// envValueForSpec 只按环境变量解析某键的取值（不经过覆盖表），
// 使界面能同时展示「环境变量是多少」与「当前生效的是哪一个」。
//
// 复用 configoverride.Resolve 而不是另写一套解析：只有一条解析路径才能保证
// 两个数字不会互相矛盾。
func envValueForSpec(spec configoverride.Spec) (any, bool) {
	if spec.Env == "" {
		return nil, false
	}
	raw, set := os.LookupEnv(spec.Env)
	if !set {
		return nil, false
	}
	var warns []string
	entry := configoverride.Resolve(spec, nil, raw, true, &warns)
	if entry.Source != configoverride.SourceEnv {
		// 环境变量已定义但取值不可用（空串或解析失败）：界面按「未设置」呈现，
		// 与 Resolve 的实际回落一致。
		return nil, false
	}
	return entry.Value, true
}

func secretValuePresent(value any) bool {
	if typed, ok := value.(string); ok {
		return strings.TrimSpace(typed) != ""
	}
	return value != nil
}

// RuntimeConfigOverrideWriteBody 是写覆盖的请求体。
//
// overrides 里的键只改提交中出现过的那些；clear 里的键恢复为「未覆盖」状态，
// 重新跟随环境变量。两者可以同时出现，clear 先应用。
type RuntimeConfigOverrideWriteBody struct {
	Overrides map[string]json.RawMessage `json:"overrides"`
	Clear     []string                   `json:"clear"`
}

// UpdateRuntimeConfigOverrides 写入或清除覆盖表条目，并触发配置重载。
//
// 对应 POST /api/v1/runtime-config/env-overrides。响应与 GET 同形状（写后回读）。
func UpdateRuntimeConfigOverrides(
	repo *repository.SystemSettingsRepo,
	db *gorm.DB,
	reload func() error,
) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var body RuntimeConfigOverrideWriteBody
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		if repo == nil {
			c.JSON(500, map[string]string{"error": "settings repository is unavailable"})
			return
		}
		raw := readRuntimeConfigOverridesRaw(repo)
		var warns []string
		overrides := configoverride.ParseStoredOverrides(raw, &warns)

		for _, key := range body.Clear {
			spec, ok := configoverride.Lookup(key)
			if !ok {
				c.JSON(400, map[string]any{"error": "unknown key", "key": key})
				return
			}
			if !spec.IsWritable() {
				c.JSON(400, map[string]any{"error": "key is not overridable", "key": key, "scope": string(spec.Scope)})
				return
			}
			delete(overrides, key)
		}

		written := make([]string, 0, len(body.Overrides))
		for key, value := range body.Overrides {
			spec, ok := configoverride.Lookup(key)
			if !ok {
				c.JSON(400, map[string]any{"error": "unknown key", "key": key})
				return
			}
			if !spec.IsWritable() {
				c.JSON(400, map[string]any{"error": "key is not overridable", "key": key, "scope": string(spec.Scope)})
				return
			}
			parsed, err := configoverride.ParseSubmitValue(spec, value)
			if err != nil {
				c.JSON(400, map[string]any{"error": err.Error(), "key": key})
				return
			}
			overrides[key] = parsed
			written = append(written, key)
		}
		sort.Strings(written)

		encoded, err := configoverride.EncodeStoredOverrides(overrides)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := repo.Set(store.SettingKeyRuntimeConfigOverrides, encoded); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if reload != nil {
			if err := reload(); err != nil {
				c.JSON(500, map[string]any{
					"error":  "config applied but reload failed: " + err.Error(),
					"stored": encoded,
				})
				return
			}
		}
		logger.New("config_override").Info("runtime config overrides updated",
			"written", strings.Join(written, ","),
			"cleared", strings.Join(body.Clear, ","),
		)
		response := buildRuntimeConfigOverridesResponse(repo, db)
		response.Warnings = append(warns, response.Warnings...)
		c.JSON(200, response)
	}
}
