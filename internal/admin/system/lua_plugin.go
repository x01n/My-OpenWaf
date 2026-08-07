package system

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/luaplugin"
)

// luaPluginRequest 是新建/更新脚本的请求体。
//
// Enabled 用 *bool 表达「未提供则保持原值」；SiteID 用 json.RawMessage 才能
// 区分「未提供」与「显式 null（改回全站）」——**uint 在 Go 里做不到这点，
// 因为 encoding/json 对 null 的语义是「不修改目标」。
type luaPluginRequest struct {
	Name        string          `json:"name"`
	Stage       string          `json:"stage"`
	Source      string          `json:"source"`
	Enabled     *bool           `json:"enabled"`
	Priority    *int            `json:"priority"`
	TimeoutMS   *int            `json:"timeout_ms"`
	Description *string         `json:"description"`
	SiteID      json.RawMessage `json:"site_id"`
}

// luaMaxTimeoutMS 限制单脚本超时上限。
//
// 脚本在数据面同步执行，允许过长会让单个慢脚本拖垮 P99 延迟。
const luaMaxTimeoutMS = 1200

// ListLuaPlugins 返回全部自定义 Lua 策略脚本。
func ListLuaPlugins(repo *repository.LuaPluginRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		items, err := repo.List()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": len(items)})
	}
}

// GetLuaPlugin 返回单个脚本。
func GetLuaPlugin(repo *repository.LuaPluginRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		item, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}
		c.JSON(200, item)
	}
}

// luaPluginStatsItem 是单个脚本的运行统计响应项。
//
// 在 admin 层单独定义而非给 luaplugin.Stats 加 json tag：后者的 Go 字段名
// （Runs/Failures/Timeouts/AvgTime）已被文档直接引用，加 tag 只会让两处命名分叉。
type luaPluginStatsItem struct {
	ID    uint   `json:"id"`
	Name  string `json:"name"`
	Stage string `json:"stage"`
	Runs  int64  `json:"runs"`
	// Failures 与 Timeouts 互斥：超时分支直接返回、不累加 Failures，
	// 故成功次数是 Runs-Failures-Timeouts。
	Failures int64 `json:"failures"`
	Timeouts int64 `json:"timeouts"`
	// AvgMS 是平均耗时（毫秒），与 dry-run 的 elapsed_ms 同单位。
	AvgMS float64 `json:"avg_ms"`
}

/**
 * GetLuaPluginStats 返回各脚本的累计运行统计。
 *
 * 脚本失败或超时时只写一条 warn 日志就静默跳过，请求判定不受影响；没有这个
 * 端点，运维无法察觉某条策略已长期失效。看 Timeouts 时应看它与 Runs 的占比，
 * 默认 50ms 超时下偶发一两次是运行时抖动而非脚本问题。
 *
 * @param engine 插件引擎，可为 nil（未装配时返回空列表而非报错）。
 * @return Hertz handler。
 */
func GetLuaPluginStats(engine *luaplugin.Engine) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		// Engine.Stats() 对 nil 接收者返回 nil，故无需额外判空。
		stats := engine.Stats()
		items := make([]luaPluginStatsItem, 0, len(stats))
		for _, s := range stats {
			items = append(items, luaPluginStatsItem{
				ID:       s.ID,
				Name:     s.Name,
				Stage:    s.Stage,
				Runs:     s.Runs,
				Failures: s.Failures,
				Timeouts: s.Timeouts,
				AvgMS:    float64(s.AvgTime.Nanoseconds()) / 1e6,
			})
		}
		c.JSON(200, map[string]any{"items": items, "total": len(items)})
	}
}

// CreateLuaPlugin 新建脚本。
//
// 编译校验在保存前完成：语法错误应在此暴露，而不是等到 reload 时才发现。
func CreateLuaPlugin(repo *repository.LuaPluginRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req luaPluginRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		item := store.LuaPlugin{Enabled: true, Priority: 100}
		if errMsg := applyLuaPluginRequest(&item, req, true); errMsg != "" {
			c.JSON(400, map[string]string{"error": errMsg})
			return
		}

		if err := repo.Create(&item); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": item})
			return
		}
		c.JSON(201, item)
	}
}

// UpdateLuaPlugin 更新脚本，仅覆盖请求中提供的字段。
func UpdateLuaPlugin(repo *repository.LuaPluginRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		existing, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}

		var req luaPluginRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		if errMsg := applyLuaPluginRequest(existing, req, false); errMsg != "" {
			c.JSON(400, map[string]string{"error": errMsg})
			return
		}

		if err := repo.Update(existing); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": existing})
			return
		}
		c.JSON(200, existing)
	}
}

// DeleteLuaPlugin 删除脚本。
func DeleteLuaPlugin(repo *repository.LuaPluginRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if _, err := repo.Get(id); err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}
		if err := repo.Delete(id); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(204, nil)
	}
}

// ToggleLuaPlugin 切换脚本启用状态。
func ToggleLuaPlugin(repo *repository.LuaPluginRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		existing, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}

		var body struct {
			Enabled *bool `json:"enabled"`
		}
		if len(c.Request.Body()) > 0 {
			if err := c.BindJSON(&body); err != nil {
				c.JSON(400, map[string]string{"error": err.Error()})
				return
			}
		}
		enabled := !existing.Enabled
		if body.Enabled != nil {
			enabled = *body.Enabled
		}

		if err := repo.Toggle(id, enabled); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{"id": id, "enabled": enabled})
	}
}

// ValidateLuaPlugin 只做编译校验，不保存也不执行。
func ValidateLuaPlugin() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			Stage  string `json:"stage"`
			Source string `json:"source"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		stage := luaplugin.Stage(strings.TrimSpace(req.Stage))
		if !stage.Valid() {
			c.JSON(400, map[string]string{"error": "stage must be pre or post"})
			return
		}
		if err := luaplugin.Validate(stage, req.Source); err != nil {
			c.JSON(200, map[string]any{"valid": false, "error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"valid": true})
	}
}

// luaDryRunRequest 是试运行的请求体。
type luaDryRunRequest struct {
	Stage      string `json:"stage"`
	Source     string `json:"source"`
	TimeoutMS  int    `json:"timeout_ms"`
	Iterations int    `json:"iterations"`
	// Request 是样例请求，字段与脚本可见的 ctx 对应。
	Request struct {
		ClientIP    string            `json:"client_ip"`
		Method      string            `json:"method"`
		Path        string            `json:"path"`
		Query       string            `json:"query"`
		Host        string            `json:"host"`
		UserAgent   string            `json:"user_agent"`
		SiteID      uint              `json:"site_id"`
		ContentType string            `json:"content_type"`
		Body        string            `json:"body"`
		Headers     map[string]string `json:"headers"`
		TLSVersion  string            `json:"tls_version"`
		TLSJA3      string            `json:"tls_ja3"`
		TLSJA4      string            `json:"tls_ja4"`
		TLSSNI      string            `json:"tls_sni"`
		// Phase/Action 模拟内置引擎的判定，用于验证 post 脚本的分支。
		Phase  string `json:"phase"`
		Action string `json:"action"`
	} `json:"request"`
}

// queryParams 将试运行原始查询串转换为与数据面一致的 Lua 查询参数视图。
// 重复键保留第一个值；非法编码作为空参数处理。
// DryRunLuaPlugin 用样例请求试运行脚本，不影响线上配置。
//
// 策略脚本的错误往往只在真实请求形态下暴露，光有语法校验不够；
// 试运行让用户在保存前看到判定与耗时。
func DryRunLuaPlugin() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req luaDryRunRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		stage := luaplugin.Stage(strings.TrimSpace(req.Stage))
		if !stage.Valid() {
			c.JSON(400, map[string]string{"error": "stage must be pre or post"})
			return
		}

		if req.TimeoutMS < 0 || req.TimeoutMS > luaMaxTimeoutMS {
			c.JSON(400, map[string]string{"error": "timeout_ms must be between 0 and 1200"})
			return
		}
		timeout := time.Duration(req.TimeoutMS) * time.Millisecond

		view := luaplugin.RequestView{
			RequestID:   "dry-run",
			ClientIP:    req.Request.ClientIP,
			Method:      req.Request.Method,
			Path:        req.Request.Path,
			RawQuery:    req.Request.Query,
			Host:        req.Request.Host,
			UserAgent:   req.Request.UserAgent,
			SiteID:      req.Request.SiteID,
			ContentType: req.Request.ContentType,
			Body:        req.Request.Body,
			Headers:     req.Request.Headers,
			TLSVersion:  req.Request.TLSVersion,
			TLSJA3:      req.Request.TLSJA3,
			TLSJA4:      req.Request.TLSJA4,
			TLSSNI:      req.Request.TLSSNI,
			Phase:       req.Request.Phase,
			Action:      req.Request.Action,
		}
		populateDryRunQuery(&req, &view)
		if stage == luaplugin.StagePre {
			view.Phase = ""
			view.Action = ""
		}

		// dry-run 必须与线上 Redis/KV 完全隔离。nil 后端会让 ctx.kv.available()
		// 固定为 false，避免试运行修改生产计数、影响限速或污染跨请求状态。
		c.JSON(200, luaplugin.DryRunNContext(ctx, stage, req.Source, view, nil, timeout, req.Iterations))
	}
}

func populateDryRunQuery(req *luaDryRunRequest, view *luaplugin.RequestView) {
	if view == nil {
		return
	}
	view.QueryParams = nil
	view.QueryValues = nil
	if req == nil || req.Request.Query == "" {
		return
	}
	values, err := url.ParseQuery(req.Request.Query)
	if err != nil {
		return
	}
	view.QueryParams = make(map[string]string, len(values))
	view.QueryValues = make(map[string][]string, len(values))
	for key, items := range values {
		if len(items) == 0 {
			continue
		}
		view.QueryParams[key] = items[0]
		view.QueryValues[key] = append([]string(nil), items...)
	}
}

/**
 * applyLuaPluginRequest 把请求字段应用到模型并校验。
 *
 * @param item     目标模型。
 * @param req      请求体。
 * @param creating 新建时 name/stage/source 为必填。
 * @return 校验错误信息，空字符串表示通过。
 */
func applyLuaPluginRequest(item *store.LuaPlugin, req luaPluginRequest, creating bool) string {
	if name := strings.TrimSpace(req.Name); name != "" {
		if !utf8.ValidString(name) {
			return "name must be valid UTF-8"
		}
		if utf8.RuneCountInString(name) > 128 {
			return "name must be at most 128 characters"
		}
		item.Name = name
	} else if creating {
		return "name is required"
	}

	if stage := strings.TrimSpace(req.Stage); stage != "" {
		if !store.ValidLuaStage(stage) {
			return "stage must be pre or post"
		}
		item.Stage = stage
	} else if creating {
		return "stage is required (pre or post)"
	}

	if req.Source != "" {
		item.Source = req.Source
	} else if creating {
		return "source is required"
	}

	// 保存前编译校验：语法错误应在此暴露，而非等到 reload 才发现。
	// 用最终生效的 stage 校验，因为 stage 影响不了编译但需保证取值合法。
	if err := luaplugin.Validate(luaplugin.Stage(item.Stage), item.Source); err != nil {
		return err.Error()
	}

	if req.Enabled != nil {
		item.Enabled = *req.Enabled
	}
	if req.Priority != nil {
		item.Priority = *req.Priority
	}
	if req.TimeoutMS != nil {
		if *req.TimeoutMS < 0 || *req.TimeoutMS > luaMaxTimeoutMS {
			return "timeout_ms must be between 0 and 1200"
		}
		item.TimeoutMS = *req.TimeoutMS
	}
	if req.Description != nil {
		if !utf8.ValidString(*req.Description) {
			return "description must be valid UTF-8"
		}
		if utf8.RuneCountInString(*req.Description) > 512 {
			return "description must be at most 512 characters"
		}
		item.Description = *req.Description
	}

	// site_id 三态：未提供保持原值，显式 null 改为全站，具体值绑定站点。
	if present, siteID, err := parseSiteScope(req.SiteID); err != nil {
		return err.Error()
	} else if present {
		item.SiteID = siteID
	}

	return ""
}
