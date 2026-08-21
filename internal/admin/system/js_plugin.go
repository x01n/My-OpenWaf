package system

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/jsplugin"
)

const jsMaxTimeoutMS = 1000

const (
	jsRuntimeUnavailableMessage       = "javascript runtime unavailable"
	jsResponseStageUnavailableMessage = "response stage is unavailable because response execution is not implemented"
)

// jsQuickJSDisabledMessage 说明当前二进制没有编入 QuickJS 后端。
//
// 构建条件逐字来自 internal/waf/jsplugin/quickjs_cgo.go 的 //go:build 约束，
// 该分支不满足时 Compile/Evaluate 一律返回 jsplugin.ErrCGODisabled。
const jsQuickJSDisabledMessage = "javascript runtime is not enabled in this build (requires build tag quickjs with cgo)"

// jsPluginRequest describes create and partial-update fields for an edge script.
type jsPluginRequest struct {
	Name        string          `json:"name"`
	Source      string          `json:"source"`
	Stage       string          `json:"stage"`
	Enabled     *bool           `json:"enabled"`
	Priority    *int            `json:"priority"`
	SiteID      json.RawMessage `json:"site_id"`
	TimeoutMS   *int            `json:"timeout_ms"`
	Description *string         `json:"description"`
	FailureMode string          `json:"failure_mode"`
}

// jsPluginStatsItem 是管理端 JS 运行时统计的稳定响应结构。
type jsPluginStatsItem struct {
	ID       uint    `json:"id"`
	Name     string  `json:"name"`
	Stage    string  `json:"stage"`
	Runs     int64   `json:"runs"`
	Failures int64   `json:"failures"`
	Timeouts int64   `json:"timeouts"`
	AvgMS    float64 `json:"avg_ms"`
}

// ListJSPlugins returns all configured JavaScript edge scripts.
// jsPluginItemResponse 是管理端 JS 插件的最终响应结构，附带当前 snapshot 的构建诊断。
type jsPluginItemResponse struct {
	ID           uint      `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Name         string    `json:"name"`
	Source       string    `json:"source"`
	Enabled      bool      `json:"enabled"`
	Priority     int       `json:"priority"`
	SiteID       *uint     `json:"site_id"`
	Stage        string    `json:"stage"`
	FailureMode  string    `json:"failure_mode"`
	TimeoutMS    int       `json:"timeout_ms"`
	Description  string    `json:"description"`
	CompileError string    `json:"compile_error,omitempty"`
}

func newJSPluginItemResponse(item store.JSPlugin, sn *snapshotpkg.Snapshot) jsPluginItemResponse {
	response := jsPluginItemResponse{
		ID:          item.ID,
		CreatedAt:   item.CreatedAt,
		UpdatedAt:   item.UpdatedAt,
		Name:        item.Name,
		Source:      item.Source,
		Enabled:     item.Enabled,
		Priority:    item.Priority,
		SiteID:      item.SiteID,
		Stage:       item.Stage,
		FailureMode: item.FailureMode,
		TimeoutMS:   item.TimeoutMS,
		Description: item.Description,
	}
	if sn != nil && sn.JSPluginErrors != nil {
		response.CompileError = sn.JSPluginErrors[snapshotpkg.JSPluginErrorKey(item.ID)]
	}
	return response
}

func currentJSPluginSnapshot(holder *snapshotpkg.Holder) *snapshotpkg.Snapshot {
	if holder == nil {
		return nil
	}
	return holder.Load()
}

func ListJSPlugins(repo *repository.JSPluginRepo, holder *snapshotpkg.Holder) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		items, err := repo.List()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		responseItems := make([]jsPluginItemResponse, 0, len(items))
		var sn *snapshotpkg.Snapshot
		if holder != nil {
			sn = holder.Load()
		}
		for _, item := range items {
			responseItems = append(responseItems, newJSPluginItemResponse(item, sn))
		}
		c.JSON(200, map[string]any{"items": responseItems, "total": len(responseItems)})
	}
}

// GetJSPlugin returns one configured JavaScript edge script.
func GetJSPlugin(repo *repository.JSPluginRepo, holder *snapshotpkg.Holder) app.HandlerFunc {
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
		var sn *snapshotpkg.Snapshot
		if holder != nil {
			sn = holder.Load()
		}
		c.JSON(200, newJSPluginItemResponse(*item, sn))
	}
}

// CreateJSPlugin creates an edge script and reloads the immutable configuration.
func CreateJSPlugin(repo *repository.JSPluginRepo, holder *snapshotpkg.Holder, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req jsPluginRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}

		item := store.JSPlugin{Enabled: true, Priority: 100, FailureMode: store.JSFailureModeOpen}
		if errMsg := applyJSPluginRequest(&item, req, true); errMsg != "" {
			c.JSON(400, map[string]string{"error": errMsg})
			return
		}
		if err := repo.Create(&item); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{
				"error":        "config applied but reload failed: " + err.Error(),
				"reload_error": err.Error(),
				"item":         newJSPluginItemResponse(item, currentJSPluginSnapshot(holder)),
			})
			return
		}
		c.JSON(201, newJSPluginItemResponse(item, currentJSPluginSnapshot(holder)))
	}
}

// UpdateJSPlugin updates only fields present in the request body.
func UpdateJSPlugin(repo *repository.JSPluginRepo, holder *snapshotpkg.Holder, reload func() error) app.HandlerFunc {
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
		var req jsPluginRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}
		if errMsg := applyJSPluginRequest(item, req, false); errMsg != "" {
			c.JSON(400, map[string]string{"error": errMsg})
			return
		}
		if err := repo.Update(item); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{
				"error":        "config applied but reload failed: " + err.Error(),
				"reload_error": err.Error(),
				"item":         newJSPluginItemResponse(*item, currentJSPluginSnapshot(holder)),
			})
			return
		}
		c.JSON(200, newJSPluginItemResponse(*item, currentJSPluginSnapshot(holder)))
	}
}

// DeleteJSPlugin deletes an edge script and reloads the configuration.
func DeleteJSPlugin(repo *repository.JSPluginRepo, reload func() error) app.HandlerFunc {
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

// ToggleJSPlugin explicitly sets enabled or flips the current state.
func ToggleJSPlugin(repo *repository.JSPluginRepo, reload func() error) app.HandlerFunc {
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
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		if len(c.Request.Body()) > 0 {
			if err := c.BindJSON(&body); err != nil {
				c.JSON(400, map[string]string{"error": err.Error()})
				return
			}
		}
		enabled := !item.Enabled
		if body.Enabled != nil {
			enabled = *body.Enabled
		}
		if enabled && item.Stage == store.JSStageResponse {
			c.JSON(400, map[string]string{"error": jsResponseStageUnavailableMessage})
			return
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

// ValidateJSPlugin reports that the JavaScript runtime is not installed yet.
func ValidateJSPlugin() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			Stage     string `json:"stage"`
			Source    string `json:"source"`
			TimeoutMS *int   `json:"timeout_ms"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}
		if req.Stage == store.JSStageResponse {
			c.JSON(400, map[string]string{"error": jsResponseStageUnavailableMessage})
			return
		}
		if req.Stage != store.JSStageRequest {
			c.JSON(400, map[string]string{"error": "stage must be request"})
			return
		}
		if req.TimeoutMS != nil && (*req.TimeoutMS < 0 || *req.TimeoutMS > jsMaxTimeoutMS) {
			c.JSON(400, map[string]string{"error": "timeout_ms must be between 0 and 1000"})
			return
		}
		opts := jsplugin.ScriptOptions{Name: "<js-plugin-validate>"}
		if req.TimeoutMS != nil && *req.TimeoutMS > 0 {
			opts.Timeout = time.Duration(*req.TimeoutMS) * time.Millisecond
		}
		if err := jsplugin.ValidateWithOptions(req.Stage, req.Source, opts); err != nil {
			if errors.Is(err, jsplugin.ErrCGODisabled) {
				c.JSON(503, map[string]any{"valid": false, "error": jsQuickJSDisabledMessage})
				return
			}
			c.JSON(200, map[string]any{"valid": false, "error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"valid": true})
	}
}

/**
 * DryRunJSPlugin 用样例请求真实执行一次脚本并返回请求变更计划。
 *
 * 只覆盖 request 阶段的执行闭环：response 阶段的宿主对象尚未接入，故 stage 仅
 * 参与入参校验，不改变执行路径。dry-run 与生产状态天然隔离——jsplugin 包不持
 * 有 RedisKV 或任何共享计数器，脚本除了返回 MutationPlan 无法产生副作用；此处
 * 另外用独立编译出的 *jsplugin.Script 执行，因此不会污染 snapshot 已编译脚本
 * 的 runs/failures/timeouts 计数。
 *
 * @param engine QuickJS 执行引擎，可为 nil（未装配时返回明确错误而非 panic）。
 * @return Hertz handler。
 */
func DryRunJSPlugin(loadEngine func() *jsplugin.Engine) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			Stage         string         `json:"stage"`
			Source        string         `json:"source"`
			TimeoutMS     int            `json:"timeout_ms"`
			SampleRequest map[string]any `json:"sample_request"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}
		if req.Stage != store.JSStageRequest && req.Stage != store.JSStageResponse {
			c.JSON(400, map[string]string{"error": "stage must be request or response"})
			return
		}
		if req.Stage == store.JSStageResponse {
			c.JSON(400, map[string]string{"error": jsResponseStageUnavailableMessage})
			return
		}
		if req.TimeoutMS < 0 || req.TimeoutMS > jsMaxTimeoutMS {
			c.JSON(400, map[string]string{"error": "timeout_ms must be between 0 and 1000"})
			return
		}
		var engine *jsplugin.Engine
		if loadEngine != nil {
			engine = loadEngine()
		}
		if engine == nil {
			c.JSON(503, map[string]any{"error": jsRuntimeUnavailableMessage, "result": nil})
			return
		}

		opts := jsplugin.ScriptOptions{Name: "<js-plugin-dry-run>"}
		if req.TimeoutMS > 0 {
			opts.Timeout = time.Duration(req.TimeoutMS) * time.Millisecond
		}
		script, err := jsplugin.Compile("<dry-run>", req.Source, opts)
		if err != nil {
			if errors.Is(err, jsplugin.ErrCGODisabled) {
				c.JSON(503, map[string]any{"error": jsQuickJSDisabledMessage, "result": nil})
				return
			}
			c.JSON(200, map[string]any{"error": err.Error(), "result": nil})
			return
		}

		requestSnapshot := buildJSDryRunSnapshot(req.SampleRequest)
		started := time.Now()
		plan, err := engine.Execute(ctx, script, requestSnapshot)
		elapsed := time.Since(started)
		if err != nil {
			if errors.Is(err, jsplugin.ErrCGODisabled) {
				c.JSON(503, map[string]any{"error": jsQuickJSDisabledMessage, "result": nil})
				return
			}
			c.JSON(200, map[string]any{
				"error":             err.Error(),
				"result":            nil,
				"execution_time_ms": float64(elapsed.Nanoseconds()) / 1e6,
			})
			return
		}
		if err := jsplugin.ValidateMutationPlan(plan); err != nil {
			c.JSON(200, map[string]any{
				"error":             err.Error(),
				"result":            nil,
				"execution_time_ms": float64(elapsed.Nanoseconds()) / 1e6,
			})
			return
		}
		c.JSON(200, map[string]any{
			"result":            plan,
			"execution_time_ms": float64(elapsed.Nanoseconds()) / 1e6,
		})
	}
}

/**
 * buildJSDryRunSnapshot 把样例请求映射为 jsplugin.RequestSnapshot。
 *
 * 键名逐字取自 jsplugin.RequestSnapshot 的 json tag。取不到目标类型的字段一律
 * 跳过而不做类型强转，避免把用户笔误静默变成一个看似成功的执行结果。SiteID 不
 * 从样例请求读取：dry-run 未绑定站点，留零值可让 Script.AppliesTo 对全局脚本
 * 放行。
 *
 * @param sample dry-run 请求里的 sample_request 对象，可为 nil。
 * @return 已填充的只读请求快照。
 */
func buildJSDryRunSnapshot(sample map[string]any) jsplugin.RequestSnapshot {
	snapshot := jsplugin.RequestSnapshot{RequestID: "dry-run"}
	if len(sample) == 0 {
		return snapshot
	}
	for key, target := range map[string]*string{
		"method":       &snapshot.Method,
		"path":         &snapshot.Path,
		"raw_query":    &snapshot.RawQuery,
		"host":         &snapshot.Host,
		"client_ip":    &snapshot.ClientIP,
		"user_agent":   &snapshot.UserAgent,
		"content_type": &snapshot.ContentType,
		"body":         &snapshot.Body,
	} {
		if value, ok := sample[key].(string); ok {
			*target = value
		}
	}
	snapshot.Headers = jsStringMapFromSample(sample["headers"])
	snapshot.QueryParams = jsStringMapFromSample(sample["query_params"])
	return snapshot
}

// jsStringMapFromSample 抽取 map[string]string 视图，非字符串值直接跳过。
func jsStringMapFromSample(raw any) map[string]string {
	entries, ok := raw.(map[string]any)
	if !ok || len(entries) == 0 {
		return nil
	}
	result := make(map[string]string, len(entries))
	for key, value := range entries {
		if text, ok := value.(string); ok {
			result[key] = text
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

/**
 * GetJSPluginStats 返回 JS 脚本的运行时统计。
 *
 * 当前返回空列表：单脚本计数器只存在于 *jsplugin.Script（script.go:120 的
 * Stats）上，而 jsplugin.Engine 是纯执行器，两个构建分支都只有 Execute/
 * Evaluate/Close，不持有脚本集合；已编译脚本集合只存在于
 * snapshot.Snapshot.JSPlugins，尚未接入本端点。端点保持 200 而非 503，因为
 * router 已把它注册为常规读端点，空集合不等于运行时故障。
 *
 * @param engine QuickJS 执行引擎，可为 nil；当前实现不读取它。
 * @return Hertz handler。
 */
func GetJSPluginStats(holder *snapshotpkg.Holder) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var scripts []*jsplugin.Script
		if holder != nil {
			if sn := holder.Load(); sn != nil {
				scripts = sn.JSPlugins
			}
		}
		items := make([]jsPluginStatsItem, 0, len(scripts))
		for _, script := range scripts {
			if script == nil {
				continue
			}
			runs, failures, timeouts, average := script.Stats()
			items = append(items, jsPluginStatsItem{
				ID:       script.ID(),
				Name:     script.Name(),
				Stage:    script.Stage(),
				Runs:     runs,
				Failures: failures,
				Timeouts: timeouts,
				AvgMS:    float64(average.Nanoseconds()) / 1e6,
			})
		}
		c.JSON(200, map[string]any{"items": items, "total": len(items)})
	}
}

func applyJSPluginRequest(item *store.JSPlugin, req jsPluginRequest, creating bool) string {
	updated := *item

	if name := strings.TrimSpace(req.Name); name != "" {
		if !utf8.ValidString(name) {
			return "name must be valid UTF-8"
		}
		if utf8.RuneCountInString(name) > 128 {
			return "name must be at most 128 characters"
		}
		updated.Name = name
	} else if creating {
		return "name is required"
	}
	if req.Source != "" {
		if len(req.Source) > jsplugin.MaxScriptBytes {
			return fmt.Sprintf("source must be at most %d bytes", jsplugin.MaxScriptBytes)
		}
		updated.Source = req.Source
	} else if creating {
		return "source is required"
	}
	if stage := strings.TrimSpace(req.Stage); stage != "" {
		if stage == store.JSStageResponse {
			return jsResponseStageUnavailableMessage
		}
		if stage != store.JSStageRequest {
			return "stage must be request"
		}
		updated.Stage = stage
	} else if creating {
		return "stage is required (request)"
	}
	if req.FailureMode != "" {
		mode := strings.TrimSpace(req.FailureMode)
		if mode != store.JSFailureModeOpen && mode != store.JSFailureModeClosed {
			return "failure_mode must be fail_open or fail_closed"
		}
		updated.FailureMode = mode
	} else if creating && updated.FailureMode == "" {
		return "failure_mode is required (fail_open or fail_closed)"
	}
	if req.Enabled != nil {
		updated.Enabled = *req.Enabled
	}
	if req.Priority != nil {
		updated.Priority = *req.Priority
	}
	if req.TimeoutMS != nil {
		if *req.TimeoutMS < 0 || *req.TimeoutMS > jsMaxTimeoutMS {
			return "timeout_ms must be between 0 and 1000"
		}
		updated.TimeoutMS = *req.TimeoutMS
	}
	if req.Description != nil {
		if !utf8.ValidString(*req.Description) {
			return "description must be valid UTF-8"
		}
		if utf8.RuneCountInString(*req.Description) > 512 {
			return "description must be at most 512 characters"
		}
		updated.Description = *req.Description
	}
	if present, siteID, err := parseSiteScope(req.SiteID); err != nil {
		return err.Error()
	} else if present {
		updated.SiteID = siteID
	}
	if updated.Stage == store.JSStageResponse {
		return jsResponseStageUnavailableMessage
	}

	*item = updated
	return ""
}
