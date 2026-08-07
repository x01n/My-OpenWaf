package system

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

const jsMaxTimeoutMS = 1000

const jsRuntimeUnavailableMessage = "javascript runtime unavailable"

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

// ListJSPlugins returns all configured JavaScript edge scripts.
func ListJSPlugins(repo *repository.JSPluginRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		items, err := repo.List()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if items == nil {
			items = make([]store.JSPlugin, 0)
		}
		c.JSON(200, map[string]any{"items": items, "total": len(items)})
	}
}

// GetJSPlugin returns one configured JavaScript edge script.
func GetJSPlugin(repo *repository.JSPluginRepo) app.HandlerFunc {
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

// CreateJSPlugin creates an edge script and reloads the immutable configuration.
func CreateJSPlugin(repo *repository.JSPluginRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req jsPluginRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
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
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": item})
			return
		}
		c.JSON(201, item)
	}
}

// UpdateJSPlugin updates only fields present in the request body.
func UpdateJSPlugin(repo *repository.JSPluginRepo, reload func() error) app.HandlerFunc {
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
			c.JSON(400, map[string]string{"error": "invalid request body"})
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
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": item})
			return
		}
		c.JSON(200, item)
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
		c.JSON(503, map[string]any{"valid": false, "error": jsRuntimeUnavailableMessage})
	}
}

// DryRunJSPlugin reports that the JavaScript runtime is not installed yet.
func DryRunJSPlugin() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(503, map[string]string{"error": jsRuntimeUnavailableMessage})
	}
}

// GetJSPluginStats reports that the JavaScript runtime is not installed yet.
func GetJSPluginStats() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(503, map[string]any{"error": jsRuntimeUnavailableMessage, "items": []any{}, "total": 0})
	}
}

func applyJSPluginRequest(item *store.JSPlugin, req jsPluginRequest, creating bool) string {
	if name := strings.TrimSpace(req.Name); name != "" {
		item.Name = name
	} else if creating {
		return "name is required"
	}
	if req.Source != "" {
		item.Source = req.Source
	} else if creating {
		return "source is required"
	}
	if stage := strings.TrimSpace(req.Stage); stage != "" {
		if stage != store.JSStageRequest && stage != store.JSStageResponse {
			return "stage must be request or response"
		}
		item.Stage = stage
	} else if creating {
		return "stage is required (request or response)"
	}
	if req.FailureMode != "" {
		mode := strings.TrimSpace(req.FailureMode)
		if mode != store.JSFailureModeOpen && mode != store.JSFailureModeClosed {
			return "failure_mode must be fail_open or fail_closed"
		}
		item.FailureMode = mode
	} else if creating && item.FailureMode == "" {
		return "failure_mode is required (fail_open or fail_closed)"
	}
	if req.Enabled != nil {
		item.Enabled = *req.Enabled
	}
	if req.Priority != nil {
		item.Priority = *req.Priority
	}
	if req.TimeoutMS != nil {
		if *req.TimeoutMS < 0 || *req.TimeoutMS > jsMaxTimeoutMS {
			return "timeout_ms must be between 0 and 1000"
		}
		item.TimeoutMS = *req.TimeoutMS
	}
	if req.Description != nil {
		item.Description = *req.Description
	}
	if present, siteID, err := parseSiteScope(req.SiteID); err != nil {
		return err.Error()
	} else if present {
		item.SiteID = siteID
	}
	return ""
}
