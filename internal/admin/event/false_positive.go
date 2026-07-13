package event

import (
	"context"
	"strconv"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

/**
 * ListFalsePositives 分页列出误报反馈记录。
 * 支持按 status 过滤（pending/confirmed/rejected）。
 */
func ListFalsePositives(repo *repository.FalsePositiveRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(string(c.Query("page")))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(string(c.Query("page_size")))
		if pageSize < 1 || pageSize > 200 {
			pageSize = 20
		}
		status := string(c.Query("status"))
		items, total, err := repo.List((page-1)*pageSize, pageSize, status)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total, "page": page, "page_size": pageSize})
	}
}

/**
 * CreateFalsePositiveReq 提交误报反馈的请求体。
 */
type CreateFalsePositiveReq struct {
	SecurityEventID uint   `json:"security_event_id"`
	RequestID       string `json:"request_id"`
	RuleIDStr       string `json:"rule_id_str"`
	Category        string `json:"category"`
	ClientIP        string `json:"client_ip"`
	Host            string `json:"host"`
	Path            string `json:"path"`
	MatchDesc       string `json:"match_desc"`
	Note            string `json:"note"`
}

/**
 * CreateFalsePositive 提交一条误报反馈。
 * 提交者用户名从 auth_user context 读取；请求体只需事件上下文与备注。
 */
func CreateFalsePositive(repo *repository.FalsePositiveRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var body CreateFalsePositiveReq
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if body.SecurityEventID == 0 && body.RequestID == "" {
			c.JSON(400, map[string]string{"error": "security_event_id or request_id required"})
			return
		}
		submittedBy := ""
		if v, ok := c.Get("auth_user"); ok {
			if s, ok := v.(string); ok {
				submittedBy = s
			}
		}
		rec := &store.FalsePositiveReport{
			SecurityEventID: body.SecurityEventID,
			RequestID:       body.RequestID,
			RuleIDStr:       body.RuleIDStr,
			Category:        body.Category,
			ClientIP:        body.ClientIP,
			Host:            body.Host,
			Path:            body.Path,
			MatchDesc:       body.MatchDesc,
			SubmittedBy:     submittedBy,
			Note:            body.Note,
			Status:          "pending",
		}
		if err := repo.Create(rec); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(201, rec)
	}
}

/**
 * UpdateFalsePositiveStatusReq 更新审查状态的请求体。
 */
type UpdateFalsePositiveStatusReq struct {
	Status string `json:"status"`
}

/**
 * UpdateFalsePositiveStatus 更新一条反馈的审查状态。
 * 允许值：pending / confirmed / rejected。
 */
func UpdateFalsePositiveStatus(repo *repository.FalsePositiveRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		var body UpdateFalsePositiveStatusReq
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		switch body.Status {
		case "pending", "confirmed", "rejected":
		default:
			c.JSON(400, map[string]string{"error": "status must be pending/confirmed/rejected"})
			return
		}
		if err := repo.UpdateStatus(id, body.Status); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"id": id, "status": body.Status})
	}
}

/**
 * DeleteFalsePositive 删除一条反馈记录。
 */
func DeleteFalsePositive(repo *repository.FalsePositiveRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if err := repo.Delete(id); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(204, nil)
	}
}
