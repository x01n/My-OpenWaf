package event

import (
	"context"
	"errors"
	"strconv"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/gorm"

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
	Note            string `json:"note"`
}

/**
 * CreateFalsePositive 提交一条误报反馈。
 * 源事件快照由后端从日志库读取，客户端仅能提交事件 ID 和备注。
 */
func CreateFalsePositive(repo *repository.FalsePositiveRepo, securityEvents *repository.SecurityEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var body CreateFalsePositiveReq
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if body.SecurityEventID == 0 {
			c.JSON(400, map[string]string{"error": "security_event_id required"})
			return
		}

		event, err := securityEvents.Get(body.SecurityEventID)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(404, map[string]string{"error": "security event not found"})
			return
		}
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}

		submittedBy := ""
		if v, ok := c.Get("auth_user"); ok {
			if s, ok := v.(string); ok {
				submittedBy = s
			}
		}
		sourceEventKey := "security-event:" + strconv.FormatUint(uint64(event.ID), 10)
		rec := &store.FalsePositiveReport{
			SecurityEventID: event.ID,
			RequestID:       event.RequestID,
			SourceEventKey:  &sourceEventKey,
			RuleIDStr:       event.RuleIDStr,
			Category:        event.Category,
			ClientIP:        event.ClientIP,
			Host:            event.Host,
			Path:            event.Path,
			MatchDesc:       event.MatchDesc,
			SubmittedBy:     submittedBy,
			Note:            body.Note,
			Status:          "pending",
		}
		saved, created, err := repo.CreateOrGetBySourceEvent(rec)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if !created {
			c.JSON(200, saved)
			return
		}
		c.JSON(201, saved)
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
		err = repo.UpdateStatus(id, body.Status)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(404, map[string]string{"error": "false positive not found"})
			return
		}
		if err != nil {
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
		err = repo.Delete(id)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(404, map[string]string{"error": "false positive not found"})
			return
		}
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(204, nil)
	}
}
