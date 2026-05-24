package event

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store/repository"
)

// GetRequestTrace returns all access logs and security events for a given request_id.
func GetRequestTrace(accessLogRepo *repository.AccessLogRepo, secEventRepo *repository.SecurityEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		requestID := c.Param("request_id")
		if requestID == "" {
			c.JSON(400, map[string]string{"error": "request_id is required"})
			return
		}

		accessLogs, err := accessLogRepo.FindByRequestID(requestID)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}

		secEvents, err := secEventRepo.FindByRequestID(requestID)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}

		c.JSON(200, map[string]any{
			"request_id":      requestID,
			"access_logs":     accessLogs,
			"security_events": secEvents,
		})
	}
}
