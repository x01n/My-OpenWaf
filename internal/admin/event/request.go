package event

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// requestTraceBotScoreLimit 限制单个 request_id 返回的 Bot 评分记录数。
//
// 同一请求正常只会产生一条 BotScoreLog（`internal/dataplane/handler.go` 中的
// RecordBotScore 每请求最多调用一次），取上限只是防御异常重复写入把响应撑大。
const requestTraceBotScoreLimit = 20

/**
 * GetRequestTrace 返回同一 request_id 的访问日志、安全事件与 Bot 评分记录。
 *
 * Bot 评分用于在请求追踪页展示「人机访问」判定依据：BotScoreLog 已含 total_score
 * 与 geoip/fingerprint/behavior/ip_rep 四个分项及 is_high_risk，通过 request_id
 * 与访问日志一一对应，无需新增数据库字段。
 *
 * botScoreRepo 允许为 nil：日志库未启用 Bot 评分表时该字段返回空数组，不影响
 * 既有的 access_logs / security_events 两块数据。
 *
 * @param accessLogRepo 访问日志仓储。
 * @param secEventRepo  安全事件仓储。
 * @param botScoreRepo  Bot 评分仓储，可为 nil。
 * @return Hertz 处理函数。
 */
func GetRequestTrace(accessLogRepo *repository.AccessLogRepo, secEventRepo *repository.SecurityEventRepo, botScoreRepo *repository.BotScoreRepo) app.HandlerFunc {
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

		botScores := []store.BotScoreLog{}
		if botScoreRepo != nil {
			items, _, listErr := botScoreRepo.List(0, requestTraceBotScoreLimit, repository.BotScoreFilter{RequestID: requestID})
			if listErr != nil {
				c.JSON(500, map[string]string{"error": listErr.Error()})
				return
			}
			if items != nil {
				botScores = items
			}
		}

		c.JSON(200, map[string]any{
			"request_id":      requestID,
			"access_logs":     accessLogs,
			"security_events": secEvents,
			"bot_scores":      botScores,
		})
	}
}
