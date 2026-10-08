package apikey

import (
	"context"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store/auth"
	"My-OpenWaf/internal/store/repository"
)

const maxAPIKeyNameBytes = 128

type createKeyBody struct {
	Name string `json:"name"`
}

/**
 * ListAPIKeys 列出令牌，并附带每个令牌所属账号的用户名。
 *
 * @param repo 令牌仓储。
 * @param accountRepo 账号仓储，用于把 user_id 解析成用户名。
 */
func ListAPIKeys(repo *repository.AdminAPIKeyRepo, accountRepo *repository.AdminAccountRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		items, err := repo.List()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": decorateKeysWithOwner(items, accountRepo)})
	}
}

/**
 * CreateAPIKey 为当前登录账号创建一枚令牌，明文只在本次响应中返回一次。
 *
 * 归属账号取自中间件写入的 auth_username —— 令牌必须挂在某个账号下，
 * 系统不存在无主令牌。
 *
 * @param repo 令牌仓储。
 * @param accountRepo 账号仓储，用于把当前用户名解析成 user_id。
 */
func CreateAPIKey(repo *repository.AdminAPIKeyRepo, accountRepo *repository.AdminAccountRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		username := currentUsername(c)
		if username == "" {
			c.JSON(401, map[string]string{"error": "unauthenticated"})
			return
		}
		account, err := accountRepo.GetByUsername(username)
		if err != nil || account.ID == 0 {
			c.JSON(403, map[string]string{"error": "current account not found"})
			return
		}

		var body createKeyBody
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		body.Name = strings.TrimSpace(body.Name)
		if body.Name == "" {
			body.Name = "unnamed"
		}
		if len([]byte(body.Name)) > maxAPIKeyNameBytes {
			c.JSON(400, map[string]string{"error": "name exceeds 128 bytes"})
			return
		}
		token, key, err := repo.Create(account.ID, body.Name)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(201, map[string]any{
			"token":    token,
			"id":       key.ID,
			"name":     key.Name,
			"user_id":  key.UserID,
			"username": account.Username,
		})
	}
}

/**
 * currentUsername 取出中间件写入的登录用户名。
 *
 * @param c Hertz 请求上下文。
 * @return 当前登录用户名；未认证时为空串。
 */
func currentUsername(c *app.RequestContext) string {
	if v, ok := c.Get("auth_username"); ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

/**
 * decorateKeysWithOwner 把令牌列表与账号名拼成管理端响应结构。
 *
 * @param items 令牌记录。
 * @param accountRepo 账号仓储。
 * @return 每项含 user_id 与 username 的切片。
 */
func decorateKeysWithOwner(items []auth.AdminAPIKey, accountRepo *repository.AdminAccountRepo) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	cache := make(map[uint]string)
	for _, k := range items {
		name, ok := cache[k.UserID]
		if !ok {
			if acct, err := accountRepo.GetByID(k.UserID); err == nil && acct.ID != 0 {
				name = acct.Username
			}
			cache[k.UserID] = name
		}
		out = append(out, map[string]any{
			"id":           k.ID,
			"created_at":   k.CreatedAt,
			"updated_at":   k.UpdatedAt,
			"name":         k.Name,
			"last_used_at": k.LastUsedAt,
			"user_id":      k.UserID,
			"username":     name,
		})
	}
	return out
}

func DeleteAPIKey(repo *repository.AdminAPIKeyRepo) app.HandlerFunc {
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
		c.JSON(204, nil)
	}
}
