package access

import (
	"context"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

// CreateUserReq 创建本地用户的请求体。
type CreateUserReq struct {
	Username string `json:"username"`
	// Password 用户密码明文，保存时以 bcrypt 哈希。
	Password string `json:"password"`
	Enabled  *bool  `json:"enabled,omitempty"`
}

// UpdateUserReq 更新本地用户的请求体。
type UpdateUserReq struct {
	// Password 非空时以 bcrypt 哈希后覆盖，空字符串表示保持原密码不变。
	Password string `json:"password,omitempty"`
	Enabled  *bool  `json:"enabled,omitempty"`
}

/**
 * ListUsers 返回站点的所有本地用户，密码哈希已由模型的 json:"-" 标签屏蔽。
 *
 * @param repo 访问控制仓库。
 * @return Hertz 处理器。
 */
func ListUsers(repo *repository.AccessControlRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		users, err := repo.ListAccessUsers(siteID)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"site_id": siteID, "users": users})
	}
}

/**
 * CreateUser 为站点创建本地用户，密码以 bcrypt（cost 10）哈希后存储。
 *
 * @param repo   访问控制仓库。
 * @param reload snapshot 重建回调。
 * @return Hertz 处理器。
 */
func CreateUser(repo *repository.AccessControlRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		var req CreateUserReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		req.Username = strings.TrimSpace(req.Username)
		if req.Username == "" {
			c.JSON(400, map[string]string{"error": "username is required"})
			return
		}
		if req.Password == "" {
			c.JSON(400, map[string]string{"error": "password is required"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
		if err != nil {
			c.JSON(500, map[string]string{"error": "failed to hash password"})
			return
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		user := &store.AccessUser{
			SiteID:       siteID,
			Username:     req.Username,
			PasswordHash: string(hash),
			Enabled:      enabled,
		}
		if err := repo.CreateAccessUser(user); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "user created but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, user)
	}
}

/**
 * UpdateUser 更新站点本地用户，可选修改密码与启用状态。
 *
 * @param repo   访问控制仓库。
 * @param reload snapshot 重建回调。
 * @return Hertz 处理器。
 */
func UpdateUser(repo *repository.AccessControlRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		userID, err := utils.ParseUint(c.Param("uid"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid user id"})
			return
		}
		var req UpdateUserReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		user, err := findSiteUser(repo, siteID, userID)
		if err != nil {
			c.JSON(404, map[string]string{"error": "user not found"})
			return
		}
		if req.Password != "" {
			hash, herr := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
			if herr != nil {
				c.JSON(500, map[string]string{"error": "failed to hash password"})
				return
			}
			user.PasswordHash = string(hash)
		}
		if req.Enabled != nil {
			user.Enabled = *req.Enabled
		}
		if err := repo.UpdateAccessUser(user); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "user updated but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, user)
	}
}

/**
 * DeleteUser 删除站点本地用户。
 *
 * @param repo   访问控制仓库。
 * @param reload snapshot 重建回调。
 * @return Hertz 处理器。
 */
func DeleteUser(repo *repository.AccessControlRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		userID, err := utils.ParseUint(c.Param("uid"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid user id"})
			return
		}
		if _, err := findSiteUser(repo, siteID, userID); err != nil {
			c.JSON(404, map[string]string{"error": "user not found"})
			return
		}
		if err := repo.DeleteAccessUser(userID); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "user deleted but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{"site_id": siteID, "id": userID, "deleted": true})
	}
}

/**
 * findSiteUser 在指定站点范围内按 ID 查找本地用户，防止跨站点越权访问。
 *
 * @param repo   访问控制仓库。
 * @param siteID 站点 ID。
 * @param userID 用户 ID。
 * @return 命中的用户；未找到或不属于该站点时返回错误。
 */
func findSiteUser(repo *repository.AccessControlRepo, siteID, userID uint) (*store.AccessUser, error) {
	users, err := repo.ListAccessUsers(siteID)
	if err != nil {
		return nil, err
	}
	for i := range users {
		if users[i].ID == userID {
			return &users[i], nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}
