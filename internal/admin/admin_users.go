package admin

import (
	"context"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/admin/shared"
	authstore "My-OpenWaf/internal/store/auth"
	"My-OpenWaf/internal/store/repository"
)

var validRoles = map[string]bool{
	auth.RoleAdmin:    true,
	auth.RoleOperator: true,
	auth.RoleReadonly: true,
}

// ListAdminUsers 返回全部管理员账号（口令哈希经 json:"-" 排除）。
func ListAdminUsers(repo *repository.AdminAccountRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		accounts, err := repo.List()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": accounts})
	}
}

type createAdminUserReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// CreateAdminUser 新建一个管理员账号。
func CreateAdminUser(repo *repository.AdminAccountRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var body createAdminUserReq
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}
		body.Username = strings.TrimSpace(body.Username)
		if body.Username == "" {
			c.JSON(400, map[string]string{"error": "username is required"})
			return
		}
		if len(body.Username) > 64 {
			c.JSON(400, map[string]string{"error": "username must be at most 64 characters"})
			return
		}
		if body.Password == "" {
			c.JSON(400, map[string]string{"error": "password is required"})
			return
		}
		if len(body.Password) < 8 {
			c.JSON(400, map[string]string{"error": "password must be at least 8 characters"})
			return
		}
		if body.Role == "" {
			body.Role = auth.RoleReadonly
		}
		if !validRoles[body.Role] {
			c.JSON(400, map[string]string{"error": "role must be one of: admin, operator, readonly"})
			return
		}

		if existing, _ := repo.GetByUsername(body.Username); existing != nil && existing.ID > 0 {
			c.JSON(409, map[string]string{"error": "username already exists"})
			return
		}

		acct, err := repo.Create(body.Username, body.Password, body.Role)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(201, map[string]any{
			"id":       acct.ID,
			"username": acct.Username,
			"role":     acct.Role,
		})
	}
}

type updateRoleReq struct {
	Role string `json:"role"`
}

// UpdateAdminRole 更新某个管理员账号的角色。
func UpdateAdminRole(repo *repository.AdminAccountRepo, revoker ...func(string, string) error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		var body updateRoleReq
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}
		if !validRoles[body.Role] {
			c.JSON(400, map[string]string{"error": "role must be one of: admin, operator, readonly"})
			return
		}

		acct, err := repo.GetByID(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "admin user not found"})
			return
		}

		if acct.Role == authstore.RoleAdmin && body.Role != authstore.RoleAdmin {
			count, err := repo.CountByRole(authstore.RoleAdmin)
			if err != nil {
				c.JSON(500, map[string]string{"error": err.Error()})
				return
			}
			if count <= 1 {
				c.JSON(400, map[string]string{"error": "cannot demote the last admin user"})
				return
			}
		}

		if err := repo.UpdateRole(id, body.Role); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if acct.Role != body.Role && len(revoker) > 0 && revoker[0] != nil {
			if err := revoker[0](acct.Username, "role_changed"); err != nil {
				c.JSON(500, map[string]string{"error": "role changed but credential revocation failed"})
				return
			}
		}
		c.JSON(200, map[string]string{"status": "ok"})
	}
}

type updatePasswordReq struct {
	Password string `json:"password"`
}

// UpdateAdminPassword 更新某个管理员账号的口令。
func UpdateAdminPassword(repo *repository.AdminAccountRepo, revoker ...func(string, string) error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		var body updatePasswordReq
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}
		if body.Password == "" {
			c.JSON(400, map[string]string{"error": "password is required"})
			return
		}
		if len(body.Password) < 8 {
			c.JSON(400, map[string]string{"error": "password must be at least 8 characters"})
			return
		}

		target, err := repo.GetByID(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "admin user not found"})
			return
		}

		roleVal, _ := c.Get("auth_role")
		role, _ := roleVal.(string)
		usernameVal, _ := c.Get("auth_user")
		currentUser, _ := usernameVal.(string)

		if role != auth.RoleAdmin && target.Username != currentUser {
			c.JSON(403, map[string]string{"error": "can only change your own password"})
			return
		}

		if err := repo.UpdatePasswordByID(id, body.Password); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if len(revoker) > 0 && revoker[0] != nil {
			if err := revoker[0](target.Username, "password_changed"); err != nil {
				c.JSON(500, map[string]string{"error": "password changed but credential revocation failed"})
				return
			}
		}
		c.JSON(200, map[string]string{"status": "ok"})
	}
}

// DeleteAdminUser 删除一个管理员账号。
func DeleteAdminUser(repo *repository.AdminAccountRepo, revoker ...func(string, string) error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}

		acct, err := repo.GetByID(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "admin user not found"})
			return
		}

		usernameVal, _ := c.Get("auth_user")
		currentUser, _ := usernameVal.(string)
		if acct.Username == currentUser {
			c.JSON(400, map[string]string{"error": "cannot delete your own account"})
			return
		}

		if acct.Role == authstore.RoleAdmin {
			count, err := repo.CountByRole(authstore.RoleAdmin)
			if err != nil {
				c.JSON(500, map[string]string{"error": err.Error()})
				return
			}
			if count <= 1 {
				c.JSON(400, map[string]string{"error": "cannot delete the last admin user"})
				return
			}
		}

		if err := repo.Delete(id); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if len(revoker) > 0 && revoker[0] != nil {
			if err := revoker[0](acct.Username, "account_deleted"); err != nil {
				c.JSON(500, map[string]string{"error": "account deleted but credential revocation failed"})
				return
			}
		}
		c.JSON(200, map[string]string{"status": "ok"})
	}
}
