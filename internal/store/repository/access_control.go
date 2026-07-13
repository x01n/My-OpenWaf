package repository

import (
	"time"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

// AccessControlRepo 提供站点访问控制相关模型的持久化操作。
type AccessControlRepo struct{ db *gorm.DB }

// NewAccessControlRepo 构造访问控制仓库。
func NewAccessControlRepo(db *gorm.DB) *AccessControlRepo {
	return &AccessControlRepo{db: db}
}

// GetSiteAccessConfig 读取指定站点的访问控制配置，不存在时返回 gorm.ErrRecordNotFound。
func (r *AccessControlRepo) GetSiteAccessConfig(siteID uint) (*store.SiteAccessConfig, error) {
	var cfg store.SiteAccessConfig
	if err := r.db.Where("site_id = ?", siteID).First(&cfg).Error; err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SaveSiteAccessConfig 创建或更新站点访问控制配置。
func (r *AccessControlRepo) SaveSiteAccessConfig(config *store.SiteAccessConfig) error {
	return r.db.Save(config).Error
}

// ListAccessProviders 按优先级列出站点的所有认证提供方。
func (r *AccessControlRepo) ListAccessProviders(siteID uint) ([]store.AccessProvider, error) {
	var list []store.AccessProvider
	return list, r.db.Where("site_id = ?", siteID).Order("priority ASC, id ASC").Find(&list).Error
}

// CreateAccessProvider 创建认证提供方。
func (r *AccessControlRepo) CreateAccessProvider(provider *store.AccessProvider) error {
	return r.db.Create(provider).Error
}

// UpdateAccessProvider 更新认证提供方。
func (r *AccessControlRepo) UpdateAccessProvider(provider *store.AccessProvider) error {
	return r.db.Save(provider).Error
}

// DeleteAccessProvider 删除认证提供方。
func (r *AccessControlRepo) DeleteAccessProvider(id uint) error {
	return r.db.Delete(&store.AccessProvider{}, id).Error
}

// ListAccessUsers 列出站点的所有本地用户。
func (r *AccessControlRepo) ListAccessUsers(siteID uint) ([]store.AccessUser, error) {
	var list []store.AccessUser
	return list, r.db.Where("site_id = ?", siteID).Order("id ASC").Find(&list).Error
}

// GetAccessUserByName 按站点与用户名读取本地用户，不存在时返回 gorm.ErrRecordNotFound。
func (r *AccessControlRepo) GetAccessUserByName(siteID uint, username string) (*store.AccessUser, error) {
	var user store.AccessUser
	if err := r.db.Where("site_id = ? AND username = ?", siteID, username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetAccessProvider 按 ID 读取认证提供方，不存在时返回 gorm.ErrRecordNotFound。
func (r *AccessControlRepo) GetAccessProvider(id uint) (*store.AccessProvider, error) {
	var provider store.AccessProvider
	if err := r.db.First(&provider, id).Error; err != nil {
		return nil, err
	}
	return &provider, nil
}

// CreateAccessUser 创建本地用户。
func (r *AccessControlRepo) CreateAccessUser(user *store.AccessUser) error {
	return r.db.Create(user).Error
}

// UpdateAccessUser 更新本地用户。
func (r *AccessControlRepo) UpdateAccessUser(user *store.AccessUser) error {
	return r.db.Save(user).Error
}

// DeleteAccessUser 删除本地用户。
func (r *AccessControlRepo) DeleteAccessUser(id uint) error {
	return r.db.Delete(&store.AccessUser{}, id).Error
}

// ListAccessPathRules 按优先级列出站点的路径访问控制规则。
func (r *AccessControlRepo) ListAccessPathRules(siteID uint) ([]store.AccessPathRule, error) {
	var list []store.AccessPathRule
	return list, r.db.Where("site_id = ?", siteID).Order("priority ASC, id ASC").Find(&list).Error
}

// CreateAccessPathRule 创建路径访问控制规则。
func (r *AccessControlRepo) CreateAccessPathRule(rule *store.AccessPathRule) error {
	return r.db.Create(rule).Error
}

// UpdateAccessPathRule 更新路径访问控制规则。
func (r *AccessControlRepo) UpdateAccessPathRule(rule *store.AccessPathRule) error {
	return r.db.Save(rule).Error
}

// DeleteAccessPathRule 删除路径访问控制规则。
func (r *AccessControlRepo) DeleteAccessPathRule(id uint) error {
	return r.db.Delete(&store.AccessPathRule{}, id).Error
}

// CreateAccessSession 创建访问控制会话。
func (r *AccessControlRepo) CreateAccessSession(session *store.AccessSession) error {
	return r.db.Create(session).Error
}

// GetAccessSession 按 token 读取访问控制会话，不存在时返回 gorm.ErrRecordNotFound。
func (r *AccessControlRepo) GetAccessSession(token string) (*store.AccessSession, error) {
	var session store.AccessSession
	if err := r.db.Where("token = ?", token).First(&session).Error; err != nil {
		return nil, err
	}
	return &session, nil
}

// DeleteExpiredAccessSessions 删除所有已过期的会话。
func (r *AccessControlRepo) DeleteExpiredAccessSessions() error {
	return r.db.Where("expires_at < ?", time.Now().UTC()).Delete(&store.AccessSession{}).Error
}

// DeleteAccessSessionsBySite 删除指定站点的所有会话。
func (r *AccessControlRepo) DeleteAccessSessionsBySite(siteID uint) error {
	return r.db.Where("site_id = ?", siteID).Delete(&store.AccessSession{}).Error
}
