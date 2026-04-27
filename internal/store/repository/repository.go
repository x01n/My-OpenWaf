package repository

import "gorm.io/gorm"

// Repos aggregates all entity repositories.
type Repos struct {
	Site           *SiteRepo
	Certificate    *CertificateRepo
	Policy         *PolicyRepo
	Rule           *RuleRepo
	SystemSettings *SystemSettingsRepo
	AdminAPIKey    *AdminAPIKeyRepo
	AdminAccount   *AdminAccountRepo
	RefreshToken   *RefreshTokenRepo
	SecurityEvent  *SecurityEventRepo
	AccessLog      *AccessLogRepo
	IPList         *IPListRepo
	BotScore       *BotScoreRepo
	CVERule        *CVERuleRepo
	CVESyncLog     *CVESyncLogRepo
	DropEvent      *DropEventRepo
	Fingerprint    *FingerprintRepo
}

func New(db *gorm.DB) *Repos {
	return &Repos{
		Site:           NewSiteRepo(db),
		Certificate:    NewCertificateRepo(db),
		Policy:         NewPolicyRepo(db),
		Rule:           NewRuleRepo(db),
		SystemSettings: NewSystemSettingsRepo(db),
		AdminAPIKey:    NewAdminAPIKeyRepo(db),
		AdminAccount:   NewAdminAccountRepo(db),
		RefreshToken:   NewRefreshTokenRepo(db),
		SecurityEvent:  NewSecurityEventRepo(db),
		AccessLog:      NewAccessLogRepo(db),
		IPList:         NewIPListRepo(db),
		BotScore:       NewBotScoreRepo(db),
		CVERule:        NewCVERuleRepo(db),
		CVESyncLog:     NewCVESyncLogRepo(db),
		DropEvent:      NewDropEventRepo(db),
		Fingerprint:    NewFingerprintRepo(db),
	}
}
