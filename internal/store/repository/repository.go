package repository

import "gorm.io/gorm"

// Repos aggregates all entity repositories.
type Repos struct {
	Listener          *ListenerRepo
	Site              *SiteRepo
	Certificate       *CertificateRepo
	Policy            *PolicyRepo
	Rule              *RuleRepo
	ForwardingProfile *ForwardingProfileRepo
	SystemSettings    *SystemSettingsRepo
	AdminAPIKey       *AdminAPIKeyRepo
	AdminAccount      *AdminAccountRepo
	RefreshToken      *RefreshTokenRepo
	SecurityEvent     *SecurityEventRepo
	IPList            *IPListRepo
}

func New(db *gorm.DB) *Repos {
	return &Repos{
		Listener:          NewListenerRepo(db),
		Site:              NewSiteRepo(db),
		Certificate:       NewCertificateRepo(db),
		Policy:            NewPolicyRepo(db),
		Rule:              NewRuleRepo(db),
		ForwardingProfile: NewForwardingProfileRepo(db),
		SystemSettings:    NewSystemSettingsRepo(db),
		AdminAPIKey:       NewAdminAPIKeyRepo(db),
		AdminAccount:      NewAdminAccountRepo(db),
		RefreshToken:      NewRefreshTokenRepo(db),
		SecurityEvent:     NewSecurityEventRepo(db),
		IPList:            NewIPListRepo(db),
	}
}
