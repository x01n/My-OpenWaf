package store

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestAutoMigrateMigratesLegacyRulePhasesToCustom(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&Policy{}, &Rule{}); err != nil {
		t.Fatalf("seed migrate policy/rule tables: %v", err)
	}

	policy := Policy{Name: "legacy-phase-policy"}
	if err := db.Create(&policy).Error; err != nil {
		t.Fatalf("create policy: %v", err)
	}

	rows := []Rule{
		{
			Name:     "legacy-rate-limit-phase",
			PolicyID: policy.ID,
			Phase:    PhaseRateLimit,
			Pattern:  "block_path:/legacy-rate",
			Action:   ActionIntercept,
			Priority: 10,
			Enabled:  true,
		},
		{
			Name:     "legacy-owasp-phase",
			PolicyID: policy.ID,
			Phase:    PhaseOWASP,
			Pattern:  "tls_sni:legacy.example.com",
			Action:   ActionObserve,
			Priority: 20,
			Enabled:  true,
		},
		{
			Name:     "already-custom",
			PolicyID: policy.ID,
			Phase:    PhaseCustom,
			Pattern:  "block_query_contains:debug",
			Action:   ActionIntercept,
			Priority: 30,
			Enabled:  true,
		},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("create rule %q: %v", rows[i].Name, err)
		}
	}

	if err := AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate second pass: %v", err)
	}

	var got []Rule
	if err := db.Order("id ASC").Find(&got).Error; err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("rule count = %d, want 3", len(got))
	}

	if got[0].Phase != PhaseCustom {
		t.Fatalf("rule %q phase = %q, want %q", got[0].Name, got[0].Phase, PhaseCustom)
	}
	if got[1].Phase != PhaseCustom {
		t.Fatalf("rule %q phase = %q, want %q", got[1].Name, got[1].Phase, PhaseCustom)
	}
	if got[2].Phase != PhaseCustom {
		t.Fatalf("rule %q phase = %q, want %q", got[2].Name, got[2].Phase, PhaseCustom)
	}
}

func TestAutoMigrateExpandsRecordedResourceKeyWithQueryString(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	schema := []string{
		`CREATE TABLE recorded_resources (
			id integer primary key autoincrement,
			created_at datetime,
			updated_at datetime,
			site_id integer not null,
			method text,
			host text,
			path text,
			client_ip text,
			status_code integer,
			content_type text,
			ja3_hash text,
			user_agent text,
			matched_rule_ids text,
			primary_rule_id integer,
			request_headers_json text,
			response_headers_json text,
			request_body_snippet text,
			response_body_snippet text,
			first_seen datetime,
			last_seen datetime,
			hit_count integer
		)`,
		`CREATE UNIQUE INDEX ux_recorded_res_key ON recorded_resources(site_id, method, host, path)`,
	}
	for _, stmt := range schema {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("seed legacy recorded_resources schema: %v", err)
		}
	}

	if err := AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	if !db.Migrator().HasColumn(&RecordedResource{}, "QueryString") {
		t.Fatal("recorded_resources.query_string column should exist after migration")
	}
	if !db.Migrator().HasColumn(&RecordedResource{}, "TLSVersion") {
		t.Fatal("recorded_resources.tls_version column should exist after migration")
	}
	if !db.Migrator().HasColumn(&RecordedResource{}, "TLSSNI") {
		t.Fatal("recorded_resources.tls_sni column should exist after migration")
	}
	if !db.Migrator().HasColumn(&RecordedResource{}, "TLSALPN") {
		t.Fatal("recorded_resources.tls_alpn column should exist after migration")
	}
	if !db.Migrator().HasColumn(&RecordedResource{}, "JA4") {
		t.Fatal("recorded_resources.ja4 column should exist after migration")
	}

	now := time.Now().UTC()
	rows := []RecordedResource{
		{
			SiteID:      1,
			Method:      "GET",
			Host:        "example.com",
			Path:        "/search",
			QueryString: "page=1",
			TLSVersion:  "TLS13",
			TLSSNI:      "example.com",
			TLSALPN:     "h3",
			JA4:         "ja4-a",
			FirstSeen:   now,
			LastSeen:    now,
			HitCount:    1,
		},
		{
			SiteID:      1,
			Method:      "GET",
			Host:        "example.com",
			Path:        "/search",
			QueryString: "page=2",
			TLSVersion:  "TLS13",
			TLSSNI:      "example.com",
			TLSALPN:     "h3",
			JA4:         "ja4-b",
			FirstSeen:   now,
			LastSeen:    now,
			HitCount:    1,
		},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("create migrated recorded resource %d: %v", i, err)
		}
	}

	var total int64
	if err := db.Model(&RecordedResource{}).Count(&total).Error; err != nil {
		t.Fatalf("count recorded resources: %v", err)
	}
	if total != 2 {
		t.Fatalf("recorded resource count after query_string migration = %d, want 2", total)
	}
}

func TestAutoMigrateLegacySQLiteSiteDefaultsKeepInheritedTLSFieldsEmpty(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	if err := db.AutoMigrate(&legacySQLiteSiteTLSDefaults{}); err != nil {
		t.Fatalf("seed legacy sites schema: %v", err)
	}

	if err := AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	site := Site{
		Host:          "legacy.example.com",
		UpstreamURLs:  "http://127.0.0.1:8080",
		Bind:          ":443",
		Network:       "tcp",
		TLSEnabled:    true,
		MaxTLSVersion: "",
		ALPN:          "",
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("create site on migrated legacy schema: %v", err)
	}

	var loaded Site
	if err := db.First(&loaded, site.ID).Error; err != nil {
		t.Fatalf("load created site: %v", err)
	}
	if loaded.MinTLSVersion != "" {
		t.Fatalf("loaded site min_tls_version = %q, want empty", loaded.MinTLSVersion)
	}
	if loaded.MaxTLSVersion != "" {
		t.Fatalf("loaded site max_tls_version = %q, want empty", loaded.MaxTLSVersion)
	}
	if loaded.ALPN != "" {
		t.Fatalf("loaded site alpn = %q, want empty", loaded.ALPN)
	}
}

func TestAutoMigrateConvertsLegacyTLS12SiteMinVersionToInheritanceOnce(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&legacySQLiteSiteTLSDefaults{}); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}

	legacyDefault := legacySQLiteSiteTLSDefaults{
		Host:          "legacy-default.example.com",
		UpstreamURLs:  "http://127.0.0.1:8080",
		Bind:          ":443",
		Network:       "tcp",
		TLSEnabled:    true,
		MinTLSVersion: "TLS12",
	}
	explicitLegacy := legacySQLiteSiteTLSDefaults{
		Host:          "legacy-explicit.example.com",
		UpstreamURLs:  "http://127.0.0.1:8080",
		Bind:          ":8443",
		Network:       "tcp",
		TLSEnabled:    true,
		MinTLSVersion: "TLS11",
	}
	if err := db.Create(&legacyDefault).Error; err != nil {
		t.Fatalf("seed legacy default site: %v", err)
	}
	if err := db.Create(&explicitLegacy).Error; err != nil {
		t.Fatalf("seed explicit legacy site: %v", err)
	}

	if err := AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	var loadedDefault Site
	if err := db.First(&loadedDefault, legacyDefault.ID).Error; err != nil {
		t.Fatalf("load migrated legacy default site: %v", err)
	}
	if loadedDefault.MinTLSVersion != "" {
		t.Fatalf("legacy default min_tls_version = %q, want empty inheritance marker", loadedDefault.MinTLSVersion)
	}

	var loadedExplicit Site
	if err := db.First(&loadedExplicit, explicitLegacy.ID).Error; err != nil {
		t.Fatalf("load explicit legacy site: %v", err)
	}
	if loadedExplicit.MinTLSVersion != "TLS11" {
		t.Fatalf("explicit legacy min_tls_version = %q, want TLS11", loadedExplicit.MinTLSVersion)
	}

	createdAfterMigration := Site{
		Host:          "explicit-tls12-after-migration.example.com",
		UpstreamURLs:  "http://127.0.0.1:8080",
		Bind:          ":9443",
		Network:       "tcp",
		TLSEnabled:    true,
		MinTLSVersion: "TLS12",
	}
	if err := db.Create(&createdAfterMigration).Error; err != nil {
		t.Fatalf("create explicit TLS12 site after migration: %v", err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("second auto migrate: %v", err)
	}

	var loadedAfterMigration Site
	if err := db.First(&loadedAfterMigration, createdAfterMigration.ID).Error; err != nil {
		t.Fatalf("load explicit TLS12 site after second migration: %v", err)
	}
	if loadedAfterMigration.MinTLSVersion != "TLS12" {
		t.Fatalf("post-migration explicit min_tls_version = %q, want TLS12", loadedAfterMigration.MinTLSVersion)
	}
}

func TestAutoMigrateAddsUpstreamHostColumnAndPersistsValues(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&legacySQLiteSiteTLSDefaults{}); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}

	if err := AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	if !db.Migrator().HasColumn(&Site{}, "UpstreamHost") {
		t.Fatal("sites.upstream_host column should exist after auto migrate")
	}

	site := Site{
		Host:         "upstream-host.example.com",
		UpstreamURLs: "http://127.0.0.1:8080",
		UpstreamHost: "backend.example.com",
		Bind:         ":80",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("create site with upstream_host: %v", err)
	}

	var loaded Site
	if err := db.First(&loaded, site.ID).Error; err != nil {
		t.Fatalf("load created site: %v", err)
	}
	if loaded.UpstreamHost != "backend.example.com" {
		t.Fatalf("loaded upstream_host = %q, want %q", loaded.UpstreamHost, "backend.example.com")
	}
}

type legacySQLiteSiteTLSDefaults struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`

	Host         string `gorm:"size:255;not null;index"`
	UpstreamURLs string `gorm:"type:text;not null"`

	Bind    string `gorm:"size:255;not null;index"`
	Network string `gorm:"size:16;default:tcp"`
	Enabled bool   `gorm:"default:true"`

	TLSEnabled    bool `gorm:"default:false"`
	CertID        *uint
	MinTLSVersion string `gorm:"size:32;default:TLS12"`
	MaxTLSVersion string `gorm:"size:32;default:TLS13"`
	CipherSuites  string `gorm:"type:text"`
	ALPN          string `gorm:"size:255;default:h2,http/1.1"`

	PolicyID              *uint
	BotProtectionEnabled  *bool  `gorm:"default:null"`
	BotProtectionLevel    string `gorm:"size:16;default:medium"`
	AttackProtectionLevel string `gorm:"size:16;default:medium"`

	AntiReplayEnabled bool   `gorm:"default:false"`
	AntiReplayTTL     int    `gorm:"default:300"`
	AntiReplayAction  string `gorm:"default:'shield_challenge'"`

	OWASPEnabled     *bool  `gorm:"default:null"`
	OWASPSensitivity string `gorm:"size:16"`
	OWASPAction      string `gorm:"size:32"`
	CVEEnabled       *bool  `gorm:"default:null"`
	CVEAction        string `gorm:"size:32"`
	RateLimitEnabled *bool  `gorm:"default:null"`
	RateLimitWindow  int    `gorm:"default:0"`
	RateLimitMax     int    `gorm:"default:0"`
	RateLimitAction  string `gorm:"size:32"`

	XFFMode              string `gorm:"size:64;default:strip_all_and_set_remote"`
	TrustedCIDR          string `gorm:"type:text"`
	PreserveOriginalHost bool   `gorm:"default:false"`

	MaxBodyBytes          int64  `gorm:"default:10485760"`
	UpstreamTLSSkipVerify bool   `gorm:"default:false"`
	UpstreamTLSServerName string `gorm:"size:255"`

	CacheEnabled    bool   `gorm:"default:false"`
	CacheDefaultTTL int    `gorm:"default:0"`
	CacheRules      string `gorm:"type:text"`

	MaintenanceEnabled bool   `gorm:"default:false"`
	MaintenanceHTML    string `gorm:"type:text"`
	MaintenanceStatus  int    `gorm:"default:503"`

	BlockHTML   string `gorm:"type:text"`
	BlockStatus int    `gorm:"default:403"`

	CustomErrorPages string `gorm:"type:text;default:'{}'"`

	ListenerID          uint `gorm:"index"`
	ForwardingProfileID *uint
	InheritListenerCert bool `gorm:"default:false"`
}

func (legacySQLiteSiteTLSDefaults) TableName() string {
	return "sites"
}
