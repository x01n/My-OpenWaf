package store

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestAutoMigrateNormalizesLegacySiteXFFModes(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&legacyXFFModeSite{}); err != nil {
		t.Fatalf("seed legacy sites schema: %v", err)
	}

	legacyModes := []string{"append", "overwrite", "transparent", "legacy_unknown", XFFModeStrip}
	rows := make([]legacyXFFModeSite, 0, len(legacyModes)+2)
	for _, mode := range legacyModes {
		xffMode := mode
		rows = append(rows, legacyXFFModeSite{
			Host:         mode + ".example.com",
			UpstreamURLs: "http://127.0.0.1:8080",
			Bind:         ":80",
			XFFMode:      &xffMode,
		})
	}
	trustMode := XFFModeTrustOuter
	rows = append(rows,
		legacyXFFModeSite{Host: "trust.example.com", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":80", XFFMode: &trustMode},
		legacyXFFModeSite{Host: "null.example.com", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":80"},
	)
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("create legacy sites: %v", err)
	}

	for pass := 1; pass <= 2; pass++ {
		if err := AutoMigrate(db); err != nil {
			t.Fatalf("auto migrate pass %d: %v", pass, err)
		}
	}

	var sites []Site
	if err := db.Find(&sites).Error; err != nil {
		t.Fatalf("load migrated sites: %v", err)
	}
	if len(sites) != len(rows) {
		t.Fatalf("migrated site count = %d, want %d", len(sites), len(rows))
	}
	for _, site := range sites {
		want := XFFModeStrip
		if site.Host == "trust.example.com" {
			want = XFFModeTrustOuter
		}
		if site.XFFMode != want {
			t.Errorf("site %q xff_mode = %q, want %q", site.Host, site.XFFMode, want)
		}
	}
}

type legacyXFFModeSite struct {
	ID           uint `gorm:"primaryKey"`
	Host         string
	UpstreamURLs string
	Bind         string
	XFFMode      *string `gorm:"column:xff_mode"`
}

func (legacyXFFModeSite) TableName() string {
	return "sites"
}
