package repository

import (
	"testing"

	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestRecordedResourceRepoUpsertIncrementsHitCount(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.RecordedResource{}); err != nil {
		t.Fatalf("migrate recorded resource: %v", err)
	}

	repo := NewRecordedResourceRepo(db)
	first := &store.RecordedResource{
		SiteID:         1,
		Method:         "GET",
		Host:           "example.com",
		Path:           "/login",
		QueryString:    "redirect=%2Fconsole",
		StatusCode:     200,
		TLSVersion:     "TLS13",
		TLSSNI:         "example.com",
		TLSALPN:        "h2",
		JA4:            "ja4-a",
		MatchedRuleIDs: "1",
		PrimaryRuleID:  1,
		HitCount:       1,
	}
	if err := repo.Upsert(first); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	second := &store.RecordedResource{
		SiteID:         1,
		Method:         "GET",
		Host:           "example.com",
		Path:           "/login",
		QueryString:    "redirect=%2Fconsole",
		StatusCode:     403,
		TLSVersion:     "TLS13",
		TLSSNI:         "example.com",
		TLSALPN:        "h2",
		JA4:            "ja4-b",
		MatchedRuleIDs: "2",
		PrimaryRuleID:  2,
		HitCount:       1,
	}
	if err := repo.Upsert(second); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	var got store.RecordedResource
	if err := db.Where("site_id = ? AND method = ? AND host = ? AND path = ?", 1, "GET", "example.com", "/login").First(&got).Error; err != nil {
		t.Fatalf("load recorded resource: %v", err)
	}
	if got.HitCount != 2 || got.StatusCode != 403 || got.TLSVersion != "TLS13" || got.TLSSNI != "example.com" || got.TLSALPN != "h2" || got.JA4 != "ja4-b" || got.PrimaryRuleID != 2 || got.MatchedRuleIDs != "2" {
		t.Fatalf("upsert did not refresh aggregate row: %#v", got)
	}
}

func TestRecordedResourceRepoUpsertSeparatesQueryStringVariants(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.RecordedResource{}); err != nil {
		t.Fatalf("migrate recorded resource: %v", err)
	}

	repo := NewRecordedResourceRepo(db)
	rows := []*store.RecordedResource{
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
			HitCount:    1,
		},
	}
	for i := range rows {
		if err := repo.Upsert(rows[i]); err != nil {
			t.Fatalf("upsert recorded resource %d: %v", i, err)
		}
	}

	var total int64
	if err := db.Model(&store.RecordedResource{}).Count(&total).Error; err != nil {
		t.Fatalf("count recorded resources: %v", err)
	}
	if total != 2 {
		t.Fatalf("recorded resource count = %d, want 2", total)
	}
}

func TestRecordedResourceRepoUpsertPreservesHistoricalRuleMetadataWhenCurrentRequestDoesNotMatchRule(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.RecordedResource{}); err != nil {
		t.Fatalf("migrate recorded resource: %v", err)
	}

	repo := NewRecordedResourceRepo(db)
	first := &store.RecordedResource{
		SiteID:         1,
		Method:         "GET",
		Host:           "example.com",
		Path:           "/catalog",
		QueryString:    "page=1",
		StatusCode:     200,
		MatchedRuleIDs: "11,12",
		PrimaryRuleID:  11,
		HitCount:       1,
	}
	if err := repo.Upsert(first); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	second := &store.RecordedResource{
		SiteID:      1,
		Method:      "GET",
		Host:        "example.com",
		Path:        "/catalog",
		QueryString: "page=1",
		StatusCode:  200,
		HitCount:    1,
	}
	if err := repo.Upsert(second); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	var got store.RecordedResource
	if err := db.Where("site_id = ? AND method = ? AND host = ? AND path = ? AND query_string = ?", 1, "GET", "example.com", "/catalog", "page=1").First(&got).Error; err != nil {
		t.Fatalf("load recorded resource: %v", err)
	}
	if got.HitCount != 2 {
		t.Fatalf("HitCount = %d, want 2", got.HitCount)
	}
	if got.PrimaryRuleID != 11 {
		t.Fatalf("PrimaryRuleID = %d, want 11", got.PrimaryRuleID)
	}
	if got.MatchedRuleIDs != "11,12" {
		t.Fatalf("MatchedRuleIDs = %q, want %q", got.MatchedRuleIDs, "11,12")
	}
}

func TestRecordedResourceRepoListBySiteAppliesFilters(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.RecordedResource{}); err != nil {
		t.Fatalf("migrate recorded resource: %v", err)
	}

	rows := []store.RecordedResource{
		{
			SiteID:         1,
			Method:         "GET",
			Host:           "api.example.com",
			Path:           "/api/login",
			QueryString:    "redirect=%2Fconsole&token=vip",
			ClientIP:       "203.0.113.10",
			StatusCode:     200,
			TLSVersion:     "TLS13",
			TLSSNI:         "api.example.com",
			TLSALPN:        "h2",
			JA3Hash:        "ja3-a",
			JA4:            "ja4-a",
			UserAgent:      "curl/8.0",
			MatchedRuleIDs: "9,12",
			PrimaryRuleID:  9,
			HitCount:       3,
		},
		{
			SiteID:         1,
			Method:         "POST",
			Host:           "www.example.com",
			Path:           "/submit",
			QueryString:    "redirect=%2Fdocs&token=basic",
			ClientIP:       "203.0.113.11",
			StatusCode:     403,
			TLSVersion:     "TLS12",
			TLSSNI:         "www.example.com",
			TLSALPN:        "http/1.1",
			JA3Hash:        "ja3-b",
			JA4:            "ja4-b",
			UserAgent:      "Mozilla/5.0",
			MatchedRuleIDs: "12",
			PrimaryRuleID:  12,
			HitCount:       1,
		},
		{
			SiteID:        2,
			Method:        "GET",
			Host:          "other.example.com",
			Path:          "/submit",
			QueryString:   "site=other",
			ClientIP:      "203.0.113.12",
			StatusCode:    200,
			TLSVersion:    "TLS13",
			TLSSNI:        "other.example.com",
			TLSALPN:       "h2",
			JA3Hash:       "ja3-c",
			JA4:           "ja4-c",
			UserAgent:     "Mozilla/5.0",
			PrimaryRuleID: 12,
			HitCount:      1,
		},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("seed recorded resource %d: %v", i, err)
		}
	}

	repo := NewRecordedResourceRepo(db)

	items, total, err := repo.ListBySite(1, 0, 20, RecordedResourceFilter{
		Path:       "/submit",
		StatusCode: 403,
		TLSVersion: "TLS12",
		TLSSNI:     "www.example.com",
		TLSALPN:    "http/1.1",
		JA3Hash:    "ja3-b",
		JA4:        "ja4-b",
		RuleID:     12,
	})
	if err != nil {
		t.Fatalf("ListBySite filtered query: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("filtered total/items = %d/%d, want 1/1", total, len(items))
	}
	if items[0].Host != "www.example.com" {
		t.Fatalf("unexpected filtered row: %#v", items[0])
	}

	items, total, err = repo.ListBySite(1, 0, 20, RecordedResourceFilter{
		RuleID: 12,
	})
	if err != nil {
		t.Fatalf("ListBySite rule_id query: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("rule_id total/items = %d/%d, want 2/2", total, len(items))
	}

	items, total, err = repo.ListBySite(1, 0, 20, RecordedResourceFilter{
		UserAgent: "curl",
	})
	if err != nil {
		t.Fatalf("ListBySite user_agent query: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Path != "/api/login" {
		t.Fatalf("unexpected user_agent result: total=%d items=%#v", total, items)
	}

	items, total, err = repo.ListBySite(1, 0, 20, RecordedResourceFilter{
		QueryString: "token=vip",
	})
	if err != nil {
		t.Fatalf("ListBySite query_string query: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Host != "api.example.com" {
		t.Fatalf("unexpected query_string result: total=%d items=%#v", total, items)
	}

	items, total, err = repo.ListBySite(1, 0, 20, RecordedResourceFilter{
		TLSVersion: "TLS 1.3",
	})
	if err != nil {
		t.Fatalf("ListBySite tls_version query: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("unexpected tls_version result: total=%d items=%#v", total, items)
	}

	items, total, err = repo.ListBySite(1, 0, 20, RecordedResourceFilter{
		TLSSNI: "api.example.com",
	})
	if err != nil {
		t.Fatalf("ListBySite tls_sni query: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Host != "api.example.com" {
		t.Fatalf("unexpected tls_sni result: total=%d items=%#v", total, items)
	}

	items, total, err = repo.ListBySite(1, 0, 20, RecordedResourceFilter{
		TLSALPN: "h2",
	})
	if err != nil {
		t.Fatalf("ListBySite tls_alpn query: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("unexpected tls_alpn result: total=%d items=%#v", total, items)
	}

	items, total, err = repo.ListBySite(1, 0, 20, RecordedResourceFilter{
		JA4: "ja4-b",
	})
	if err != nil {
		t.Fatalf("ListBySite ja4 query: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].JA4 != "ja4-b" {
		t.Fatalf("unexpected ja4 result: total=%d items=%#v", total, items)
	}

	items, total, err = repo.ListBySite(1, 0, 20, RecordedResourceFilter{
		Query: "403",
	})
	if err != nil {
		t.Fatalf("ListBySite unified numeric query: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].StatusCode != 403 {
		t.Fatalf("unexpected unified numeric result: total=%d items=%#v", total, items)
	}

	items, total, err = repo.ListBySite(1, 0, 20, RecordedResourceFilter{
		Query: "curl/8.0",
	})
	if err != nil {
		t.Fatalf("ListBySite unified user agent query: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Host != "api.example.com" {
		t.Fatalf("unexpected unified user agent result: total=%d items=%#v", total, items)
	}

	items, total, err = repo.ListBySite(1, 0, 20, RecordedResourceFilter{
		Query: "ja4-b",
	})
	if err != nil {
		t.Fatalf("ListBySite unified ja4 query: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].JA4 != "ja4-b" {
		t.Fatalf("unexpected unified ja4 result: total=%d items=%#v", total, items)
	}

	items, total, err = repo.ListBySite(1, 0, 20, RecordedResourceFilter{
		Query: "http/1.1",
	})
	if err != nil {
		t.Fatalf("ListBySite unified tls query: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].TLSSNI != "www.example.com" {
		t.Fatalf("unexpected unified tls query result: total=%d items=%#v", total, items)
	}
}
