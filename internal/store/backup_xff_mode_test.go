package store

import "testing"

func TestImportBackupNormalizesLegacySiteXFFModesWithoutMutatingInput(t *testing.T) {
	db := newBackupTestDB(t)
	legacyModes := []string{"append", "overwrite", "transparent", "legacy_unknown", XFFModeStrip}
	data := &BackupData{Version: BackupVersion, Sites: make([]Site, 0, len(legacyModes)+1)}
	for i, mode := range legacyModes {
		data.Sites = append(data.Sites, Site{
			ID:           uint(i + 1),
			Host:         mode + ".example.com",
			UpstreamURLs: "http://127.0.0.1:8080",
			Bind:         ":80",
			XFFMode:      mode,
		})
	}
	data.Sites = append(data.Sites, Site{
		ID:           uint(len(data.Sites) + 1),
		Host:         "trust.example.com",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":80",
		XFFMode:      XFFModeTrustOuter,
	})

	for pass := 1; pass <= 2; pass++ {
		if err := ImportBackup(db, data, false); err != nil {
			t.Fatalf("import pass %d: %v", pass, err)
		}
	}

	for i, site := range data.Sites {
		want := XFFModeTrustOuter
		if i < len(legacyModes) {
			want = legacyModes[i]
		}
		if site.XFFMode != want {
			t.Errorf("backup input site %q xff_mode = %q, want %q", site.Host, site.XFFMode, want)
		}
	}

	var sites []Site
	if err := db.Find(&sites).Error; err != nil {
		t.Fatalf("load imported sites: %v", err)
	}
	if len(sites) != len(data.Sites) {
		t.Fatalf("imported site count = %d, want %d", len(sites), len(data.Sites))
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
