package app

import (
	"crypto/tls"
	"testing"

	"My-OpenWaf/internal/core"
	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestSnapshotUpstreamsDeduplicates(t *testing.T) {
	sn := &snapshotpkg.Snapshot{Sites: map[string]snapshotpkg.SiteRuntime{
		"a": {UpstreamURLs: []string{"http://a", "http://b"}},
		"b": {UpstreamURLs: []string{"http://a", ""}},
	}}
	got := snapshotUpstreams(sn)
	if len(got) != 2 || got[0] != "http://a" || got[1] != "http://b" {
		t.Fatalf("unexpected upstream list: %#v", got)
	}
}

func TestListenerRuntimesByBindDeduplicatesBindAndPrefersTLS(t *testing.T) {
	sn := &snapshotpkg.Snapshot{Sites: map[string]snapshotpkg.SiteRuntime{
		"a": {Bind: ":443", Site: store.Site{ID: 1, Bind: ":443", TLSEnabled: false}},
		"b": {Bind: ":443", Site: store.Site{ID: 2, Bind: ":443", TLSEnabled: true}},
		"c": {Bind: ":80", Site: store.Site{ID: 3, Bind: ":80", TLSEnabled: false}},
	}}

	got := listenerRuntimesByBind(sn)
	if len(got) != 2 {
		t.Fatalf("expected one listener per bind, got %d", len(got))
	}

	byBind := make(map[string]snapshotpkg.SiteRuntime)
	for _, rt := range got {
		byBind[rt.Bind] = rt
	}
	if !byBind[":443"].Site.TLSEnabled || byBind[":443"].Site.ID != 2 {
		t.Fatalf("expected TLS runtime to represent :443 listener, got %+v", byBind[":443"])
	}
	if byBind[":80"].Site.ID != 3 {
		t.Fatalf("expected :80 runtime to remain available, got %+v", byBind[":80"].Site)
	}
}

func TestParseALPNProtocolsDefaultsAndDeduplicates(t *testing.T) {
	got := parseALPNProtocols("")
	if len(got) != 2 || got[0] != "h2" || got[1] != "http/1.1" {
		t.Fatalf("unexpected default ALPN list: %#v", got)
	}

	got = parseALPNProtocols(" h2 , http/1.1 , h2 , h3 ")
	want := []string{"h2", "http/1.1", "h3"}
	if len(got) != len(want) {
		t.Fatalf("unexpected ALPN length: got=%#v want=%#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected ALPN order: got=%#v want=%#v", got, want)
		}
	}
}

func TestTCPTLSALPNProtocolsFiltersHTTP3(t *testing.T) {
	got := tcpTLSALPNProtocols("h2,h3,http/1.1")
	want := []string{"h2", "http/1.1"}
	if len(got) != len(want) {
		t.Fatalf("unexpected TCP ALPN list: got=%#v want=%#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected TCP ALPN list: got=%#v want=%#v", got, want)
		}
	}
}

func TestShouldEnableHTTP3(t *testing.T) {
	if !shouldEnableHTTP3("") {
		t.Fatal("empty ALPN should use defaults and enable HTTP/3")
	}
	if !shouldEnableHTTP3("h2, h3, http/1.1") {
		t.Fatal("expected h3 ALPN to enable HTTP/3")
	}
	if shouldEnableHTTP3("h2,http/1.1") {
		t.Fatal("ALPN without h3 should not enable HTTP/3")
	}
	if shouldEnableHTTP3("h3", snapshotpkg.NetworkDefaults{HTTP3Enabled: false}) {
		t.Fatal("network_config.http3_enabled=false should disable HTTP/3")
	}
	if !shouldEnableHTTP3("h3", snapshotpkg.NetworkDefaults{HTTP3Enabled: true}) {
		t.Fatal("network_config.http3_enabled=true should allow HTTP/3")
	}
}

func TestLoadDropPolicyPreservesFallbackForMissingBoolFields(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SystemSettings{}); err != nil {
		t.Fatalf("migrate settings: %v", err)
	}
	repo := repository.NewSystemSettingsRepo(db)
	if err := repo.Set("drop_policy", `{"enabled":false,"bot_score_threshold":90}`); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}

	got := loadDropPolicy(repo, core.DefaultDropConfig())
	if got.Enabled {
		t.Fatalf("expected explicit enabled=false to be preserved, got %#v", got)
	}
	if got.BotScoreThreshold != 90 {
		t.Fatalf("expected bot threshold to be loaded, got %#v", got)
	}
	if !got.CVEAutoDropCritical || !got.CVEAutoDropHigh {
		t.Fatalf("expected missing CVE auto-drop fields to keep fallback true, got %#v", got)
	}
}

func TestParseCipherSuitesRecognizesNames(t *testing.T) {
	got := parseCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,ECDHE_RSA_WITH_AES_256_GCM_SHA384")
	if len(got) != 2 {
		t.Fatalf("expected 2 cipher suites, got %#v", got)
	}
	if got[0] != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("unexpected first cipher suite: %v", got[0])
	}
	if got[1] != tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 {
		t.Fatalf("unexpected second cipher suite: %v", got[1])
	}
}

func TestBuildListenerTLSAppliesALPNAndBounds(t *testing.T) {
	sn := &snapshotpkg.Snapshot{}
	rt := snapshotpkg.SiteRuntime{
		Bind: ":443",
		Site: store.Site{
			TLSEnabled:    true,
			MinTLSVersion: "1.2",
			MaxTLSVersion: "1.3",
			ALPN:          "h2,h3,http/1.1",
		},
	}

	cfg := buildListenerTLS(rt, sn)
	if cfg == nil {
		t.Fatal("expected TLS config")
	}
	if cfg.MinVersion != tls.VersionTLS12 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("unexpected TLS bounds: min=%v max=%v", cfg.MinVersion, cfg.MaxVersion)
	}
	want := []string{"h2", "http/1.1"}
	if len(cfg.NextProtos) != len(want) {
		t.Fatalf("unexpected ALPN list: %#v", cfg.NextProtos)
	}
	for i := range want {
		if cfg.NextProtos[i] != want[i] {
			t.Fatalf("unexpected ALPN list: got=%#v want=%#v", cfg.NextProtos, want)
		}
	}
	if cfg.GetCertificate == nil {
		t.Fatal("expected dynamic certificate selector")
	}
}
