package snapshot

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"My-OpenWaf/internal/acme"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

func TestLoadDefaultsFallbackOnInvalidJSON(t *testing.T) {
	network := LoadNetworkDefaults(`{"default_network":"tcp6","default_alpn":`)
	if network.DefaultNetwork != DefaultNetworkDefaults().DefaultNetwork || network.DefaultALPN != DefaultNetworkDefaults().DefaultALPN {
		t.Fatalf("invalid network config should use defaults, got %+v", network)
	}

	tlsDefaults := LoadTLSDefaults(`{"min_version":"TLS13","default_alpn":`)
	if tlsDefaults.MinVersion != DefaultTLSDefaults().MinVersion || tlsDefaults.DefaultALPN != DefaultTLSDefaults().DefaultALPN {
		t.Fatalf("invalid TLS config should use defaults, got %+v", tlsDefaults)
	}

	http2cfg := LoadHTTP2Config(`{"max_concurrent_streams":`)
	if http2cfg != DefaultHTTP2Config() {
		t.Fatalf("invalid HTTP/2 config should use defaults, got %+v", http2cfg)
	}
}

func TestSnapshotSystemSettingQueriesUseDialectQuotedKeyColumn(t *testing.T) {
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  "host=127.0.0.1 user=openwaf dbname=openwaf sslmode=disable",
		PreferSimpleProtocol: true,
	}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatalf("open dry-run postgres db: %v", err)
	}

	statements := []string{
		db.Where(systemSettingKeyEquals("network_config")).First(&store.SystemSettings{}).Statement.SQL.String(),
		db.Where(systemSettingKeyEquals("tls_default_config")).First(&store.SystemSettings{}).Statement.SQL.String(),
		db.Where(systemSettingKeyEquals("http2_config")).First(&store.SystemSettings{}).Statement.SQL.String(),
		db.Where(systemSettingKeyEquals("protection")).First(&store.SystemSettings{}).Statement.SQL.String(),
		db.Where(systemSettingKeyEquals(store.SettingKeyHPKP)).First(&store.SystemSettings{}).Statement.SQL.String(),
	}

	for _, sql := range statements {
		if strings.Contains(sql, "`key`") {
			t.Fatalf("SQL should not contain MySQL-style key quoting: %s", sql)
		}
		if !strings.Contains(sql, `"key"`) {
			t.Fatalf("SQL should contain dialect-quoted key column: %s", sql)
		}
	}
}

func TestLoadDefaultsPreserveMissingCriticalFields(t *testing.T) {
	network := LoadNetworkDefaults(`{"http3_enabled":true}`)
	if !network.HTTP3Enabled || network.DefaultNetwork != "tcp" || network.DefaultALPN != "h2,h3,http/1.1" {
		t.Fatalf("partial network config should preserve defaults, got %+v", network)
	}
	network = LoadNetworkDefaults(`{"http2_enabled":true,"http3_enabled":false}`)
	if network.HTTP3Enabled || network.DefaultALPN != "h2,http/1.1" {
		t.Fatalf("missing default_alpn should follow protocol switches, got %+v", network)
	}
	network = LoadNetworkDefaults(`{"http2_enabled":true,"http3_enabled":false,"default_alpn":"h3,http/1.1"}`)
	if network.DefaultALPN != "h3,http/1.1" {
		t.Fatalf("explicit default_alpn should be preserved, got %+v", network)
	}

	tlsDefaults := LoadTLSDefaults(`{"cipher_suites":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}`)
	if tlsDefaults.MinVersion != "TLS10" || tlsDefaults.MaxVersion != "TLS13" || tlsDefaults.DefaultALPN != "h2,h3,http/1.1" {
		t.Fatalf("partial TLS config should preserve defaults, got %+v", tlsDefaults)
	}
	if !tlsDefaults.SessionTicketsEnabled {
		t.Fatalf("missing session_tickets_enabled should default to true, got %+v", tlsDefaults)
	}
	tlsDefaults = LoadTLSDefaults(`{"session_tickets_enabled":false}`)
	if tlsDefaults.SessionTicketsEnabled {
		t.Fatalf("explicit session_tickets_enabled=false should be preserved, got %+v", tlsDefaults)
	}

	http2cfg := LoadHTTP2Config(`{"max_concurrent_streams":250,"max_handlers":7}`)
	if http2cfg.MaxConcurrentStreams != 250 ||
		http2cfg.MaxReadFrameSize != DefaultHTTP2Config().MaxReadFrameSize ||
		http2cfg.IdleTimeoutSeconds != DefaultHTTP2Config().IdleTimeoutSeconds ||
		http2cfg.MaxHeaderBytes != DefaultHTTP2Config().MaxHeaderBytes ||
		http2cfg.MaxHeaderFields != DefaultHTTP2Config().MaxHeaderFields ||
		http2cfg.MaxHandlers != 7 ||
		http2cfg.MaxQueuedControlFrames != DefaultHTTP2Config().MaxQueuedControlFrames {
		t.Fatalf("partial HTTP/2 config should preserve defaults, got %+v", http2cfg)
	}
}

func TestDefaultALPNForProtocolSwitches(t *testing.T) {
	tests := []struct {
		name         string
		http2Enabled bool
		http3Enabled bool
		want         string
	}{
		{name: "http2 and http3 enabled", http2Enabled: true, http3Enabled: true, want: "h2,h3,http/1.1"},
		{name: "http2 only", http2Enabled: true, http3Enabled: false, want: "h2,http/1.1"},
		{name: "http3 only", http2Enabled: false, http3Enabled: true, want: "h3,http/1.1"},
		{name: "http1 only", http2Enabled: false, http3Enabled: false, want: "http/1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DefaultALPNForProtocolSwitches(tt.http2Enabled, tt.http3Enabled); got != tt.want {
				t.Fatalf("DefaultALPNForProtocolSwitches(%v,%v) = %q, want %q", tt.http2Enabled, tt.http3Enabled, got, tt.want)
			}
		})
	}
}

func TestNetworkDefaultsNormalizeAndFallbackNetworkValues(t *testing.T) {
	network := LoadNetworkDefaults(`{"default_network":" TCP6 ","default_alpn":"h2,http/1.1"}`)
	if network.DefaultNetwork != "tcp6" {
		t.Fatalf("default network = %q, want tcp6", network.DefaultNetwork)
	}

	network = LoadNetworkDefaults(`{"default_network":"udp","default_alpn":"h2,http/1.1"}`)
	if network.DefaultNetwork != "tcp" {
		t.Fatalf("invalid default network should fallback to tcp, got %q", network.DefaultNetwork)
	}

	effectiveNetwork, _ := EffectiveSiteNetwork("", "udp", NetworkDefaults{
		HTTP2Enabled:   true,
		HTTP3Enabled:   true,
		DefaultALPN:    "h2,h3,http/1.1",
		DefaultNetwork: "tcp4",
	}, DefaultTLSDefaults())
	if effectiveNetwork != "tcp4" {
		t.Fatalf("invalid site network should fallback to default network, got %q", effectiveNetwork)
	}
}

func TestNormalizeHTTP3Bind(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{name: "empty inherited", input: "", want: "", ok: true},
		{name: "port only", input: " :8443 ", want: ":8443", ok: true},
		{name: "host port", input: "127.0.0.1:8443", want: "127.0.0.1:8443", ok: true},
		{name: "bracketed ipv6", input: "[::1]:8443", want: "[::1]:8443", ok: true},
		{name: "missing port", input: "127.0.0.1", ok: false},
		{name: "bad port", input: ":abc", ok: false},
		{name: "zero port", input: ":0", ok: false},
		{name: "port overflow", input: ":65536", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NormalizeHTTP3Bind(tt.input)
			if ok != tt.ok {
				t.Fatalf("NormalizeHTTP3Bind(%q) ok = %v, want %v", tt.input, ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("NormalizeHTTP3Bind(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLoadHTTP2ConfigNormalizesUnsafeLargeValues(t *testing.T) {
	http2cfg := LoadHTTP2Config(`{"read_timeout_seconds":90,"max_concurrent_streams":100000,"max_read_frame_size":16777216,"idle_timeout_seconds":25,"max_upload_buffer_per_connection":16777216,"max_upload_buffer_per_stream":16777216,"max_header_bytes":16777216,"max_header_fields":10000,"max_handlers":100000,"max_queued_control_frames":100000}`)
	if http2cfg.ReadTimeoutSeconds != 90 || http2cfg.IdleTimeoutSeconds != 25 {
		t.Fatalf("positive timeout values should be preserved, got %+v", http2cfg)
	}
	if http2cfg.MaxConcurrentStreams != MaxHTTP2ConcurrentStreams ||
		http2cfg.MaxReadFrameSize != MaxHTTP2ReadFrameSize ||
		http2cfg.MaxUploadBufferPerConnection != MaxHTTP2UploadBufferPerConnection ||
		http2cfg.MaxUploadBufferPerStream != MaxHTTP2UploadBufferPerStream ||
		http2cfg.MaxHeaderBytes != MaxHTTP2HeaderBytes ||
		http2cfg.MaxHeaderFields != MaxHTTP2HeaderFields ||
		http2cfg.MaxHandlers != MaxHTTP2Handlers ||
		http2cfg.MaxQueuedControlFrames != MaxHTTP2QueuedControlFrames {
		t.Fatalf("unsafe HTTP/2 config should be capped, got %+v", http2cfg)
	}
}

func TestParseTLSCipherSuitesRecognizesNamesAndDeduplicates(t *testing.T) {
	// parseTLSCipherSuites only resolves named cipher suites (not numeric IDs like 49199 or 0xc02f).
	// TLS_AES_128_GCM_SHA256 (0x1301) is a distinct TLS 1.3 suite from TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f).
	got := parseTLSCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,ECDHE_RSA_WITH_AES_128_GCM_SHA256,tls_ecdhe_rsa_with_aes_128_gcm_sha256")
	if len(got) != 1 || got[0] != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("unexpected cipher suites: %#v", got)
	}
}

// TestSnapshotParsePatternRecognizesTLSFingerprintKinds was removed because
// ParsePattern no longer supports TLS fingerprint kinds (tls_version, tls_sni,
// tls_alpn, tls_cipher_suites, header_order_contains).

func TestParseTLSVersionSupportsAliasesAndWireValues(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  uint16
	}{
		{name: "ssl3", input: "SSL3", want: 0x0300},
		{name: "tls13 short", input: "1.3", want: 0x0304},
		{name: "tls12 spaced", input: "TLS 1.2", want: 0x0303},
		{name: "tls11 prefixed", input: "TLSv1.1", want: 0x0302},
		{name: "hex", input: "0x0301", want: 0x0301},
		{name: "decimal", input: "772", want: 0x0304},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseTLSVersion(tt.input); got != tt.want {
				t.Fatalf("ParseTLSVersion(%q) = %#x, want %#x", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseALPNProtocolsDeduplicates(t *testing.T) {
	got := parseALPNProtocols(" h2 , http/1.1 , h2 ")
	want := []string{"h2", "http/1.1"}
	if len(got) != len(want) {
		t.Fatalf("unexpected ALPN list: %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected ALPN list: got=%#v want=%#v", got, want)
		}
	}
}

func TestNormalizeALPNListDeduplicatesAndKeepsCustomProtocols(t *testing.T) {
	if got := NormalizeALPNList(" H2 , h2 , HTTP/1.1 "); got != "h2,http/1.1" {
		t.Fatalf("NormalizeALPNList mixed case = %q, want h2,http/1.1", got)
	}
	if got := NormalizeALPNList(" acme-tls/1 , H3 , acme-tls/1 "); got != "acme-tls/1,h3" {
		t.Fatalf("NormalizeALPNList custom ALPN = %q, want acme-tls/1,h3", got)
	}
	if got := NormalizeALPNList(" , "); got != "" {
		t.Fatalf("NormalizeALPNList empty tokens = %q, want empty", got)
	}
}

func TestParseOCSPStapleAcceptsPEMBase64AndRawText(t *testing.T) {
	der := []byte{0x30, 0x03, 0x0a, 0x01, 0x00}
	pemValue := string(pem.EncodeToMemory(&pem.Block{Type: "OCSP RESPONSE", Bytes: der}))
	encoded := base64.StdEncoding.EncodeToString(der)
	base64Value := encoded[:4] + "\n" + encoded[4:]

	for _, tt := range []struct {
		name string
		raw  string
		want []byte
	}{
		{name: "pem", raw: pemValue, want: der},
		{name: "base64", raw: base64Value, want: der},
		{name: "raw text", raw: "raw-ocsp-response", want: []byte("raw-ocsp-response")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseOCSPStaple(tt.raw)
			if !ok {
				t.Fatalf("ParseOCSPStaple(%q) returned ok=false", tt.name)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("ParseOCSPStaple(%q) = %x, want %x", tt.name, got, tt.want)
			}
		})
	}

	if got, ok := ParseOCSPStaple(" \n\t "); ok || got != nil {
		t.Fatalf("empty OCSP value should return nil,false; got %x,%v", got, ok)
	}
}

func TestEffectiveSiteNetworkHonorsProtocolSwitches(t *testing.T) {
	tests := []struct {
		name     string
		siteALPN string
		defaults NetworkDefaults
		wantALPN string
	}{
		{
			name:     "disable h2 keeps h3 and http1",
			siteALPN: "",
			defaults: NetworkDefaults{HTTP2Enabled: false, HTTP3Enabled: true, DefaultALPN: "h2,h3,http/1.1", DefaultNetwork: "tcp"},
			wantALPN: "h3,http/1.1",
		},
		{
			name:     "disable h2 and h3 falls back to http1",
			siteALPN: "h2,h3,http/1.1",
			defaults: NetworkDefaults{HTTP2Enabled: false, HTTP3Enabled: false, DefaultALPN: "h2,h3,http/1.1", DefaultNetwork: "tcp"},
			wantALPN: "http/1.1",
		},
		{
			name:     "custom alpn keeps unknown protocol",
			siteALPN: "acme-tls/1,h2,http/1.1",
			defaults: NetworkDefaults{HTTP2Enabled: false, HTTP3Enabled: false, DefaultALPN: "h2,h3,http/1.1", DefaultNetwork: "tcp"},
			wantALPN: "acme-tls/1,http/1.1",
		},
		{
			name:     "explicit site alpn disables h3 even when default enables it",
			siteALPN: "h2,http/1.1",
			defaults: NetworkDefaults{HTTP2Enabled: true, HTTP3Enabled: true, DefaultALPN: "h2,h3,http/1.1", DefaultNetwork: "tcp"},
			wantALPN: "h2,http/1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, alpn := EffectiveSiteNetwork(tt.siteALPN, "", tt.defaults, DefaultTLSDefaults())
			if network != "tcp" {
				t.Fatalf("network = %q, want tcp", network)
			}
			if alpn != tt.wantALPN {
				t.Fatalf("alpn = %q, want %q", alpn, tt.wantALPN)
			}
		})
	}
}

func TestEffectiveSiteNetworkPrefersExplicitTLSDefaultALPN(t *testing.T) {
	defaults := NetworkDefaults{
		HTTP2Enabled:   true,
		HTTP3Enabled:   false,
		DefaultALPN:    "http/1.1",
		DefaultNetwork: "tcp",
	}
	tlsDefaults := LoadTLSDefaults(`{"default_alpn":"h2,http/1.1"}`)

	network, alpn := EffectiveSiteNetwork("", "", defaults, tlsDefaults)
	if network != "tcp" {
		t.Fatalf("network = %q, want tcp", network)
	}
	if alpn != "h2,http/1.1" {
		t.Fatalf("alpn = %q, want %q", alpn, "h2,http/1.1")
	}
}

func TestEffectiveSiteNetworkFallsBackToNetworkDefaultALPNWhenTLSDefaultNotExplicit(t *testing.T) {
	defaults := NetworkDefaults{
		HTTP2Enabled:   true,
		HTTP3Enabled:   false,
		DefaultALPN:    "http/1.1",
		DefaultNetwork: "tcp",
	}

	network, alpn := EffectiveSiteNetwork("", "", defaults, DefaultTLSDefaults())
	if network != "tcp" {
		t.Fatalf("network = %q, want tcp", network)
	}
	if alpn != "http/1.1" {
		t.Fatalf("alpn = %q, want %q", alpn, "http/1.1")
	}
}

func TestBuildPreservesExplicitSiteALPNWithoutH3(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	if err := db.Create(&store.SystemSettings{
		Key:   "network_config",
		Value: `{"http2_enabled":true,"http3_enabled":true,"http3_bind":":443","default_alpn":"h2,h3,http/1.1","default_network":"tcp"}`,
	}).Error; err != nil {
		t.Fatalf("seed network config: %v", err)
	}

	site := store.Site{
		Host:         "explicit-alpn.example.test",
		Bind:         ":443",
		Network:      "tcp",
		UpstreamURLs: "http://127.0.0.1:8080",
		Enabled:      true,
		TLSEnabled:   true,
		ALPN:         "h2,http/1.1",
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	rt, ok := sn.MatchSite(":443", "explicit-alpn.example.test")
	if !ok {
		t.Fatal("expected site runtime to be present in snapshot")
	}
	if rt.Site.ALPN != "h2,http/1.1" {
		t.Fatalf("runtime ALPN = %q, want %q", rt.Site.ALPN, "h2,http/1.1")
	}
}

func TestBuildUsesTLSDefaultMaxVersionWhenSiteInherits(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	if err := db.Create(&store.SystemSettings{
		Key:   "tls_default_config",
		Value: `{"min_version":"TLS12","max_version":"TLS12","default_alpn":"h2,http/1.1","curve_preferences":"X25519,CurveP256,CurveP384","prefer_server_cipher_suites":true,"self_signed_on_ip":true}`,
	}).Error; err != nil {
		t.Fatalf("seed tls_default_config: %v", err)
	}

	site := store.Site{
		Host:          "inherit-max-version.example.test",
		Bind:          ":443",
		Network:       "tcp",
		UpstreamURLs:  "http://127.0.0.1:8080",
		Enabled:       true,
		TLSEnabled:    true,
		MinTLSVersion: "TLS12",
		MaxTLSVersion: "",
		ALPN:          "h2,http/1.1",
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	rt, ok := sn.MatchSite(":443", "inherit-max-version.example.test")
	if !ok {
		t.Fatal("expected site runtime to be present in snapshot")
	}
	if rt.Site.MaxTLSVersion != "TLS12" {
		t.Fatalf("runtime max_tls_version = %q, want %q", rt.Site.MaxTLSVersion, "TLS12")
	}
}

func TestBuildFallsBackFromUnsupportedRuntimeTLSVersions(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	if err := db.Create(&store.SystemSettings{
		Key:   "tls_default_config",
		Value: `{"min_version":"TLS11","max_version":"TLS12","default_alpn":"h2,http/1.1","curve_preferences":"X25519,CurveP256,CurveP384","prefer_server_cipher_suites":true,"session_tickets_enabled":true,"self_signed_on_ip":true}`,
	}).Error; err != nil {
		t.Fatalf("seed tls_default_config: %v", err)
	}

	certPEM, keyPEM, err := acme.GenerateSelfSignedPEM("legacy-ssl-runtime.example.test", []string{"legacy-ssl-runtime.example.test"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	cert := store.Certificate{
		Name:    "legacy-ssl-runtime",
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}
	if err := db.Create(&cert).Error; err != nil {
		t.Fatalf("seed certificate: %v", err)
	}

	site := store.Site{
		Host:          "legacy-ssl-runtime.example.test",
		Bind:          ":443",
		Network:       "tcp",
		UpstreamURLs:  "http://127.0.0.1:8080",
		Enabled:       true,
		TLSEnabled:    true,
		CertID:        &cert.ID,
		MinTLSVersion: "SSL3",
		MaxTLSVersion: "0x0300",
		ALPN:          "h2,http/1.1",
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	rt, ok := sn.MatchSite(":443", "legacy-ssl-runtime.example.test")
	if !ok {
		t.Fatal("expected site runtime to be present in snapshot")
	}
	if rt.Site.MinTLSVersion != "TLS11" {
		t.Fatalf("runtime min_tls_version = %q, want TLS11", rt.Site.MinTLSVersion)
	}
	if rt.Site.MaxTLSVersion != "TLS12" {
		t.Fatalf("runtime max_tls_version = %q, want TLS12", rt.Site.MaxTLSVersion)
	}
	if rt.TLSConfig == nil {
		t.Fatal("expected runtime TLS config")
	}
	if rt.TLSConfig.MinVersion != tls.VersionTLS11 {
		t.Fatalf("tls config MinVersion = %#x, want %#x", rt.TLSConfig.MinVersion, tls.VersionTLS11)
	}
	if rt.TLSConfig.MaxVersion != tls.VersionTLS12 {
		t.Fatalf("tls config MaxVersion = %#x, want %#x", rt.TLSConfig.MaxVersion, tls.VersionTLS12)
	}
}

func TestEffectiveSiteTLSFallsBackFromInvalidRuntimeVersionRange(t *testing.T) {
	minVersion, maxVersion, _ := EffectiveSiteTLS("TLS13", "TLS12", "", TLSDefaults{
		MinVersion: "TLS11",
		MaxVersion: "TLS13",
	})
	if minVersion != "TLS11" {
		t.Fatalf("effective min_tls_version = %q, want TLS11", minVersion)
	}
	if maxVersion != "TLS13" {
		t.Fatalf("effective max_tls_version = %q, want TLS13", maxVersion)
	}

	minVersion, maxVersion, _ = EffectiveSiteTLS("TLS13", "TLS12", "", TLSDefaults{
		MinVersion: "SSL3",
		MaxVersion: "TLS10",
	})
	if minVersion != "TLS10" {
		t.Fatalf("fallback min_tls_version = %q, want TLS10", minVersion)
	}
	if maxVersion != "TLS13" {
		t.Fatalf("fallback max_tls_version = %q, want TLS13", maxVersion)
	}
}

func TestEffectiveSiteTLSKeepsExplicitTLS12Minimum(t *testing.T) {
	minVersion, maxVersion, _ := EffectiveSiteTLS("TLS12", "", "", TLSDefaults{
		MinVersion: "TLS10",
		MaxVersion: "TLS13",
	})
	if minVersion != "TLS12" {
		t.Fatalf("explicit site min_tls_version = %q, want TLS12", minVersion)
	}
	if maxVersion != "TLS13" {
		t.Fatalf("inherited max_tls_version = %q, want TLS13", maxVersion)
	}

	minVersion, maxVersion, _ = EffectiveSiteTLS("", "", "", TLSDefaults{
		MinVersion: "TLS10",
		MaxVersion: "TLS13",
	})
	if minVersion != "TLS10" {
		t.Fatalf("empty site min_tls_version = %q, want inherited TLS10", minVersion)
	}
	if maxVersion != "TLS13" {
		t.Fatalf("empty site max_tls_version = %q, want inherited TLS13", maxVersion)
	}
}

// TestBuildAttachesOCSPStapleToSnapshotTLSCertificates was removed because
// Build() no longer attaches OCSP staple data to TLS certificates in the snapshot.

func TestParseCurvePreferencesAliasesAndDeduplicates(t *testing.T) {
	got := ParseCurvePreferences("X25519,P-256,CurveP256,p384")
	if len(got) != 3 {
		t.Fatalf("unexpected curves: %#v", got)
	}
}

func testSiteRuntime(id uint, bind, host string) SiteRuntime {
	return SiteRuntime{
		Site: store.Site{
			ID:   id,
			Host: host,
		},
		Bind: bind,
	}
}

func TestMatchSiteMatchesWithinCurrentBind(t *testing.T) {
	sn := &Snapshot{
		Sites: map[string]SiteRuntime{
			SiteMapKey(":443", "app.example.com"): testSiteRuntime(1, ":443", "app.example.com"),
			SiteMapKey(":443", "*.example.com"):   testSiteRuntime(2, ":443", "*.example.com"),
		},
	}

	tests := []struct {
		name   string
		bind   string
		host   string
		wantID uint
	}{
		{name: "exact match", bind: ":443", host: "app.example.com", wantID: 1},
		{name: "host header with port", bind: ":443", host: "app.example.com:443", wantID: 1},
		{name: "wildcard match", bind: ":443", host: "api.example.com", wantID: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sn.MatchSite(tt.bind, tt.host)
			if !ok {
				t.Fatalf("MatchSite(%q, %q) = no match, want site %d", tt.bind, tt.host, tt.wantID)
			}
			if got.Site.ID != tt.wantID {
				t.Fatalf("MatchSite(%q, %q) = site %d, want %d", tt.bind, tt.host, got.Site.ID, tt.wantID)
			}
		})
	}
}

func TestMatchSitePrefersExactThenWildcardThenCatchAll(t *testing.T) {
	sn := &Snapshot{
		Sites: map[string]SiteRuntime{
			SiteMapKey(":443", "app.example.com"): testSiteRuntime(1, ":443", "app.example.com"),
			SiteMapKey(":443", "*.example.com"):   testSiteRuntime(2, ":443", "*.example.com"),
			SiteMapKey(":443", "*"):               testSiteRuntime(3, ":443", "*"),
			SiteMapKey(":8443", "*"):              testSiteRuntime(4, ":8443", "*"),
		},
	}

	tests := []struct {
		name   string
		bind   string
		host   string
		wantID uint
	}{
		{name: "exact before wildcard and catch-all", bind: ":443", host: "APP.EXAMPLE.COM:443", wantID: 1},
		{name: "wildcard before catch-all", bind: ":443", host: "api.example.com", wantID: 2},
		{name: "bare domain uses catch-all", bind: ":443", host: "example.com", wantID: 3},
		{name: "unmatched domain uses catch-all", bind: ":443", host: "other.test", wantID: 3},
		{name: "IP uses catch-all", bind: ":443", host: "192.0.2.10:443", wantID: 3},
		{name: "catch-all stays within bind", bind: ":8443", host: "other.test", wantID: 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sn.MatchSite(tt.bind, tt.host)
			if !ok {
				t.Fatalf("MatchSite(%q, %q) = no match, want site %d", tt.bind, tt.host, tt.wantID)
			}
			if got.Site.ID != tt.wantID {
				t.Fatalf("MatchSite(%q, %q) = site %d, want %d", tt.bind, tt.host, got.Site.ID, tt.wantID)
			}

			gotPtr, ok := sn.MatchSitePtr(tt.bind, tt.host)
			if !ok || gotPtr == nil {
				t.Fatalf("MatchSitePtr(%q, %q) = no match, want site %d", tt.bind, tt.host, tt.wantID)
			}
			if gotPtr.Site.ID != tt.wantID {
				t.Fatalf("MatchSitePtr(%q, %q) = site %d, want %d", tt.bind, tt.host, gotPtr.Site.ID, tt.wantID)
			}
		})
	}
}

func TestMatchSiteCatchAllDoesNotCrossBinds(t *testing.T) {
	sn := &Snapshot{
		Sites: map[string]SiteRuntime{
			SiteMapKey(":443", "*"): testSiteRuntime(1, ":443", "*"),
		},
	}

	if _, ok := sn.MatchSite(":8443", "other.test"); ok {
		t.Fatal("MatchSite matched catch-all from another bind")
	}
	if got, ok := sn.MatchSitePtr(":8443", "other.test"); ok || got != nil {
		t.Fatal("MatchSitePtr matched catch-all from another bind")
	}
}

func TestMatchSiteIPDetectionAvoidsWildcardForAddresses(t *testing.T) {
	sn := &Snapshot{
		Sites: map[string]SiteRuntime{
			SiteMapKey(":443", "*.0.0.1"):       testSiteRuntime(1, ":443", "*.0.0.1"),
			SiteMapKey(":443", "*.example.com"): testSiteRuntime(2, ":443", "*.example.com"),
		},
	}

	tests := []struct {
		name   string
		host   string
		wantOK bool
		wantID uint
	}{
		{name: "domain still uses wildcard", host: "api.example.com", wantOK: true, wantID: 2},
		{name: "ipv4 does not use wildcard", host: "127.0.0.1", wantOK: false},
		{name: "normalized ipv4 with port does not use wildcard", host: "127.0.0.1:443", wantOK: false},
		{name: "invalid dotted numeric host can use wildcard", host: "300.0.0.1", wantOK: true, wantID: 1},
		{name: "domain with non ip letters bypasses ip parsing", host: "feed.example.com", wantOK: true, wantID: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sn.MatchSite(":443", tt.host)
			if ok != tt.wantOK {
				t.Fatalf("MatchSite(%q, %q) ok=%v, want %v", ":443", tt.host, ok, tt.wantOK)
			}
			if ok && got.Site.ID != tt.wantID {
				t.Fatalf("MatchSite(%q, %q) = site %d, want %d", ":443", tt.host, got.Site.ID, tt.wantID)
			}
		})
	}
}

func BenchmarkMatchSiteNoMatchDomainHost(b *testing.B) {
	sn := &Snapshot{
		Sites: map[string]SiteRuntime{
			SiteMapKey(":443", "app.example.com"): testSiteRuntime(1, ":443", "app.example.com"),
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := sn.MatchSite(":443", "missing.example.com"); ok {
			b.Fatal("unexpected site match")
		}
	}
}

func TestMatchSiteDoesNotFallbackAcrossBinds(t *testing.T) {
	sn := &Snapshot{
		Sites: map[string]SiteRuntime{
			SiteMapKey(":80", "public.example.com"):                testSiteRuntime(1, ":80", "public.example.com"),
			SiteMapKey(":80", "other.example.com"):                 testSiteRuntime(2, ":80", "other.example.com"),
			SiteMapKey("127.0.0.1:8081", "admin.internal.example"): testSiteRuntime(3, "127.0.0.1:8081", "admin.internal.example"),
		},
	}

	if got, ok := sn.MatchSite(":80", "admin.internal.example"); ok {
		t.Fatalf("MatchSite matched cross-bind site %d on bind %q", got.Site.ID, got.Bind)
	}
}

func TestMatchSiteNoMatchReturnsFalse(t *testing.T) {
	sn := &Snapshot{
		Sites: map[string]SiteRuntime{
			SiteMapKey(":8800", "a.example.com"): testSiteRuntime(1, ":8800", "a.example.com"),
			SiteMapKey(":8800", "b.example.com"): testSiteRuntime(2, ":8800", "b.example.com"),
			SiteMapKey(":8800", "*.example.com"): testSiteRuntime(3, ":8800", "*.example.com"),
		},
	}

	tests := []struct {
		name   string
		bind   string
		host   string
		wantOK bool
		wantID uint
	}{
		{name: "exact match a", bind: ":8800", host: "a.example.com", wantOK: true, wantID: 1},
		{name: "exact match b", bind: ":8800", host: "b.example.com", wantOK: true, wantID: 2},
		{name: "wildcard match c", bind: ":8800", host: "c.example.com", wantOK: true, wantID: 3},
		{name: "no match different domain", bind: ":8800", host: "d.other.com", wantOK: false},
		{name: "no match different port", bind: ":9999", host: "a.example.com", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sn.MatchSite(tt.bind, tt.host)
			if ok != tt.wantOK {
				t.Fatalf("MatchSite(%q, %q) ok=%v, want %v", tt.bind, tt.host, ok, tt.wantOK)
			}
			if ok && got.Site.ID != tt.wantID {
				t.Fatalf("MatchSite(%q, %q) = site %d, want %d", tt.bind, tt.host, got.Site.ID, tt.wantID)
			}
		})
	}
}

func TestRegisterSiteKeysRejectsDuplicateBindHostAcrossSites(t *testing.T) {
	sites := make(map[string]SiteRuntime)
	if err := registerSiteKeys(sites, testSiteRuntime(1, ":80", "example.com")); err != nil {
		t.Fatalf("register first site: %v", err)
	}

	err := registerSiteKeys(sites, testSiteRuntime(2, ":80", "EXAMPLE.COM:80"))
	if err == nil {
		t.Fatal("expected duplicate normalized bind and host to be rejected")
	}

	got := sites[SiteMapKey(":80", "example.com")]
	if got.Site.ID != 1 {
		t.Fatalf("registered site ID = %d, want 1", got.Site.ID)
	}
}

func TestRegisterSiteKeysAllowsDuplicateHostWithinSameSite(t *testing.T) {
	sites := make(map[string]SiteRuntime)
	if err := registerSiteKeys(sites, testSiteRuntime(1, ":80", "example.com, EXAMPLE.COM:80")); err != nil {
		t.Fatalf("register duplicate host within same site: %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("registered site key count = %d, want 1", len(sites))
	}
}

func TestRegisterSiteKeysMultiHost(t *testing.T) {
	sites := make(map[string]SiteRuntime)
	// Site with comma-separated hosts including a wildcard
	if err := registerSiteKeys(sites, testSiteRuntime(1, ":80", "a.example.com, b.example.com, *.example.com")); err != nil {
		t.Fatalf("register site keys: %v", err)
	}

	if _, ok := sites[SiteMapKey(":80", "a.example.com")]; !ok {
		t.Fatal("expected a.example.com to be registered")
	}
	if _, ok := sites[SiteMapKey(":80", "b.example.com")]; !ok {
		t.Fatal("expected b.example.com to be registered")
	}
	if _, ok := sites[SiteMapKey(":80", "*.example.com")]; !ok {
		t.Fatal("expected *.example.com to be registered")
	}
	// All three keys should point to the same site
	if sites[SiteMapKey(":80", "a.example.com")].Site.ID != 1 {
		t.Fatal("site ID mismatch for a.example.com")
	}
}

func TestMatchSiteMultiHost(t *testing.T) {
	sites := make(map[string]SiteRuntime)
	if err := registerSiteKeys(sites, testSiteRuntime(1, ":8800", "app.example.com, *.example.org")); err != nil {
		t.Fatalf("register site keys: %v", err)
	}
	sn := &Snapshot{Sites: sites}

	// Exact match
	if rt, ok := sn.MatchSite(":8800", "app.example.com"); !ok || rt.Site.ID != 1 {
		t.Fatal("expected exact match on app.example.com")
	}
	// Wildcard match on the second host
	if rt, ok := sn.MatchSite(":8800", "sub.example.org"); !ok || rt.Site.ID != 1 {
		t.Fatal("expected wildcard match on sub.example.org")
	}
	// No match
	if _, ok := sn.MatchSite(":8800", "other.test.com"); ok {
		t.Fatal("expected no match on other.test.com")
	}
}

func TestMergeProtectionBotNullableOverride(t *testing.T) {
	global := store.DefaultProtectionConfig()
	global.BotDetectionEnabled = true

	inherited := mergeProtection(global, store.Site{})
	if !inherited.BotDetectionEnabled {
		t.Fatal("nil bot override should inherit global enabled value")
	}

	disabled := false
	off := mergeProtection(global, store.Site{BotProtectionEnabled: &disabled})
	if off.BotDetectionEnabled {
		t.Fatal("false bot override should disable site bot detection")
	}

	global.BotDetectionEnabled = false
	enabled := true
	on := mergeProtection(global, store.Site{BotProtectionEnabled: &enabled})
	if !on.BotDetectionEnabled {
		t.Fatal("true bot override should enable site bot detection")
	}
}

func TestMergeProtectionIgnoresSiteFieldsWhenNullableOverrideInherits(t *testing.T) {
	global := store.DefaultProtectionConfig()
	global.OWASPEnabled = true
	global.OWASPSensitivity = "mid"
	global.OWASPAction = "intercept"
	global.CVEEnabled = true
	global.CVEAction = "intercept"
	global.RequestRateLimitEnabled = true
	global.RequestRateLimitWindow = 60
	global.RequestRateLimitMax = 300
	global.RequestRateLimitAction = "rate_limit"

	merged := mergeProtection(global, store.Site{
		OWASPSensitivity: "strict",
		OWASPAction:      "drop",
		CVEAction:        "drop",
		RateLimitWindow:  1,
		RateLimitMax:     1,
		RateLimitAction:  "drop",
	})

	if merged.OWASPEnabled != global.OWASPEnabled ||
		merged.OWASPSensitivity != global.OWASPSensitivity ||
		merged.OWASPAction != global.OWASPAction {
		t.Fatalf("OWASP inherit should keep global values, got %+v", merged)
	}
	if merged.CVEEnabled != global.CVEEnabled || merged.CVEAction != global.CVEAction {
		t.Fatalf("CVE inherit should keep global values, got %+v", merged)
	}
	if merged.RequestRateLimitEnabled != global.RequestRateLimitEnabled ||
		merged.RequestRateLimitWindow != global.RequestRateLimitWindow ||
		merged.RequestRateLimitMax != global.RequestRateLimitMax ||
		merged.RequestRateLimitAction != global.RequestRateLimitAction {
		t.Fatalf("rate limit inherit should keep global values, got %+v", merged)
	}
}

func TestMergeProtectionAppliesSiteFieldsWhenNullableOverrideIsSet(t *testing.T) {
	global := store.DefaultProtectionConfig()
	global.OWASPEnabled = false
	global.OWASPSensitivity = "mid"
	global.OWASPAction = "intercept"
	global.CVEEnabled = false
	global.CVEAction = "intercept"
	global.RequestRateLimitEnabled = false
	global.RequestRateLimitWindow = 60
	global.RequestRateLimitMax = 300
	global.RequestRateLimitAction = "rate_limit"

	enabled := true
	merged := mergeProtection(global, store.Site{
		OWASPEnabled:     &enabled,
		OWASPSensitivity: "strict",
		OWASPAction:      "drop",
		CVEEnabled:       &enabled,
		CVEAction:        "drop",
		RateLimitEnabled: &enabled,
		RateLimitWindow:  1,
		RateLimitMax:     1,
		RateLimitAction:  "drop",
	})

	if !merged.OWASPEnabled || merged.OWASPSensitivity != "strict" || merged.OWASPAction != "drop" {
		t.Fatalf("OWASP site override should apply, got %+v", merged)
	}
	if !merged.CVEEnabled || merged.CVEAction != "drop" {
		t.Fatalf("CVE site override should apply, got %+v", merged)
	}
	if !merged.RequestRateLimitEnabled ||
		merged.RequestRateLimitWindow != 1 ||
		merged.RequestRateLimitMax != 1 ||
		merged.RequestRateLimitAction != "drop" {
		t.Fatalf("rate limit site override should apply, got %+v", merged)
	}
}

func TestMergeProtectionDisablesCVEAutoDropForSiteObserveAction(t *testing.T) {
	global := store.DefaultProtectionConfig()
	global.CVEEnabled = true
	global.CVEAction = string(store.ActionIntercept)
	global.CVEAutoDropCritical = true
	global.CVEAutoDropHigh = true

	enabled := true
	merged := mergeProtection(global, store.Site{
		CVEEnabled: &enabled,
		CVEAction:  string(store.ActionObserve),
	})

	if !merged.CVEEnabled || merged.CVEAction != string(store.ActionObserve) {
		t.Fatalf("CVE observe override should apply, got %+v", merged)
	}
	if merged.CVEAutoDropCritical || merged.CVEAutoDropHigh {
		t.Fatalf("CVE observe override should disable auto drop, got %+v", merged)
	}
}

func newSnapshotBuildDBForTest(t *testing.T) (*gorm.DB, *repository.ApplicationRouteRuleRepo) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&store.Site{},
		&store.SiteListener{},
		&store.Certificate{},
		&store.Rule{},
		&store.ApplicationRouteRule{},
		&store.SystemSettings{},
	); err != nil {
		t.Fatalf("migrate snapshot build tables: %v", err)
	}
	return db, repository.NewApplicationRouteRuleRepo(db)
}

func TestBuildRejectsDuplicateNormalizedRouteAcrossSites(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	sites := []store.Site{
		{
			Host:         "example.com",
			Bind:         ":80",
			Network:      "tcp",
			UpstreamURLs: "http://127.0.0.1:8080",
			Enabled:      true,
		},
		{
			Host:         "EXAMPLE.COM:80",
			Bind:         ":80",
			Network:      "tcp",
			UpstreamURLs: "http://127.0.0.1:8081",
			Enabled:      true,
		},
	}
	if err := db.Create(&sites).Error; err != nil {
		t.Fatalf("seed sites: %v", err)
	}

	if _, err := Build(db, 1); err == nil {
		t.Fatal("expected Build to reject duplicate normalized site route")
	}
}

func TestBuildExcludesDisabledApplicationRouteRules(t *testing.T) {
	db, appRouteRepo := newSnapshotBuildDBForTest(t)
	site := store.Site{
		Host:         "app.example.test",
		Bind:         ":80",
		Network:      "tcp",
		UpstreamURLs: "http://127.0.0.1:8080",
		Enabled:      true,
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}

	enabledRule := &store.ApplicationRouteRule{
		SiteID:   site.ID,
		Name:     "enabled get",
		Enabled:  true,
		Priority: 10,
		Target:   store.AppRouteTargetRequestMethod,
		Op:       store.AppRouteOpEq,
		Pattern:  "GET",
	}
	if err := appRouteRepo.Create(enabledRule); err != nil {
		t.Fatalf("seed enabled rule: %v", err)
	}
	disabledRule := &store.ApplicationRouteRule{
		SiteID:   site.ID,
		Name:     "disabled post",
		Enabled:  false,
		Priority: 20,
		Target:   store.AppRouteTargetRequestMethod,
		Op:       store.AppRouteOpEq,
		Pattern:  "POST",
	}
	if err := appRouteRepo.Create(disabledRule); err != nil {
		t.Fatalf("seed disabled rule: %v", err)
	}

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	rt, ok := sn.Sites[SiteMapKey(":80", "app.example.test")]
	if !ok {
		t.Fatalf("site runtime missing, keys=%v", sn.Sites)
	}
	if len(rt.AppRouteRules) != 1 {
		t.Fatalf("expected one enabled app route rule, got %#v", rt.AppRouteRules)
	}
	if rt.AppRouteRules[0].ID != enabledRule.ID {
		t.Fatalf("expected enabled rule %d, got %#v", enabledRule.ID, rt.AppRouteRules[0])
	}
	if rt.AppRouteRules[0].ID == disabledRule.ID {
		t.Fatalf("disabled rule %d was compiled into snapshot", disabledRule.ID)
	}
}

func TestBuildRejectsInvalidProtectionJSON(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	if err := db.Create(&store.SystemSettings{Key: "protection", Value: `{"cve_enabled":`}).Error; err != nil {
		t.Fatalf("seed invalid protection config: %v", err)
	}

	if _, err := Build(db, 1); err == nil || !strings.Contains(err.Error(), "invalid protection config JSON") {
		t.Fatalf("Build should reject invalid protection JSON, got %v", err)
	}
}

func TestBuildLoadsHSTSEnabledFromSystemSettings(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "enabled", value: "true", want: true},
		{name: "disabled", value: "false", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, _ := newSnapshotBuildDBForTest(t)
			if err := db.Create(&store.SystemSettings{Key: "hsts_enabled", Value: tt.value}).Error; err != nil {
				t.Fatalf("seed hsts setting: %v", err)
			}

			sn, err := Build(db, 1)
			if err != nil {
				t.Fatalf("build snapshot: %v", err)
			}
			if sn.HSTSEnabled != tt.want {
				t.Fatalf("snapshot HSTSEnabled = %v, want %v", sn.HSTSEnabled, tt.want)
			}
		})
	}
}

func TestBuildDefaultsHSTSDisabledWhenSettingMissing(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if sn.HSTSEnabled {
		t.Fatal("snapshot HSTSEnabled should default to false when setting is missing")
	}
}

func TestBuildLoadsXSSProtectionEnabledFromSystemSettings(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "enabled", value: "true", want: true},
		{name: "disabled", value: "false", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, _ := newSnapshotBuildDBForTest(t)
			if err := db.Create(&store.SystemSettings{Key: "xss_protection_enabled", Value: tt.value}).Error; err != nil {
				t.Fatalf("seed xss protection setting: %v", err)
			}

			sn, err := Build(db, 1)
			if err != nil {
				t.Fatalf("build snapshot: %v", err)
			}
			if sn.XSSProtectionEnabled != tt.want {
				t.Fatalf("snapshot XSSProtectionEnabled = %v, want %v", sn.XSSProtectionEnabled, tt.want)
			}
		})
	}
}

func TestBuildDefaultsXSSProtectionDisabledWhenSettingMissing(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if sn.XSSProtectionEnabled {
		t.Fatal("snapshot XSSProtectionEnabled should default to false when setting is missing")
	}
}

func TestBuildLoadsExpectCTSettingsFromSystemSettings(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	if err := db.Create(&store.SystemSettings{Key: "expect_ct_enabled", Value: "true"}).Error; err != nil {
		t.Fatalf("seed expect ct enabled setting: %v", err)
	}
	if err := db.Create(&store.SystemSettings{Key: "expect_ct_value", Value: "max-age=86400, enforce"}).Error; err != nil {
		t.Fatalf("seed expect ct value setting: %v", err)
	}

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if !sn.ExpectCTEnabled {
		t.Fatalf("snapshot ExpectCTEnabled = %v, want true", sn.ExpectCTEnabled)
	}
	if sn.ExpectCTValue != "max-age=86400, enforce" {
		t.Fatalf("snapshot ExpectCTValue = %q, want configured value", sn.ExpectCTValue)
	}
}

func TestBuildDefaultsExpectCTSettingsWhenMissing(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if sn.ExpectCTEnabled {
		t.Fatal("snapshot ExpectCTEnabled should default to false when setting is missing")
	}
	if sn.ExpectCTValue != DefaultExpectCTValue {
		t.Fatalf("snapshot ExpectCTValue = %q, want %q", sn.ExpectCTValue, DefaultExpectCTValue)
	}
}

func TestBuildLoadsHPKPSettingsFromSystemSettings(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	if err := db.Create(&store.SystemSettings{Key: store.SettingKeyHPKP, Value: "true"}).Error; err != nil {
		t.Fatalf("seed hpkp enabled setting: %v", err)
	}
	if err := db.Create(&store.SystemSettings{Key: store.SettingKeyHPKPValue, Value: `pin-sha256="abc"; max-age=86400; includeSubDomains`}).Error; err != nil {
		t.Fatalf("seed hpkp value setting: %v", err)
	}
	if err := db.Create(&store.SystemSettings{Key: store.SettingKeyHPKPReportOnly, Value: "true"}).Error; err != nil {
		t.Fatalf("seed hpkp report only enabled setting: %v", err)
	}
	if err := db.Create(&store.SystemSettings{Key: store.SettingKeyHPKPReportOnlyValue, Value: `pin-sha256="abc"; max-age=86400; report-uri="https://report.example/hpkp"`}).Error; err != nil {
		t.Fatalf("seed hpkp report only value setting: %v", err)
	}

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if !sn.HPKPEnabled || sn.HPKPValue != `pin-sha256="abc"; max-age=86400; includeSubDomains` {
		t.Fatalf("snapshot HPKP settings not loaded: %#v", sn)
	}
	if !sn.HPKPReportOnlyEnabled || sn.HPKPReportOnlyValue != `pin-sha256="abc"; max-age=86400; report-uri="https://report.example/hpkp"` {
		t.Fatalf("snapshot HPKP report only settings not loaded: %#v", sn)
	}
}

func TestBuildDefaultsHPKPSettingsWhenMissing(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if sn.HPKPEnabled || sn.HPKPReportOnlyEnabled {
		t.Fatalf("snapshot HPKP flags should default to false, got enabled=%v report_only=%v", sn.HPKPEnabled, sn.HPKPReportOnlyEnabled)
	}
	if sn.HPKPValue != DefaultHPKPValue || sn.HPKPReportOnlyValue != DefaultHPKPReportOnlyValue {
		t.Fatalf("snapshot HPKP values should use defaults, got hpkp=%q report_only=%q", sn.HPKPValue, sn.HPKPReportOnlyValue)
	}
}

func TestBuildLoadsBrotliEnabledFromSystemSettings(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "enabled", value: "true", want: true},
		{name: "disabled", value: "false", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, _ := newSnapshotBuildDBForTest(t)
			if err := db.Create(&store.SystemSettings{Key: "brotli_enabled", Value: tt.value}).Error; err != nil {
				t.Fatalf("seed brotli setting: %v", err)
			}

			sn, err := Build(db, 1)
			if err != nil {
				t.Fatalf("build snapshot: %v", err)
			}
			if sn.BrotliEnabled != tt.want {
				t.Fatalf("snapshot BrotliEnabled = %v, want %v", sn.BrotliEnabled, tt.want)
			}
		})
	}
}

func TestBuildLoadsResponseCompressionSettingsFromSystemSettings(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	if err := db.Create(&store.SystemSettings{Key: "response_compression_enabled", Value: "false"}).Error; err != nil {
		t.Fatalf("seed response compression enabled setting: %v", err)
	}
	if err := db.Create(&store.SystemSettings{Key: "response_compression_gzip_enabled", Value: "false"}).Error; err != nil {
		t.Fatalf("seed response compression gzip enabled setting: %v", err)
	}
	if err := db.Create(&store.SystemSettings{Key: "response_compression_min_bytes", Value: "4096"}).Error; err != nil {
		t.Fatalf("seed response compression min bytes setting: %v", err)
	}

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if sn.ResponseCompressionEnabled {
		t.Fatalf("snapshot ResponseCompressionEnabled = %v, want false", sn.ResponseCompressionEnabled)
	}
	if sn.ResponseCompressionGzipEnabled {
		t.Fatalf("snapshot ResponseCompressionGzipEnabled = %v, want false", sn.ResponseCompressionGzipEnabled)
	}
	if sn.ResponseCompressionMinBytes != 4096 {
		t.Fatalf("snapshot ResponseCompressionMinBytes = %d, want 4096", sn.ResponseCompressionMinBytes)
	}
}

func TestBuildDefaultsResponseCompressionSettingsWhenMissing(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	// loadBoolSetting returns false when the setting row is missing,
	// so both compression booleans default to false without explicit DB rows.
	if sn.ResponseCompressionEnabled {
		t.Fatalf("snapshot ResponseCompressionEnabled = %v, want false (loadBoolSetting default)", sn.ResponseCompressionEnabled)
	}
	if sn.ResponseCompressionGzipEnabled {
		t.Fatalf("snapshot ResponseCompressionGzipEnabled = %v, want false (loadBoolSetting default)", sn.ResponseCompressionGzipEnabled)
	}
	if sn.ResponseCompressionMinBytes != DefaultResponseCompressionMinBytes {
		t.Fatalf("snapshot ResponseCompressionMinBytes = %d, want %d", sn.ResponseCompressionMinBytes, DefaultResponseCompressionMinBytes)
	}
}

func TestBuildLoadsHTTP2ConfigFromSystemSettings(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	if err := db.Create(&store.SystemSettings{Key: "http2_config", Value: `{"read_timeout_seconds":90,"disable_keepalive":true,"permit_prohibited_cipher_suites":false,"max_concurrent_streams":300,"max_read_frame_size":131072,"idle_timeout_seconds":25,"max_upload_buffer_per_connection":1048576,"max_upload_buffer_per_stream":524288,"max_header_bytes":262144,"max_header_fields":80,"max_handlers":24,"max_queued_control_frames":2048}`}).Error; err != nil {
		t.Fatalf("seed http2 config: %v", err)
	}

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if sn.HTTP2Config.ReadTimeoutSeconds != 90 ||
		!sn.HTTP2Config.DisableKeepalive ||
		sn.HTTP2Config.PermitProhibitedCipherSuites ||
		sn.HTTP2Config.MaxConcurrentStreams != 300 ||
		sn.HTTP2Config.MaxReadFrameSize != 131072 ||
		sn.HTTP2Config.IdleTimeoutSeconds != 25 ||
		sn.HTTP2Config.MaxUploadBufferPerConnection != 1048576 ||
		sn.HTTP2Config.MaxUploadBufferPerStream != 524288 ||
		sn.HTTP2Config.MaxHeaderBytes != 262144 ||
		sn.HTTP2Config.MaxHeaderFields != 80 ||
		sn.HTTP2Config.MaxHandlers != 24 ||
		sn.HTTP2Config.MaxQueuedControlFrames != 2048 {
		t.Fatalf("snapshot HTTP2Config not loaded as expected, got %+v", sn.HTTP2Config)
	}
}

func TestBuildNormalizesUnsafeHTTP2ConfigFromSystemSettings(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	if err := db.Create(&store.SystemSettings{Key: "http2_config", Value: `{"read_timeout_seconds":90,"max_concurrent_streams":100000,"max_read_frame_size":16777216,"idle_timeout_seconds":25,"max_upload_buffer_per_connection":16777216,"max_upload_buffer_per_stream":16777216,"max_header_bytes":16777216,"max_header_fields":10000,"max_handlers":100000,"max_queued_control_frames":100000}`}).Error; err != nil {
		t.Fatalf("seed http2 config: %v", err)
	}

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if sn.HTTP2Config.ReadTimeoutSeconds != 90 || sn.HTTP2Config.IdleTimeoutSeconds != 25 {
		t.Fatalf("positive timeout values should be preserved, got %+v", sn.HTTP2Config)
	}
	if sn.HTTP2Config.MaxConcurrentStreams != MaxHTTP2ConcurrentStreams ||
		sn.HTTP2Config.MaxReadFrameSize != MaxHTTP2ReadFrameSize ||
		sn.HTTP2Config.MaxUploadBufferPerConnection != MaxHTTP2UploadBufferPerConnection ||
		sn.HTTP2Config.MaxUploadBufferPerStream != MaxHTTP2UploadBufferPerStream ||
		sn.HTTP2Config.MaxHeaderBytes != MaxHTTP2HeaderBytes ||
		sn.HTTP2Config.MaxHeaderFields != MaxHTTP2HeaderFields ||
		sn.HTTP2Config.MaxHandlers != MaxHTTP2Handlers ||
		sn.HTTP2Config.MaxQueuedControlFrames != MaxHTTP2QueuedControlFrames {
		t.Fatalf("snapshot HTTP2Config should be capped, got %+v", sn.HTTP2Config)
	}
}

func TestBuildDefaultsHTTP2ConfigWhenSettingMissing(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if sn.HTTP2Config != DefaultHTTP2Config() {
		t.Fatalf("snapshot HTTP2Config should default when setting missing, got %+v", sn.HTTP2Config)
	}
}

func TestBuildDefaultsBrotliDisabledWhenSettingMissing(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if sn.BrotliEnabled {
		t.Fatal("snapshot BrotliEnabled should default to false when setting is missing")
	}
}

func TestCompileCCRulesBuildsCompoundCustomRule(t *testing.T) {
	protection := store.ProtectionConfig{
		CCUseCustom: true,
		CCRules: `[
			{
				"name":"admin post challenge",
				"enabled":true,
				"action":"captcha",
				"conditions":[
					{"target":"url_path","operator":"prefix","value":"/admin"},
					{"target":"method","operator":"equals","value":"post"}
				],
				"window":60,
				"threshold":100,
				"duration":5
			}
		]`,
	}

	rules := compileCCRules(protection)
	if len(rules) != 1 {
		t.Fatalf("compileCCRules() returned %d rules, want 1", len(rules))
	}
	if rules[0].Phase != store.PhaseCustom {
		t.Fatalf("phase = %q, want %q", rules[0].Phase, store.PhaseCustom)
	}
	if rules[0].Action != store.ActionChallenge {
		t.Fatalf("action = %q, want %q", rules[0].Action, store.ActionChallenge)
	}
	if rules[0].Kind != "compound" {
		t.Fatalf("kind = %q, want compound", rules[0].Kind)
	}
	if !strings.Contains(rules[0].Arg, `"op":"cc_rate"`) {
		t.Fatalf("compound arg missing cc_rate op: %s", rules[0].Arg)
	}
	if !strings.Contains(rules[0].Arg, `"threshold":100`) {
		t.Fatalf("compound arg missing threshold: %s", rules[0].Arg)
	}
	if !strings.Contains(rules[0].Arg, `"window":60`) {
		t.Fatalf("compound arg missing window: %s", rules[0].Arg)
	}
	if !strings.Contains(rules[0].Arg, `"op":"and"`) {
		t.Fatalf("compound arg missing and op: %s", rules[0].Arg)
	}
	if !strings.Contains(rules[0].Arg, `"kind":"block_path"`) {
		t.Fatalf("compound arg missing path matcher: %s", rules[0].Arg)
	}
	if !strings.Contains(rules[0].Arg, `"arg":"/admin"`) {
		t.Fatalf("compound arg missing path value: %s", rules[0].Arg)
	}
	if !strings.Contains(rules[0].Arg, `"kind":"block_method"`) {
		t.Fatalf("compound arg missing method matcher: %s", rules[0].Arg)
	}
	if !strings.Contains(rules[0].Arg, `"arg":"POST"`) {
		t.Fatalf("compound arg missing normalized method: %s", rules[0].Arg)
	}
}

func TestCompileCCRulesDisabledWhenCustomCCOff(t *testing.T) {
	protection := store.ProtectionConfig{
		CCRules: `[
			{
				"action":"block",
				"conditions":[{"target":"url_path","operator":"contains","value":"/login"}]
			}
		]`,
	}

	if rules := compileCCRules(protection); len(rules) != 0 {
		t.Fatalf("compileCCRules() returned %d rules, want 0", len(rules))
	}
}

func TestCompileCCRulesSkipsUnsupportedConditions(t *testing.T) {
	protection := store.ProtectionConfig{
		CCUseCustom: true,
		CCRules: `[
			{
				"name":"method contains draft",
				"enabled":true,
				"action":"observe",
				"conditions":[{"target":"method","operator":"contains","value":"POST"}]
			}
		]`,
	}

	if rules := compileCCRules(protection); len(rules) != 0 {
		t.Fatalf("compileCCRules() returned %d rules, want 0", len(rules))
	}
}

// validCCRulesJSON 返回一条可编译的 CC 规则 JSON（供站点级测试复用）。
func validCCRulesJSON() string {
	return `[
		{
			"name":"site rule",
			"enabled":true,
			"action":"block",
			"conditions":[{"target":"url_path","operator":"prefix","value":"/api"}],
			"window":60,
			"threshold":50,
			"duration":10
		}
	]`
}

func TestSiteCCRulesInheritsGlobalWhenNil(t *testing.T) {
	global := compileCCRulesFromJSON(validCCRulesJSON())
	if len(global) != 1 {
		t.Fatalf("global cc rules = %d, want 1", len(global))
	}
	// CCUseCustom 为 nil：站点继承全局规则。
	site := store.Site{CCUseCustom: nil}
	got := siteCCRules(site, global)
	if len(got) != len(global) {
		t.Fatalf("inherited cc rules = %d, want %d", len(got), len(global))
	}
}

func TestSiteCCRulesDisabledWhenExplicitlyOff(t *testing.T) {
	global := compileCCRulesFromJSON(validCCRulesJSON())
	off := false
	// CCUseCustom = false：站点显式关闭，忽略全局规则。
	site := store.Site{CCUseCustom: &off, CCRules: validCCRulesJSON()}
	if got := siteCCRules(site, global); len(got) != 0 {
		t.Fatalf("disabled site cc rules = %d, want 0", len(got))
	}
}

func TestSiteCCRulesUsesSiteRulesWhenEnabled(t *testing.T) {
	// 全局为空，站点自定义启用：应使用站点自身规则。
	on := true
	site := store.Site{CCUseCustom: &on, CCRules: validCCRulesJSON()}
	got := siteCCRules(site, nil)
	if len(got) != 1 {
		t.Fatalf("site cc rules = %d, want 1", len(got))
	}
	if got[0].Phase != store.PhaseCustom {
		t.Fatalf("phase = %q, want %q", got[0].Phase, store.PhaseCustom)
	}
	if !strings.Contains(got[0].Arg, `"threshold":50`) {
		t.Fatalf("site rule missing threshold: %s", got[0].Arg)
	}
}

func TestSiteCCRulesEnabledButEmptyReturnsNil(t *testing.T) {
	// CCUseCustom = true 但站点 CCRules 为空：返回空（不回退全局）。
	on := true
	site := store.Site{CCUseCustom: &on, CCRules: ""}
	global := compileCCRulesFromJSON(validCCRulesJSON())
	if got := siteCCRules(site, global); len(got) != 0 {
		t.Fatalf("enabled-but-empty site cc rules = %d, want 0", len(got))
	}
}

func TestCompileCCRulesBuildsHeaderRule(t *testing.T) {
	protection := store.ProtectionConfig{
		CCUseCustom: true,
		CCRules: `[
			{
				"action":"block",
				"conditions":[{"target":"header","operator":"contains","value":"User-Agent:curl"}]
			}
		]`,
	}

	rules := compileCCRules(protection)
	if len(rules) != 1 {
		t.Fatalf("compileCCRules() returned %d rules, want 1", len(rules))
	}
	if rules[0].Kind != "block_header" {
		t.Fatalf("kind = %q, want block_header", rules[0].Kind)
	}
	if rules[0].Arg != "User-Agent:curl" {
		t.Fatalf("arg = %q, want User-Agent:curl", rules[0].Arg)
	}
}

func TestCompileCCRulesBuildsSinglePathRule(t *testing.T) {
	protection := store.ProtectionConfig{
		CCUseCustom: true,
		CCRules: `[
			{
				"action":"observe",
				"conditions":[{"target":"url_path","operator":"equals","value":"/login"}]
			}
		]`,
	}

	rules := compileCCRules(protection)
	if len(rules) != 1 {
		t.Fatalf("compileCCRules() returned %d rules, want 1", len(rules))
	}
	if rules[0].Kind != "block_path_exact" {
		t.Fatalf("kind = %q, want block_path_exact", rules[0].Kind)
	}
	if rules[0].Arg != "/login" {
		t.Fatalf("arg = %q, want /login", rules[0].Arg)
	}
	if rules[0].Action != store.ActionObserve {
		t.Fatalf("action = %q, want %q", rules[0].Action, store.ActionObserve)
	}
}

func TestCompileCCRulesKeepsSpecificChallengeAndRateLimitActions(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want store.RuleAction
	}{
		{name: "captcha challenge", raw: "captcha_challenge", want: store.ActionCaptchaChallenge},
		{name: "shield challenge", raw: "shield_challenge", want: store.ActionShieldChallenge},
		{name: "chain challenge", raw: "chain_challenge", want: store.ActionChainChallenge},
		{name: "rate limit", raw: "rate_limit", want: store.ActionRateLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			protection := store.ProtectionConfig{
				CCUseCustom: true,
				CCRules: `[{
					"action":"` + tt.raw + `",
					"conditions":[{"target":"url_path","operator":"equals","value":"/login"}]
				}]`,
			}

			rules := compileCCRules(protection)
			if len(rules) != 1 {
				t.Fatalf("compileCCRules() returned %d rules, want 1", len(rules))
			}
			if rules[0].Action != tt.want {
				t.Fatalf("action = %q, want %q", rules[0].Action, tt.want)
			}
		})
	}
}

func TestParseUpstreamURLsSupportsJSONArray(t *testing.T) {
	got := parseUpstreamURLs(`[" http://127.0.0.1:8800 ", "", "https://example.com"]`)
	want := []string{"http://127.0.0.1:8800", "https://example.com"}
	if len(got) != len(want) {
		t.Fatalf("parseUpstreamURLs() returned %d urls, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("url[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseUpstreamURLsKeepsCommaFormat(t *testing.T) {
	got := parseUpstreamURLs(` http://127.0.0.1:8800 , https://example.com `)
	want := []string{"http://127.0.0.1:8800", "https://example.com"}
	if len(got) != len(want) {
		t.Fatalf("parseUpstreamURLs() returned %d urls, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("url[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBuildCompilesAndResolvesUpstreamHostTemplate(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	site := store.Site{
		Host:         "app.example.test",
		Bind:         ":80",
		Network:      "tcp",
		UpstreamURLs: "http://127.0.0.1:8080",
		UpstreamHost: "{{.Host}}.internal",
		Enabled:      true,
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	rt, ok := sn.MatchSite(":80", "app.example.test")
	if !ok {
		t.Fatal("site was not matched")
	}
	// ResolveOutboundHost returns the raw UpstreamHost value when set,
	// without template expansion.
	got, err := ResolveOutboundHost(rt, "127.0.0.1:8080", "app.example.test")
	if err != nil {
		t.Fatalf("ResolveOutboundHost returned error: %v", err)
	}
	if got != "{{.Host}}.internal" {
		t.Fatalf("resolved host = %q, want %q", got, "{{.Host}}.internal")
	}
}

func TestBuildPrecomputesStaticUpstreamHost(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	site := store.Site{
		Host:         "app.example.test",
		Bind:         ":80",
		Network:      "tcp",
		UpstreamURLs: "http://127.0.0.1:8080",
		UpstreamHost: "backend.example.com:8443",
		Enabled:      true,
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}

	sn, err := Build(db, 1)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	rt, ok := sn.MatchSite(":80", "app.example.test")
	if !ok {
		t.Fatal("site was not matched")
	}
	// Build does not precompute UpstreamHostHeader; ResolveOutboundHost
	// returns the raw Site.UpstreamHost value directly.
	if rt.Site.UpstreamHost != "backend.example.com:8443" {
		t.Fatalf("site upstream host = %q, want %q", rt.Site.UpstreamHost, "backend.example.com:8443")
	}
	got, err := ResolveOutboundHost(rt, "127.0.0.1:8080", "app.example.test")
	if err != nil {
		t.Fatalf("ResolveOutboundHost returned error: %v", err)
	}
	if got != "backend.example.com:8443" {
		t.Fatalf("resolved host = %q, want %q", got, "backend.example.com:8443")
	}
}

func BenchmarkResolveOutboundHostStaticPrecomputed(b *testing.B) {
	rt := SiteRuntime{
		Site:               store.Site{UpstreamHost: "backend.example.com:8443"},
		UpstreamHostHeader: "backend.example.com:8443",
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ResolveOutboundHost(rt, "127.0.0.1:8080", "app.example.test"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestParseSiteCacheRulesSuffixNoLeadingSlash(t *testing.T) {
	raw := `[{"type":"suffix","value":"config","ttl":10}]`
	rules := parseSiteCacheRules(raw)
	// Bare token without ".", "/", "?" is treated as a file extension → ".config"
	if len(rules) != 1 || rules[0].Path != ".config" {
		t.Fatalf("got %#v", rules)
	}
}

func TestParseSiteCacheRulesCommaSeparatedSuffixes(t *testing.T) {
	raw := `[{"type":"suffix","value":".js,.mjs","ttl":10}]`
	rules := parseSiteCacheRules(raw)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d %#v", len(rules), rules)
	}
}

func TestParseSiteCacheRulesSuffixBareExtensions(t *testing.T) {
	raw := `[{"type":"suffix","value":"js,html,css","ttl":10}]`
	rules := parseSiteCacheRules(raw)
	if len(rules) != 3 {
		t.Fatalf("want 3 rules, got %d %#v", len(rules), rules)
	}
	want := map[string]bool{".js": true, ".html": true, ".css": true}
	for _, r := range rules {
		if !want[r.Path] {
			t.Fatalf("unexpected pattern %q in %#v", r.Path, rules)
		}
	}
}

func TestParseSiteCacheRulesSuffixMultiDotPreserved(t *testing.T) {
	raw := `[{"type":"suffix","value":"min.js,tar.gz","ttl":10}]`
	rules := parseSiteCacheRules(raw)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d %#v", len(rules), rules)
	}
	got := map[string]bool{rules[0].Path: true, rules[1].Path: true}
	if !got["min.js"] || !got["tar.gz"] {
		t.Fatalf("want min.js and tar.gz unchanged, got %#v", rules)
	}
}

func TestParseSiteCacheRulesContainsNoForcedSlash(t *testing.T) {
	raw := `[{"type":"contains","value":"v=1","ttl":10}]`
	rules := parseSiteCacheRules(raw)
	if len(rules) != 1 || rules[0].Path != "v=1" {
		t.Fatalf("got %#v", rules)
	}
}

func TestParseSiteCacheRulesRegexCompiled(t *testing.T) {
	raw := `[{"type":"regex","value":"\\.(js|css)$","ttl":10}]`
	rules := parseSiteCacheRules(raw)
	if len(rules) != 1 || rules[0].Regex == nil {
		t.Fatalf("got %#v", rules)
	}
	if !rules[0].Regex.MatchString("/a/b.js") {
		t.Fatal("expected regex match")
	}
}

func TestParseSiteCacheRulesRegexCaseInsensitive(t *testing.T) {
	raw := `[{"type":"regex","value":"\\.js$","ttl":10,"case_insensitive":true}]`
	rules := parseSiteCacheRules(raw)
	if len(rules) != 1 || rules[0].Regex == nil {
		t.Fatalf("got %#v", rules)
	}
	if !rules[0].Regex.MatchString("/a/b.JS") {
		t.Fatal("expected case-insensitive regex match")
	}
}
