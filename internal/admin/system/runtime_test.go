package system

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/proxy"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

func TestBuildTLSCapabilityStatusesReportsRuntimeProtocolBounds(t *testing.T) {
	statuses := buildTLSCapabilityStatuses(
		snapshot.DefaultNetworkDefaults(),
		snapshot.DefaultTLSDefaults(),
		TLSCapabilityStatus{Key: "caa"},
		TLSCapabilityStatus{Key: "ocsp_stapling"},
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	)

	byKey := make(map[string]TLSCapabilityStatus, len(statuses))
	for _, status := range statuses {
		byKey[status.Key] = status
	}

	for _, key := range []string{"tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3"} {
		status, ok := byKey[key]
		if !ok {
			t.Fatalf("missing capability %q", key)
		}
		if status.Status != "supported" || status.Missing {
			t.Fatalf("capability %q = %+v, want supported and not missing", key, status)
		}
	}

	for _, key := range []string{"ssl_1", "ssl_2", "ssl_3"} {
		status, ok := byKey[key]
		if !ok {
			t.Fatalf("missing capability %q", key)
		}
		if status.Status != "not_supported" || !status.Missing {
			t.Fatalf("capability %q = %+v, want not_supported and missing", key, status)
		}
		if !strings.Contains(status.Detail, "不支持") || !strings.Contains(status.Detail, "不进入运行态 TLS 配置") {
			t.Fatalf("capability %q detail = %q, want explicit non-runtime SSL detail", key, status.Detail)
		}
	}
}

func TestBuildTLSCapabilityStatusesUseFrontendStatusContract(t *testing.T) {
	statuses := buildTLSCapabilityStatuses(
		snapshot.DefaultNetworkDefaults(),
		snapshot.DefaultTLSDefaults(),
		TLSCapabilityStatus{Key: "caa", Status: "disabled"},
		TLSCapabilityStatus{Key: "ocsp_stapling", Status: "disabled"},
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	)

	allowed := map[string]struct{}{
		"supported":     {},
		"enabled":       {},
		"disabled":      {},
		"not_supported": {},
	}
	for _, status := range statuses {
		if _, ok := allowed[status.Status]; !ok {
			t.Fatalf("capability %q status = %q, want frontend contract status", status.Key, status.Status)
		}
		if status.Missing && status.Status != "not_supported" {
			t.Fatalf("capability %q = %+v, missing must only be true for not_supported", status.Key, status)
		}
	}
}

func TestBuildTLSCapabilityStatusesReportsCipherSuitesAndCurvePreferences(t *testing.T) {
	defaults := snapshot.DefaultTLSDefaults()
	defaults.CipherSuites = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_AES_128_GCM_SHA256"
	defaults.CurvePreferences = "X25519,CurveP256"
	defaults.PreferServerCipherSuites = false

	statuses := buildTLSCapabilityStatuses(
		snapshot.DefaultNetworkDefaults(),
		defaults,
		TLSCapabilityStatus{Key: "caa"},
		TLSCapabilityStatus{Key: "ocsp_stapling"},
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	)

	cipherSuites := capabilityByKey(t, statuses, "cipher_suites")
	if cipherSuites.Status != "enabled" || cipherSuites.Missing {
		t.Fatalf("cipher_suites capability = %+v, want enabled and not missing", cipherSuites)
	}
	for _, want := range []string{
		"tls.Config.CipherSuites",
		"TLS1.0-1.2",
		"TLS1.3",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_AES_128_GCM_SHA256",
		"未进入 tls.Config.CipherSuites",
		"prefer_server_cipher_suites=false",
		"legacy",
		"ignored",
	} {
		if !strings.Contains(cipherSuites.Detail, want) {
			t.Fatalf("cipher_suites detail = %q, want %q", cipherSuites.Detail, want)
		}
	}

	curves := capabilityByKey(t, statuses, "curve_preferences")
	if curves.Status != "enabled" || curves.Missing {
		t.Fatalf("curve_preferences capability = %+v, want enabled and not missing", curves)
	}
	for _, want := range []string{
		"tls.Config.CurvePreferences",
		"X25519",
		"CurveP256",
		"HTTP/3 UDP/QUIC",
	} {
		if !strings.Contains(curves.Detail, want) {
			t.Fatalf("curve_preferences detail = %q, want %q", curves.Detail, want)
		}
	}
}

func TestBuildTLSCapabilityStatusesReportsTLSConfigFallbacks(t *testing.T) {
	defaults := snapshot.DefaultTLSDefaults()
	defaults.CipherSuites = "TLS_AES_128_GCM_SHA256"
	defaults.CurvePreferences = "UNKNOWN_CURVE"

	statuses := buildTLSCapabilityStatuses(
		snapshot.DefaultNetworkDefaults(),
		defaults,
		TLSCapabilityStatus{Key: "caa"},
		TLSCapabilityStatus{Key: "ocsp_stapling"},
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	)

	cipherSuites := capabilityByKey(t, statuses, "cipher_suites")
	if cipherSuites.Status != "disabled" || cipherSuites.Missing {
		t.Fatalf("cipher_suites capability = %+v, want disabled custom tls.Config.CipherSuites and not missing", cipherSuites)
	}
	for _, want := range []string{
		"未解析出可写入 tls.Config.CipherSuites",
		"TLS_AES_128_GCM_SHA256",
		"TLS1.3",
	} {
		if !strings.Contains(cipherSuites.Detail, want) {
			t.Fatalf("cipher_suites detail = %q, want %q", cipherSuites.Detail, want)
		}
	}

	curves := capabilityByKey(t, statuses, "curve_preferences")
	if curves.Status != "supported" || curves.Missing {
		t.Fatalf("curve_preferences capability = %+v, want supported fallback and not missing", curves)
	}
	for _, want := range []string{
		"未解析出有效曲线",
		"X25519",
		"CurveP384",
		"tls.Config.CurvePreferences",
	} {
		if !strings.Contains(curves.Detail, want) {
			t.Fatalf("curve_preferences detail = %q, want %q", curves.Detail, want)
		}
	}
}

func TestBuildTLSCapabilityStatusesOrdersSSLVersionsNumerically(t *testing.T) {
	statuses := buildTLSCapabilityStatuses(
		snapshot.DefaultNetworkDefaults(),
		snapshot.DefaultTLSDefaults(),
		TLSCapabilityStatus{Key: "caa"},
		TLSCapabilityStatus{Key: "ocsp_stapling"},
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	)

	var got []string
	for _, status := range statuses {
		switch status.Key {
		case "ssl_1", "ssl_2", "ssl_3":
			got = append(got, status.Key)
		}
	}
	want := []string{"ssl_1", "ssl_2", "ssl_3"}
	if len(got) != len(want) {
		t.Fatalf("SSL capability keys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SSL capability keys = %v, want %v", got, want)
		}
	}
}

func TestRuntimeTransportPoolsSummarizesProxyPools(t *testing.T) {
	got := runtimeTransportPools(proxy.UpstreamTransportPoolStats{
		HTTPTransports:           2,
		HTTP2CleartextTransports: 1,
		HTTP3Transports:          3,
		HTTPClients:              5,
		HTTPNoTimeoutClients:     7,
		HTTP3Clients:             11,
		HTTP3NoTimeoutClients:    13,
	})

	if got.HTTPTransports != 2 || got.HTTP2CleartextTransports != 1 || got.HTTP3Transports != 3 || got.TotalTransports != 6 {
		t.Fatalf("transport pools = %+v, want HTTP/H2C/HTTP3/total 2/1/3/6", got)
	}
	if got.HTTPClients != 5 ||
		got.HTTPNoTimeoutClients != 7 ||
		got.HTTP3Clients != 11 ||
		got.HTTP3NoTimeoutClients != 13 ||
		got.TotalClients != 36 {
		t.Fatalf("client pools = %+v, want HTTP/HTTP no-timeout/HTTP3/HTTP3 no-timeout/total 5/7/11/13/36", got)
	}
}

func TestBuildTLSCapabilityStatusesRespectsTLSDefaultRange(t *testing.T) {
	defaults := snapshot.DefaultTLSDefaults()
	defaults.MinVersion = "TLS12"
	defaults.MaxVersion = "TLS13"

	statuses := buildTLSCapabilityStatuses(
		snapshot.DefaultNetworkDefaults(),
		defaults,
		TLSCapabilityStatus{Key: "caa"},
		TLSCapabilityStatus{Key: "ocsp_stapling"},
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	)

	byKey := make(map[string]TLSCapabilityStatus, len(statuses))
	for _, status := range statuses {
		byKey[status.Key] = status
	}

	for _, key := range []string{"tls_1_0", "tls_1_1"} {
		status := byKey[key]
		if status.Status != "disabled" || status.Missing {
			t.Fatalf("capability %q = %+v, want disabled and not missing", key, status)
		}
		if !strings.Contains(status.Detail, "当前范围为 TLS12 到 TLS13") {
			t.Fatalf("capability %q detail = %q, want current TLS range", key, status.Detail)
		}
	}
	for _, key := range []string{"tls_1_2", "tls_1_3"} {
		status := byKey[key]
		if status.Status != "supported" || status.Missing {
			t.Fatalf("capability %q = %+v, want supported and not missing", key, status)
		}
		if !strings.Contains(status.Detail, "当前范围为 TLS12 到 TLS13") {
			t.Fatalf("capability %q detail = %q, want current TLS range", key, status.Detail)
		}
	}
}

func TestBuildTLSCapabilityStatusesReportsEffectiveInheritedALPN(t *testing.T) {
	networkDefaults := snapshot.NetworkDefaults{
		HTTP2Enabled:   true,
		HTTP3Enabled:   true,
		HTTP3Bind:      ":8443",
		DefaultALPN:    "http/1.1",
		DefaultNetwork: "tcp",
	}
	tlsDefaults := snapshot.TLSDefaults{
		MinVersion:             "TLS10",
		MaxVersion:             "TLS13",
		DefaultALPN:            "h2,h3,http/1.1",
		HasExplicitDefaultALPN: true,
		SessionTicketsEnabled:  true,
	}

	statuses := buildTLSCapabilityStatuses(
		networkDefaults,
		tlsDefaults,
		TLSCapabilityStatus{Key: "caa"},
		TLSCapabilityStatus{Key: "ocsp_stapling"},
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	)

	alpn := capabilityByKey(t, statuses, "alpn")
	if !strings.Contains(alpn.Detail, "h2,h3,http/1.1") {
		t.Fatalf("ALPN capability detail = %q, want inherited TLS default ALPN", alpn.Detail)
	}
}

func TestBuildTLSCapabilityStatusesReportsHTTPProtocolALPNPreconditions(t *testing.T) {
	networkDefaults := snapshot.NetworkDefaults{
		HTTP2Enabled:   true,
		HTTP3Enabled:   true,
		HTTP3Bind:      ":8443",
		DefaultALPN:    "http/1.1",
		DefaultNetwork: "tcp",
	}
	tlsDefaults := snapshot.TLSDefaults{
		MinVersion:             "TLS10",
		MaxVersion:             "TLS13",
		DefaultALPN:            "http/1.1",
		HasExplicitDefaultALPN: true,
		SessionTicketsEnabled:  true,
	}

	statuses := buildTLSCapabilityStatuses(
		networkDefaults,
		tlsDefaults,
		TLSCapabilityStatus{Key: "caa"},
		TLSCapabilityStatus{Key: "ocsp_stapling"},
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	)

	http2 := capabilityByKey(t, statuses, "http2")
	if http2.Status != "enabled" || !strings.Contains(http2.Detail, "未包含 h2") {
		t.Fatalf("HTTP/2 capability = %+v, want enabled with missing h2 ALPN detail", http2)
	}
	http3 := capabilityByKey(t, statuses, "http3")
	if http3.Status != "enabled" || !strings.Contains(http3.Detail, "未包含 h3") || !strings.Contains(http3.Detail, ":8443") {
		t.Fatalf("HTTP/3 capability = %+v, want enabled with missing h3 ALPN and bind detail", http3)
	}
}

func TestRuntimeHTTP3BindDetailNormalizesAndFallsBack(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: " ", want: snapshot.DefaultNetworkDefaults().HTTP3Bind},
		{name: "trimmed port", input: " :8443 ", want: ":8443"},
		{name: "host port", input: "127.0.0.1:9443", want: "127.0.0.1:9443"},
		{name: "invalid host without port", input: "127.0.0.1", want: snapshot.DefaultNetworkDefaults().HTTP3Bind},
		{name: "zero port", input: ":0", want: snapshot.DefaultNetworkDefaults().HTTP3Bind},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runtimeHTTP3BindDetail(tt.input); got != tt.want {
				t.Fatalf("runtimeHTTP3BindDetail(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildTLSCapabilityStatusesReportsHTTP2TLS12Precondition(t *testing.T) {
	networkDefaults := snapshot.NetworkDefaults{
		HTTP2Enabled:   true,
		HTTP3Enabled:   true,
		HTTP3Bind:      ":8443",
		DefaultALPN:    "h2,h3,http/1.1",
		DefaultNetwork: "tcp",
	}
	tlsDefaults := snapshot.TLSDefaults{
		MinVersion:             "TLS10",
		MaxVersion:             "TLS11",
		DefaultALPN:            "h2,h3,http/1.1",
		HasExplicitDefaultALPN: true,
		SessionTicketsEnabled:  true,
	}

	statuses := buildTLSCapabilityStatuses(
		networkDefaults,
		tlsDefaults,
		TLSCapabilityStatus{Key: "caa"},
		TLSCapabilityStatus{Key: "ocsp_stapling"},
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	)

	http2 := capabilityByKey(t, statuses, "http2")
	if http2.Status != "enabled" {
		t.Fatalf("HTTP/2 capability status = %q, want enabled protocol switch", http2.Status)
	}
	if !strings.Contains(http2.Detail, "最高版本为 TLS11") ||
		!strings.Contains(http2.Detail, "移除 h2") ||
		!strings.Contains(http2.Detail, "TLS12 及以上") {
		t.Fatalf("HTTP/2 capability detail = %q, want TLS12 precondition detail", http2.Detail)
	}
	tls12 := capabilityByKey(t, statuses, "tls_1_2")
	if tls12.Status != "disabled" || tls12.Missing {
		t.Fatalf("TLS 1.2 capability = %+v, want disabled and not missing", tls12)
	}
}

func TestBuildTLSCapabilityStatusesReportsHTTP3QUICUsesTLS13(t *testing.T) {
	networkDefaults := snapshot.NetworkDefaults{
		HTTP2Enabled:   true,
		HTTP3Enabled:   true,
		HTTP3Bind:      ":8443",
		DefaultALPN:    "h2,h3,http/1.1",
		DefaultNetwork: "tcp",
	}
	tlsDefaults := snapshot.TLSDefaults{
		MinVersion:             "TLS10",
		MaxVersion:             "TLS11",
		DefaultALPN:            "h2,h3,http/1.1",
		HasExplicitDefaultALPN: true,
		SessionTicketsEnabled:  true,
	}

	statuses := buildTLSCapabilityStatuses(
		networkDefaults,
		tlsDefaults,
		TLSCapabilityStatus{Key: "caa"},
		TLSCapabilityStatus{Key: "ocsp_stapling"},
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	)

	http3 := capabilityByKey(t, statuses, "http3")
	if http3.Status != "enabled" {
		t.Fatalf("HTTP/3 capability status = %q, want enabled protocol switch", http3.Status)
	}
	if !strings.Contains(http3.Detail, "UDP/QUIC") ||
		!strings.Contains(http3.Detail, "TLS1.3") ||
		!strings.Contains(http3.Detail, "h3 ALPN") ||
		!strings.Contains(http3.Detail, "不随继承 TLS 版本范围降级") {
		t.Fatalf("HTTP/3 capability detail = %q, want QUIC TLS1.3 boundary detail", http3.Detail)
	}
}

func TestEnrichTLSCapabilitiesWithHTTP2ConfigReportsSettingsAndReloadDetail(t *testing.T) {
	cfg := snapshot.DefaultHTTP2Config()
	cfg.ReadTimeoutSeconds = 90
	cfg.DisableKeepalive = true
	cfg.PermitProhibitedCipherSuites = false
	cfg.MaxConcurrentStreams = 7
	cfg.MaxReadFrameSize = 64 << 10
	cfg.IdleTimeoutSeconds = 25
	cfg.MaxUploadBufferPerConnection = 1 << 20
	cfg.MaxUploadBufferPerStream = 512 << 10
	cfg.MaxHeaderBytes = 2048
	cfg.MaxHeaderFields = 5
	cfg.MaxHandlers = 24
	cfg.MaxQueuedControlFrames = 2048

	statuses := []TLSCapabilityStatus{
		{Key: "http2", Detail: "http2 detail"},
		{Key: "http3", Detail: "http3 detail"},
	}
	got := enrichTLSCapabilitiesWithHTTP2Config(statuses, cfg)
	http2 := capabilityByKey(t, got, "http2")
	for _, want := range []string{
		"read_timeout_seconds=90",
		"disable_keepalive=true",
		"permit_prohibited_cipher_suites=false",
		"max_concurrent_streams=7",
		"max_read_frame_size=65536",
		"max_upload_buffer_per_connection=1048576",
		"max_upload_buffer_per_stream=524288",
		"max_header_bytes=2048",
		"max_header_fields=5",
		"max_handlers=24",
		"max_queued_control_frames=2048",
		"SETTINGS_MAX_CONCURRENT_STREAMS=7",
		"SETTINGS_MAX_FRAME_SIZE=65536",
		"SETTINGS_MAX_HEADER_LIST_SIZE=2208",
		"listener tag",
		"新连接使用新 SETTINGS",
		"已有 h2 连接不阻塞热重载",
	} {
		if !strings.Contains(http2.Detail, want) {
			t.Fatalf("HTTP/2 capability detail = %q, want %q", http2.Detail, want)
		}
	}
	http3 := capabilityByKey(t, got, "http3")
	if http3.Detail != "http3 detail" {
		t.Fatalf("HTTP/3 capability detail = %q, want unchanged", http3.Detail)
	}
	if strings.Contains(statuses[0].Detail, "listener tag") {
		t.Fatalf("original HTTP/2 capability detail mutated: %q", statuses[0].Detail)
	}
}

func TestEnrichTLSCapabilitiesWithHTTP3RouteConflictsReportsHostConflicts(t *testing.T) {
	networkDefaults := snapshot.DefaultNetworkDefaults()
	networkDefaults.HTTP3Enabled = true
	networkDefaults.HTTP3Bind = ":8443"
	networkDefaults.DefaultALPN = "h2,h3,http/1.1"
	tlsDefaults := snapshot.DefaultTLSDefaults()
	tlsDefaults.DefaultALPN = "h2,h3,http/1.1"

	left := runtimeHTTP3RouteConflictTestRuntime(1, "127.0.0.1:9443", "same.example.test, *.conflict.example.test", networkDefaults, tlsDefaults)
	right := runtimeHTTP3RouteConflictTestRuntime(2, "127.0.0.1:9444", "same.example.test, *.conflict.example.test", networkDefaults, tlsDefaults)
	sn := &snapshot.Snapshot{
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(left.Bind, "same.example.test"):  left,
			snapshot.SiteMapKey(right.Bind, "same.example.test"): right,
		},
		NetworkDefaults: networkDefaults,
		TLSDefaults:     tlsDefaults,
	}

	statuses := []TLSCapabilityStatus{
		{Key: "http2", Detail: "http2 detail"},
		{Key: "http3", Detail: "http3 detail"},
	}
	got := enrichTLSCapabilitiesWithHTTP3RouteConflicts(statuses, sn)
	http3 := capabilityByKey(t, got, "http3")
	if !strings.Contains(http3.Detail, "跨 TCP bind Host 冲突") ||
		!strings.Contains(http3.Detail, "udp_bind=:8443") ||
		!strings.Contains(http3.Detail, "exact=same.example.test") ||
		!strings.Contains(http3.Detail, "wildcard=*.conflict.example.test") {
		t.Fatalf("HTTP/3 capability detail = %q, want route conflict summary", http3.Detail)
	}
	if strings.Contains(got[0].Detail, "跨 TCP bind") {
		t.Fatalf("HTTP/2 capability detail = %q, want unchanged non-HTTP3 capability", got[0].Detail)
	}
	if strings.Contains(statuses[1].Detail, "跨 TCP bind") {
		t.Fatalf("original HTTP/3 capability detail mutated: %q", statuses[1].Detail)
	}
}

func TestEnrichTLSCapabilitiesWithHTTP3RouteConflictsIgnoresNonHTTP3Sites(t *testing.T) {
	networkDefaults := snapshot.DefaultNetworkDefaults()
	networkDefaults.HTTP3Enabled = true
	networkDefaults.HTTP3Bind = ":8443"
	networkDefaults.DefaultALPN = "http/1.1"
	tlsDefaults := snapshot.DefaultTLSDefaults()
	tlsDefaults.DefaultALPN = "http/1.1"

	left := runtimeHTTP3RouteConflictTestRuntime(1, "127.0.0.1:9443", "same.example.test", networkDefaults, tlsDefaults)
	right := runtimeHTTP3RouteConflictTestRuntime(2, "127.0.0.1:9444", "same.example.test", networkDefaults, tlsDefaults)
	sn := &snapshot.Snapshot{
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(left.Bind, "same.example.test"):  left,
			snapshot.SiteMapKey(right.Bind, "same.example.test"): right,
		},
		NetworkDefaults: networkDefaults,
		TLSDefaults:     tlsDefaults,
	}

	statuses := []TLSCapabilityStatus{{Key: "http3", Detail: "http3 detail"}}
	got := enrichTLSCapabilitiesWithHTTP3RouteConflicts(statuses, sn)
	http3 := capabilityByKey(t, got, "http3")
	if http3.Detail != "http3 detail" {
		t.Fatalf("HTTP/3 capability detail = %q, want unchanged detail for non-h3 sites", http3.Detail)
	}
}

func runtimeHTTP3RouteConflictTestRuntime(id uint, bind string, host string, networkDefaults snapshot.NetworkDefaults, tlsDefaults snapshot.TLSDefaults) snapshot.SiteRuntime {
	return snapshot.SiteRuntime{
		Site: store.Site{
			ID:         id,
			Host:       host,
			Bind:       bind,
			TLSEnabled: true,
		},
		Bind:            bind,
		NetworkDefaults: networkDefaults,
		TLSDefaults:     tlsDefaults,
	}
}

func TestBuildTLSCapabilityStatusesReportsDisabledHTTPProtocolALPNPreconditions(t *testing.T) {
	networkDefaults := snapshot.NetworkDefaults{
		HTTP2Enabled:   false,
		HTTP3Enabled:   false,
		HTTP3Bind:      ":8443",
		DefaultALPN:    "h2,h3,http/1.1",
		DefaultNetwork: "tcp",
	}

	statuses := buildTLSCapabilityStatuses(
		networkDefaults,
		snapshot.DefaultTLSDefaults(),
		TLSCapabilityStatus{Key: "caa"},
		TLSCapabilityStatus{Key: "ocsp_stapling"},
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	)

	http2 := capabilityByKey(t, statuses, "http2")
	if http2.Status != "disabled" || !strings.Contains(http2.Detail, "不会注册 h2") {
		t.Fatalf("HTTP/2 capability = %+v, want disabled with h2 registration detail", http2)
	}
	http3 := capabilityByKey(t, statuses, "http3")
	if http3.Status != "disabled" || !strings.Contains(http3.Detail, "不会启动 HTTP/3 UDP/QUIC 监听") {
		t.Fatalf("HTTP/3 capability = %+v, want disabled with UDP listener detail", http3)
	}
}

func TestBuildTLSCapabilityStatusesReportsFilteredInheritedALPN(t *testing.T) {
	networkDefaults := snapshot.NetworkDefaults{
		HTTP2Enabled:   false,
		HTTP3Enabled:   false,
		DefaultALPN:    "h2,h3,http/1.1",
		DefaultNetwork: "tcp",
	}

	statuses := buildTLSCapabilityStatuses(
		networkDefaults,
		snapshot.DefaultTLSDefaults(),
		TLSCapabilityStatus{Key: "caa"},
		TLSCapabilityStatus{Key: "ocsp_stapling"},
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	)

	alpn := capabilityByKey(t, statuses, "alpn")
	if !strings.Contains(alpn.Detail, "http/1.1") || strings.Contains(alpn.Detail, "h2,h3") {
		t.Fatalf("ALPN capability detail = %q, want filtered inherited ALPN", alpn.Detail)
	}
}

func TestRuntimeTLSDefaultVersionRangeNormalizesRuntimeOnlyValues(t *testing.T) {
	tests := []struct {
		name    string
		min     string
		max     string
		wantMin string
		wantMax string
	}{
		{name: "runtime range", min: "TLS 1.1", max: "0x0303", wantMin: "TLS11", wantMax: "TLS12"},
		{name: "non runtime max", min: "TLS10", max: "SSL3", wantMin: "TLS10", wantMax: "TLS13"},
		{name: "descending range", min: "TLS13", max: "TLS12", wantMin: "TLS10", wantMax: "TLS13"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaults := snapshot.DefaultTLSDefaults()
			defaults.MinVersion = tt.min
			defaults.MaxVersion = tt.max

			gotMin, gotMax := runtimeTLSDefaultVersionRange(defaults)
			if gotMin != tt.wantMin || gotMax != tt.wantMax {
				t.Fatalf("runtimeTLSDefaultVersionRange() = %q,%q; want %q,%q", gotMin, gotMax, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestBuildTLSCapabilityStatusesIgnoresNonRuntimeTLSMaxVersion(t *testing.T) {
	defaults := snapshot.DefaultTLSDefaults()
	defaults.MinVersion = "TLS10"
	defaults.MaxVersion = "SSL3"

	statuses := buildTLSCapabilityStatuses(
		snapshot.DefaultNetworkDefaults(),
		defaults,
		TLSCapabilityStatus{Key: "caa"},
		TLSCapabilityStatus{Key: "ocsp_stapling"},
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	)

	byKey := make(map[string]TLSCapabilityStatus, len(statuses))
	for _, status := range statuses {
		byKey[status.Key] = status
	}

	for _, key := range []string{"tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3"} {
		status := byKey[key]
		if status.Status != "supported" || status.Missing {
			t.Fatalf("capability %q = %+v, want supported and not missing", key, status)
		}
	}
	ssl3 := byKey["ssl_3"]
	if ssl3.Status != "not_supported" || !ssl3.Missing {
		t.Fatalf("ssl_3 capability = %+v, want not_supported and missing", ssl3)
	}
}

func TestBuildTLSCapabilityStatusesFallsBackForDescendingTLSDefaultRange(t *testing.T) {
	defaults := snapshot.DefaultTLSDefaults()
	defaults.MinVersion = "TLS13"
	defaults.MaxVersion = "TLS12"

	statuses := buildTLSCapabilityStatuses(
		snapshot.DefaultNetworkDefaults(),
		defaults,
		TLSCapabilityStatus{Key: "caa"},
		TLSCapabilityStatus{Key: "ocsp_stapling"},
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	)

	byKey := make(map[string]TLSCapabilityStatus, len(statuses))
	for _, status := range statuses {
		byKey[status.Key] = status
	}

	for _, key := range []string{"tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3"} {
		status := byKey[key]
		if status.Status != "supported" || status.Missing {
			t.Fatalf("capability %q = %+v, want supported and not missing", key, status)
		}
	}
}

func capabilityByKey(t *testing.T, statuses []TLSCapabilityStatus, key string) TLSCapabilityStatus {
	t.Helper()
	for _, status := range statuses {
		if status.Key == key {
			return status
		}
	}
	t.Fatalf("missing capability %q", key)
	return TLSCapabilityStatus{}
}
