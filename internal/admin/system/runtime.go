package system

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core"
	"My-OpenWaf/internal/proxy"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/tlsmeta"
)

type RuntimeConfigResponse struct {
	DBDriver                       string                `json:"db_driver"`
	DBDSN                          string                `json:"db_dsn"`
	LogDBDSN                       string                `json:"log_db_dsn"`
	DataDir                        string                `json:"data_dir"`
	RedisAddr                      string                `json:"redis_addr"`
	RedisEnabled                   bool                  `json:"redis_enabled"`
	RedisDB                        int                   `json:"redis_db"`
	AdminBind                      string                `json:"admin_bind"`
	AdminStaticDir                 string                `json:"admin_static_dir"`
	GeoIPDBPath                    string                `json:"geoip_db_path"`
	CVEEnabled                     bool                  `json:"cve_enabled"`
	CVEFeedEnabled                 bool                  `json:"cve_feed_enabled"`
	CVEFeedInterval                string                `json:"cve_feed_interval"`
	DropEnabled                    bool                  `json:"drop_enabled"`
	HSTSEnabled                    bool                  `json:"hsts_enabled"`
	XSSProtectionEnabled           bool                  `json:"xss_protection_enabled"`
	ExpectCTEnabled                bool                  `json:"expect_ct_enabled"`
	ExpectCTValue                  string                `json:"expect_ct_value"`
	HPKPEnabled                    bool                  `json:"hpkp_enabled"`
	HPKPValue                      string                `json:"hpkp_value"`
	HPKPReportOnlyEnabled          bool                  `json:"hpkp_report_only_enabled"`
	HPKPReportOnlyValue            string                `json:"hpkp_report_only_value"`
	BrotliEnabled                  bool                  `json:"brotli_enabled"`
	ResponseCompressionEnabled     bool                  `json:"response_compression_enabled"`
	ResponseCompressionGzipEnabled bool                  `json:"response_compression_gzip_enabled"`
	ResponseCompressionMinBytes    int                   `json:"response_compression_min_bytes"`
	Source                         string                `json:"source"`
	Editable                       bool                  `json:"editable"`
	RestartRequired                bool                  `json:"restart_required"`
	UpstreamTransportPools         RuntimeTransportPools `json:"upstream_transport_pools"`
	TLSCapabilities                []TLSCapabilityStatus `json:"tls_capabilities"`
}

type RuntimeTransportPools struct {
	HTTPTransports           int `json:"http_transports"`
	HTTP2CleartextTransports int `json:"http2_cleartext_transports"`
	HTTP3Transports          int `json:"http3_transports"`
	TotalTransports          int `json:"total_transports"`
	HTTPClients              int `json:"http_clients"`
	HTTPNoTimeoutClients     int `json:"http_no_timeout_clients"`
	HTTP3Clients             int `json:"http3_clients"`
	HTTP3NoTimeoutClients    int `json:"http3_no_timeout_clients"`
	TotalClients             int `json:"total_clients"`
}

type TLSCapabilityStatus struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Status  string `json:"status"`
	Detail  string `json:"detail"`
	Missing bool   `json:"missing"`
}

type RuntimeStateProvider func() (core.Config, bool)

func GetRuntimeConfig(load RuntimeStateProvider, holder *snapshot.Holder, settingsRepo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cfg := core.Config{}
		redisEnabled := false
		if load != nil {
			cfg, redisEnabled = load()
		}
		hstsEnabled := false
		xssProtectionEnabled := false
		expectCTEnabled := false
		expectCTValue := snapshot.DefaultExpectCTValue
		hpkpEnabled := false
		hpkpValue := snapshot.DefaultHPKPValue
		hpkpReportOnlyEnabled := false
		hpkpReportOnlyValue := snapshot.DefaultHPKPReportOnlyValue
		responseCompressionEnabled := snapshot.DefaultResponseCompressionEnabled
		responseCompressionGzipEnabled := snapshot.DefaultResponseCompressionGzipEnabled
		responseCompressionMinBytes := snapshot.DefaultResponseCompressionMinBytes
		brotliEnabled := false
		acmeCfg := defaultACMEConfig()
		if settingsRepo != nil {
			acmeCfg = loadACMEConfig(settingsRepo)
		}
		caaStatus := runtimeCAAStatus(acmeCfg)
		ocspStaplingStatus := runtimeOCSPStaplingStatus(nil)
		networkDefaults := snapshot.DefaultNetworkDefaults()
		tlsDefaults := snapshot.DefaultTLSDefaults()
		http2Config := snapshot.DefaultHTTP2Config()
		var runtimeSnapshot *snapshot.Snapshot
		if holder != nil {
			if sn := holder.Load(); sn != nil {
				runtimeSnapshot = sn
				networkDefaults = sn.NetworkDefaults
				tlsDefaults = sn.TLSDefaults
				http2Config = snapshot.NormalizeHTTP2Config(sn.HTTP2Config)
				hstsEnabled = sn.HSTSEnabled
				xssProtectionEnabled = sn.XSSProtectionEnabled
				expectCTEnabled = sn.ExpectCTEnabled
				if strings.TrimSpace(sn.ExpectCTValue) != "" {
					expectCTValue = sn.ExpectCTValue
				}
				hpkpEnabled = sn.HPKPEnabled
				if strings.TrimSpace(sn.HPKPValue) != "" {
					hpkpValue = sn.HPKPValue
				}
				hpkpReportOnlyEnabled = sn.HPKPReportOnlyEnabled
				if strings.TrimSpace(sn.HPKPReportOnlyValue) != "" {
					hpkpReportOnlyValue = sn.HPKPReportOnlyValue
				}
				brotliEnabled = sn.BrotliEnabled
				ocspStaplingStatus = runtimeOCSPStaplingStatus(sn)
				if sn.ResponseCompressionMinBytes > 0 {
					responseCompressionEnabled = sn.ResponseCompressionEnabled
					responseCompressionGzipEnabled = sn.ResponseCompressionGzipEnabled
					responseCompressionMinBytes = sn.ResponseCompressionMinBytes
				}
			}
		}
		dropEnabled := loadRuntimeDropEnabled(settingsRepo, cfg.Drop.Enabled)
		tlsCapabilities := buildTLSCapabilityStatuses(networkDefaults, tlsDefaults, caaStatus, ocspStaplingStatus, hstsEnabled, xssProtectionEnabled, expectCTEnabled, hpkpEnabled, hpkpReportOnlyEnabled, responseCompressionEnabled, responseCompressionGzipEnabled, brotliEnabled)
		tlsCapabilities = enrichTLSCapabilitiesWithHTTP2Config(tlsCapabilities, http2Config)
		tlsCapabilities = enrichTLSCapabilitiesWithHTTP3RouteConflicts(tlsCapabilities, runtimeSnapshot)
		upstreamTransportPools := runtimeTransportPools(proxy.UpstreamTransportPoolStatsSnapshot())
		c.JSON(200, RuntimeConfigResponse{
			DBDriver:                       cfg.DBDriver,
			DBDSN:                          maskDSN(cfg.DBDSN),
			LogDBDSN:                       maskDSN(cfg.LogDBDSN),
			DataDir:                        cfg.DataDir,
			RedisAddr:                      cfg.RedisAddr,
			RedisEnabled:                   redisEnabled,
			RedisDB:                        cfg.RedisDB,
			AdminBind:                      cfg.AdminBind,
			AdminStaticDir:                 cfg.AdminStaticDir,
			GeoIPDBPath:                    cfg.Bot.GeoIPDBPath,
			CVEEnabled:                     cfg.CVE.Enabled,
			CVEFeedEnabled:                 cfg.CVE.FeedEnabled,
			CVEFeedInterval:                cfg.CVE.FeedInterval,
			DropEnabled:                    dropEnabled,
			HSTSEnabled:                    hstsEnabled,
			XSSProtectionEnabled:           xssProtectionEnabled,
			ExpectCTEnabled:                expectCTEnabled,
			ExpectCTValue:                  expectCTValue,
			HPKPEnabled:                    hpkpEnabled,
			HPKPValue:                      hpkpValue,
			HPKPReportOnlyEnabled:          hpkpReportOnlyEnabled,
			HPKPReportOnlyValue:            hpkpReportOnlyValue,
			BrotliEnabled:                  brotliEnabled,
			ResponseCompressionEnabled:     responseCompressionEnabled,
			ResponseCompressionGzipEnabled: responseCompressionGzipEnabled,
			ResponseCompressionMinBytes:    responseCompressionMinBytes,
			Source:                         "runtime",
			Editable:                       false,
			RestartRequired:                false,
			UpstreamTransportPools:         upstreamTransportPools,
			TLSCapabilities:                tlsCapabilities,
		})
	}
}

func runtimeTransportPools(stats proxy.UpstreamTransportPoolStats) RuntimeTransportPools {
	return RuntimeTransportPools{
		HTTPTransports:           stats.HTTPTransports,
		HTTP2CleartextTransports: stats.HTTP2CleartextTransports,
		HTTP3Transports:          stats.HTTP3Transports,
		TotalTransports:          stats.HTTPTransports + stats.HTTP2CleartextTransports + stats.HTTP3Transports,
		HTTPClients:              stats.HTTPClients,
		HTTPNoTimeoutClients:     stats.HTTPNoTimeoutClients,
		HTTP3Clients:             stats.HTTP3Clients,
		HTTP3NoTimeoutClients:    stats.HTTP3NoTimeoutClients,
		TotalClients:             stats.HTTPClients + stats.HTTPNoTimeoutClients + stats.HTTP3Clients + stats.HTTP3NoTimeoutClients,
	}
}

func buildTLSCapabilityStatuses(networkDefaults snapshot.NetworkDefaults, tlsDefaults snapshot.TLSDefaults, caaStatus, ocspStaplingStatus TLSCapabilityStatus, hstsEnabled, xssProtectionEnabled, expectCTEnabled, hpkpEnabled, hpkpReportOnlyEnabled, responseCompressionEnabled, responseCompressionGzipEnabled, brotliEnabled bool) []TLSCapabilityStatus {
	return []TLSCapabilityStatus{
		{Key: "http2", Label: "HTTP/2", Status: boolStatus(networkDefaults.HTTP2Enabled), Detail: runtimeHTTP2Detail(networkDefaults, tlsDefaults)},
		{Key: "http3", Label: "HTTP/3", Status: boolStatus(networkDefaults.HTTP3Enabled), Detail: runtimeHTTP3Detail(networkDefaults, tlsDefaults)},
		tlsVersionCapability("tls_1_3", "TLS 1.3", tlsDefaults, "TLS13"),
		tlsVersionCapability("tls_1_2", "TLS 1.2", tlsDefaults, "TLS12"),
		tlsVersionCapability("tls_1_1", "TLS 1.1", tlsDefaults, "TLS11"),
		tlsVersionCapability("tls_1_0", "TLS 1.0", tlsDefaults, "TLS10"),
		runtimeTLSCipherSuitesCapability(tlsDefaults),
		runtimeCurvePreferencesCapability(tlsDefaults),
		{Key: "ssl_1", Label: "SSL 1", Status: "not_supported", Detail: "当前 Go/Hertz 数据面不支持 SSL 1 成功握手；仅保留历史协议状态展示，不进入运行态 TLS 配置。", Missing: true},
		{Key: "ssl_2", Label: "SSL 2", Status: "not_supported", Detail: "当前 Go/Hertz 数据面不支持 SSL 2 成功握手；仅保留历史协议状态展示，不进入运行态 TLS 配置。", Missing: true},
		{Key: "ssl_3", Label: "SSL 3", Status: "not_supported", Detail: "当前 Go/Hertz 数据面不支持 SSL 3 成功握手；仅保留历史协议状态展示，不进入运行态 TLS 配置。", Missing: true},
		{Key: "alpn", Label: "ALPN", Status: "supported", Detail: "当前快照继承站点默认 ALPN 为 " + runtimeALPNDetail(networkDefaults, tlsDefaults) + "；站点级 ALPN 可继续覆盖。"},
		{Key: "npn", Label: "NPN", Status: "not_supported", Detail: "当前运行态没有 NPN 配置路径；ALPN 不能等同为 NPN。", Missing: true},
		{Key: "session_ticket", Label: "Session Ticket", Status: boolStatus(tlsDefaults.SessionTicketsEnabled), Detail: boolDetail(tlsDefaults.SessionTicketsEnabled, "当前快照启用 TLS Session Ticket；session_tickets_enabled 已映射到 tls.Config.SessionTicketsDisabled。", "当前快照关闭 TLS Session Ticket；session_tickets_enabled 已映射到 tls.Config.SessionTicketsDisabled。")},
		{Key: "session_id_caching", Label: "SessionID caching", Status: "not_supported", Detail: "当前没有服务端 SessionID cache 配置或状态输出。", Missing: true},
		{Key: "starttls", Label: "STARTTLS", Status: "not_supported", Detail: "当前数据面只提供 HTTP/HTTPS/HTTP2/HTTP3 监听，没有 STARTTLS 升级链路。", Missing: true},
		ocspStaplingStatus,
		caaStatus,
		{Key: "hsts", Label: "HSTS", Status: boolStatus(hstsEnabled), Detail: boolDetail(hstsEnabled, "当前快照会向安全响应写入 Strict-Transport-Security。", "当前快照未启用 Strict-Transport-Security。")},
		{Key: "expect_ct", Label: "Expect-CT", Status: boolStatus(expectCTEnabled), Detail: boolDetail(expectCTEnabled, "当前快照会写入 Expect-CT 响应头。", "当前快照未启用 Expect-CT。")},
		{Key: "hpkp", Label: "HPKP", Status: boolStatus(hpkpEnabled), Detail: boolDetail(hpkpEnabled, "当前快照会写入 Public-Key-Pins。", "当前快照未启用 Public-Key-Pins。")},
		{Key: "hpkp_report_only", Label: "HPKP Report-Only", Status: boolStatus(hpkpReportOnlyEnabled), Detail: boolDetail(hpkpReportOnlyEnabled, "当前快照会写入 Public-Key-Pins-Report-Only。", "当前快照未启用 Public-Key-Pins-Report-Only。")},
		{Key: "xss_protection", Label: "XSS 保护头", Status: boolStatus(xssProtectionEnabled), Detail: boolDetail(xssProtectionEnabled, "当前快照会写入 X-XSS-Protection。", "当前快照未启用 X-XSS-Protection。")},
		{Key: "response_compression", Label: "响应压缩", Status: boolStatus(responseCompressionEnabled), Detail: boolDetail(responseCompressionEnabled, "当前快照允许对客户端响应进行压缩协商。", "当前快照关闭响应压缩总开关。")},
		{Key: "gzip_compression", Label: "Gzip 压缩", Status: boolStatus(responseCompressionEnabled && responseCompressionGzipEnabled), Detail: boolDetail(responseCompressionEnabled && responseCompressionGzipEnabled, "当前快照允许输出 gzip 响应。", "当前快照不会输出 gzip 响应。")},
		{Key: "brotli_compression", Label: "Brotli 压缩", Status: boolStatus(responseCompressionEnabled && brotliEnabled), Detail: boolDetail(responseCompressionEnabled && brotliEnabled, "当前快照允许输出 Brotli 响应。", "当前快照不会输出 Brotli 响应。")},
	}
}

func enrichTLSCapabilitiesWithHTTP2Config(statuses []TLSCapabilityStatus, cfg snapshot.HTTP2Config) []TLSCapabilityStatus {
	detail := runtimeHTTP2ConfigDetail(cfg)
	if detail == "" {
		return statuses
	}
	out := make([]TLSCapabilityStatus, len(statuses))
	copy(out, statuses)
	for i := range out {
		if out[i].Key != "http2" {
			continue
		}
		out[i].Detail = joinRuntimeDetail(out[i].Detail, detail)
	}
	return out
}

func runtimeHTTP2ConfigDetail(cfg snapshot.HTTP2Config) string {
	maxHeaderListSize := cfg.MaxHeaderBytes + cfg.MaxHeaderFields*32
	parts := []string{
		"read_timeout_seconds=" + strconv.Itoa(cfg.ReadTimeoutSeconds),
		"disable_keepalive=" + strconv.FormatBool(cfg.DisableKeepalive),
		"permit_prohibited_cipher_suites=" + strconv.FormatBool(cfg.PermitProhibitedCipherSuites),
		"max_concurrent_streams=" + strconv.FormatUint(uint64(cfg.MaxConcurrentStreams), 10),
		"max_read_frame_size=" + strconv.FormatUint(uint64(cfg.MaxReadFrameSize), 10),
		"idle_timeout_seconds=" + strconv.Itoa(cfg.IdleTimeoutSeconds),
		"max_upload_buffer_per_connection=" + strconv.FormatInt(int64(cfg.MaxUploadBufferPerConnection), 10),
		"max_upload_buffer_per_stream=" + strconv.FormatInt(int64(cfg.MaxUploadBufferPerStream), 10),
		"max_header_bytes=" + strconv.Itoa(cfg.MaxHeaderBytes),
		"max_header_fields=" + strconv.Itoa(cfg.MaxHeaderFields),
		"max_handlers=" + strconv.Itoa(cfg.MaxHandlers),
		"max_queued_control_frames=" + strconv.Itoa(cfg.MaxQueuedControlFrames),
	}
	settings := []string{
		"SETTINGS_MAX_CONCURRENT_STREAMS=" + strconv.FormatUint(uint64(cfg.MaxConcurrentStreams), 10),
		"SETTINGS_MAX_FRAME_SIZE=" + strconv.FormatUint(uint64(cfg.MaxReadFrameSize), 10),
		"SETTINGS_MAX_HEADER_LIST_SIZE=" + strconv.Itoa(maxHeaderListSize),
	}
	return "hertz-contrib/http2 ServerFactory 参数为 " + strings.Join(parts, "，") +
		"；对外 SETTINGS 摘要为 " + strings.Join(settings, "，") +
		"；全部 HTTP/2 字段已进入 listener tag，变更后会重建监听器，新连接使用新 SETTINGS，已有 h2 连接不阻塞热重载。"
}

func joinRuntimeDetail(base string, extra string) string {
	base = strings.TrimSpace(base)
	extra = strings.TrimSpace(extra)
	if base == "" {
		return extra
	}
	if extra == "" {
		return base
	}
	return base + "；" + extra
}

func enrichTLSCapabilitiesWithHTTP3RouteConflicts(statuses []TLSCapabilityStatus, sn *snapshot.Snapshot) []TLSCapabilityStatus {
	summary := runtimeHTTP3RouteConflictSummary(sn)
	if summary == "" {
		return statuses
	}
	out := make([]TLSCapabilityStatus, len(statuses))
	copy(out, statuses)
	for i := range out {
		if out[i].Key != "http3" {
			continue
		}
		out[i].Detail = strings.TrimSpace(out[i].Detail) + " HTTP/3 route table 存在跨 TCP bind Host 冲突，冲突 Host 不会进入 HTTP/3 路由表；" + summary + "。"
		return out
	}
	return out
}

type runtimeHTTP3RouteConflictSet struct {
	UDPBind       string
	ExactHosts    []string
	WildcardHosts []string
}

func runtimeHTTP3RouteConflictSummary(sn *snapshot.Snapshot) string {
	conflicts := runtimeHTTP3RouteConflicts(sn)
	if len(conflicts) == 0 {
		return ""
	}
	parts := make([]string, 0, len(conflicts))
	for _, conflict := range conflicts {
		segments := []string{"udp_bind=" + conflict.UDPBind}
		if len(conflict.ExactHosts) > 0 {
			segments = append(segments, "exact="+strings.Join(conflict.ExactHosts, ","))
		}
		if len(conflict.WildcardHosts) > 0 {
			segments = append(segments, "wildcard="+strings.Join(conflict.WildcardHosts, ","))
		}
		parts = append(parts, strings.Join(segments, " "))
	}
	return strings.Join(parts, "；")
}

func runtimeHTTP3RouteConflicts(sn *snapshot.Snapshot) []runtimeHTTP3RouteConflictSet {
	if sn == nil || len(sn.Sites) == 0 {
		return nil
	}
	grouped := make(map[string][]snapshot.SiteRuntime)
	for _, rt := range runtimeUniqueHTTP3SiteRuntimes(sn) {
		if !runtimeEffectiveHTTP3Enabled(rt) {
			continue
		}
		udpBind := runtimeHTTP3BindForSite(rt)
		if udpBind == "" {
			udpBind = strings.TrimSpace(rt.Bind)
		}
		if udpBind == "" {
			continue
		}
		grouped[udpBind] = append(grouped[udpBind], rt)
	}
	if len(grouped) == 0 {
		return nil
	}

	udpBinds := make([]string, 0, len(grouped))
	for bind := range grouped {
		udpBinds = append(udpBinds, bind)
	}
	sort.Strings(udpBinds)

	out := make([]runtimeHTTP3RouteConflictSet, 0, len(udpBinds))
	for _, udpBind := range udpBinds {
		exact, wildcard := runtimeHTTP3RouteHostConflicts(grouped[udpBind])
		if len(exact) == 0 && len(wildcard) == 0 {
			continue
		}
		out = append(out, runtimeHTTP3RouteConflictSet{
			UDPBind:       udpBind,
			ExactHosts:    exact,
			WildcardHosts: wildcard,
		})
	}
	return out
}

type runtimeHTTP3SiteKey struct {
	siteID uint
	bind   string
}

func runtimeUniqueHTTP3SiteRuntimes(sn *snapshot.Snapshot) []snapshot.SiteRuntime {
	seen := make(map[runtimeHTTP3SiteKey]struct{}, len(sn.Sites))
	items := make([]snapshot.SiteRuntime, 0, len(sn.Sites))
	for _, rt := range sn.Sites {
		key := runtimeHTTP3SiteKey{siteID: rt.Site.ID, bind: rt.Bind}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		items = append(items, rt)
	}
	return items
}

func runtimeEffectiveHTTP3Enabled(siteRT snapshot.SiteRuntime) bool {
	if !siteRT.Site.TLSEnabled {
		return false
	}
	defaults := siteRT.NetworkDefaults
	if defaults == (snapshot.NetworkDefaults{}) {
		defaults = snapshot.DefaultNetworkDefaults()
	}
	if !defaults.HTTP3Enabled {
		return false
	}
	_, effectiveALPN := snapshot.EffectiveSiteNetwork(siteRT.Site.ALPN, siteRT.Site.Network, defaults, siteRT.TLSDefaults)
	if strings.TrimSpace(effectiveALPN) == "" {
		effectiveALPN = defaults.DefaultALPN
		if strings.TrimSpace(effectiveALPN) == "" {
			effectiveALPN = snapshot.DefaultTLSDefaults().DefaultALPN
		}
	}
	return alpnDetailIncludes(effectiveALPN, "h3")
}

func runtimeHTTP3BindForSite(rt snapshot.SiteRuntime) string {
	if bind := strings.TrimSpace(rt.NetworkDefaults.HTTP3Bind); bind != "" {
		return bind
	}
	return strings.TrimSpace(rt.Bind)
}

func runtimeHTTP3RouteHostConflicts(runtimes []snapshot.SiteRuntime) ([]string, []string) {
	exact := make(map[string]string)
	wildcard := make(map[string]string)
	exactConflicts := make(map[string]struct{})
	wildcardConflicts := make(map[string]struct{})

	for _, rt := range runtimes {
		for _, rawHost := range splitRuntimeHosts(rt.Site.Host) {
			host := snapshot.NormalizeMatchHost(rawHost)
			if host == "" {
				continue
			}
			if strings.HasPrefix(host, "*.") {
				collectRuntimeHTTP3RouteConflict(wildcard, wildcardConflicts, host, rt.Bind)
				continue
			}
			collectRuntimeHTTP3RouteConflict(exact, exactConflicts, host, rt.Bind)
		}
	}
	return sortedRuntimeHTTP3ConflictHosts(exactConflicts), sortedRuntimeHTTP3ConflictHosts(wildcardConflicts)
}

func collectRuntimeHTTP3RouteConflict(bindByHost map[string]string, conflicts map[string]struct{}, host string, bind string) {
	if existingBind, exists := bindByHost[host]; exists && existingBind != bind {
		conflicts[host] = struct{}{}
		delete(bindByHost, host)
		return
	}
	if _, conflicted := conflicts[host]; !conflicted {
		bindByHost[host] = bind
	}
}

func splitRuntimeHosts(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func sortedRuntimeHTTP3ConflictHosts(hosts map[string]struct{}) []string {
	if len(hosts) == 0 {
		return nil
	}
	out := make([]string, 0, len(hosts))
	for host := range hosts {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func runtimeCAAStatus(acmeCfg ACMEConfig) TLSCapabilityStatus {
	enabled := acmeCfg.Enabled && acmeCfg.CAACheckEnabled
	if enabled {
		allowedIssuers := strings.TrimSpace(acmeCfg.CAAAllowedIssuers)
		if allowedIssuers == "" {
			allowedIssuers = defaultACMEConfig().CAAAllowedIssuers
		}
		dnsServer := strings.TrimSpace(acmeCfg.CAADNSServer)
		if dnsServer == "" {
			dnsServer = "-"
		}
		return TLSCapabilityStatus{
			Key:    "caa",
			Label:  "CAA",
			Status: "enabled",
			Detail: "当前 ACME 配置启用签发前 DNS CAA 预检；允许颁发者为 " + allowedIssuers + "；DNS 服务器为 " + dnsServer + "。",
		}
	}
	if !acmeCfg.Enabled {
		return TLSCapabilityStatus{
			Key:    "caa",
			Label:  "CAA",
			Status: "disabled",
			Detail: "当前 ACME 配置未启用，因此不会执行 DNS CAA 预检。",
		}
	}
	return TLSCapabilityStatus{
		Key:    "caa",
		Label:  "CAA",
		Status: "disabled",
		Detail: "当前 ACME 配置已启用，但未开启 DNS CAA 预检。",
	}
}

func runtimeOCSPStaplingStatus(sn *snapshot.Snapshot) TLSCapabilityStatus {
	enabled := snapshotHasOCSPStaple(sn)
	return TLSCapabilityStatus{
		Key:    "ocsp_stapling",
		Label:  "OCSP Stapling",
		Status: boolStatus(enabled),
		Detail: boolDetail(enabled, "当前快照中存在带 OCSPStaple 的运行态证书。", "当前快照没有带 OCSPStaple 的运行态证书；证书记录仍支持 ocsp_staple_pem。"),
	}
}

func snapshotHasOCSPStaple(sn *snapshot.Snapshot) bool {
	if sn == nil {
		return false
	}
	for _, cert := range sn.SiteTLSCertBySNI {
		if len(cert.OCSPStaple) > 0 {
			return true
		}
	}
	for _, rt := range sn.Sites {
		if rt.TLSConfig == nil {
			continue
		}
		for _, cert := range rt.TLSConfig.Certificates {
			if len(cert.OCSPStaple) > 0 {
				return true
			}
		}
	}
	return false
}

func runtimeALPNDetail(networkDefaults snapshot.NetworkDefaults, tlsDefaults snapshot.TLSDefaults) string {
	_, alpn := snapshot.EffectiveSiteNetwork("", "", networkDefaults, tlsDefaults)
	trimmed := strings.TrimSpace(alpn)
	if trimmed == "" {
		return "http/1.1"
	}
	return trimmed
}

func runtimeHTTP2Detail(networkDefaults snapshot.NetworkDefaults, tlsDefaults snapshot.TLSDefaults) string {
	effectiveALPN := runtimeALPNDetail(networkDefaults, tlsDefaults)
	if !networkDefaults.HTTP2Enabled {
		return "当前快照关闭 HTTP/2；继承站点默认 ALPN 为 " + effectiveALPN + "，TLS 监听不会注册 h2。"
	}
	_, maxTLSVersion := runtimeTLSDefaultVersionRange(tlsDefaults)
	if parsedMaxVersion := snapshot.ParseTLSVersion(maxTLSVersion); parsedMaxVersion != 0 && parsedMaxVersion < tls.VersionTLS12 {
		return "当前快照允许 HTTP/2，但继承 TLS 默认最高版本为 " + maxTLSVersion + "；TLS 监听会移除 h2，因为 HTTP/2 over TLS 需要 TLS12 及以上。只有站点级 TLS 版本覆盖到 TLS12 及以上且 ALPN 包含 h2 时可协商 HTTP/2。"
	}
	if alpnDetailIncludes(effectiveALPN, "h2") {
		return "当前快照允许 HTTP/2，且继承站点默认 ALPN 包含 h2；TLS 监听可协商 h2。"
	}
	return "当前快照允许 HTTP/2，但继承站点默认 ALPN 为 " + effectiveALPN + "，未包含 h2；仅显式站点 ALPN 包含 h2 的 TLS 监听可协商 HTTP/2。"
}

func runtimeHTTP3Detail(networkDefaults snapshot.NetworkDefaults, tlsDefaults snapshot.TLSDefaults) string {
	effectiveALPN := runtimeALPNDetail(networkDefaults, tlsDefaults)
	if !networkDefaults.HTTP3Enabled {
		return "当前快照关闭 HTTP/3；继承站点默认 ALPN 为 " + effectiveALPN + "，不会启动 HTTP/3 UDP/QUIC 监听。"
	}
	bind := runtimeHTTP3BindDetail(networkDefaults.HTTP3Bind)
	quicDetail := "HTTP/3 UDP/QUIC 监听固定使用 TLS1.3 与 h3 ALPN，不随继承 TLS 版本范围降级。"
	if alpnDetailIncludes(effectiveALPN, "h3") {
		return "当前快照允许 HTTP/3，且继承站点默认 ALPN 包含 h3；默认 UDP/QUIC 监听为 " + bind + "；" + quicDetail
	}
	return "当前快照允许 HTTP/3，但继承站点默认 ALPN 为 " + effectiveALPN + "，未包含 h3；仅显式站点 ALPN 包含 h3 的 TLS 站点会进入 HTTP/3 UDP/QUIC 监听计划，默认监听为 " + bind + "；" + quicDetail
}

func alpnDetailIncludes(raw string, proto string) bool {
	for _, item := range strings.Split(raw, ",") {
		if strings.TrimSpace(item) == proto {
			return true
		}
	}
	return false
}

func runtimeHTTP3BindDetail(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return snapshot.DefaultNetworkDefaults().HTTP3Bind
	}
	if normalized, ok := snapshot.NormalizeHTTP3Bind(trimmed); ok {
		return normalized
	}
	return snapshot.DefaultNetworkDefaults().HTTP3Bind
}

func runtimeTLSCipherSuitesCapability(tlsDefaults snapshot.TLSDefaults) TLSCapabilityStatus {
	raw := strings.TrimSpace(tlsDefaults.CipherSuites)
	suites := tlsmeta.ParseTLSConfigCipherSuites(raw)
	status := "supported"
	detail := "当前 TLS 默认未配置自定义 cipher_suites；tls.Config.CipherSuites 为空，Go 在 TLS1.0-1.2 协商时使用默认套件；TLS1.3 套件由 Go TLS 运行态管理，不能通过 tls.Config.CipherSuites 自定义。"
	if raw != "" {
		if len(suites) > 0 {
			status = "enabled"
			detail = "当前 TLS 默认解析出 " + strconv.Itoa(len(suites)) + " 个可写入 tls.Config.CipherSuites 的 TLS1.0-1.2 套件：" + tlsmeta.FormatCipherSuites(suites) + "；TLS1.3 套件由 Go TLS 运行态管理，不能通过 tls.Config.CipherSuites 自定义。"
		} else {
			status = "disabled"
			detail = "当前 TLS 默认 cipher_suites 未解析出可写入 tls.Config.CipherSuites 的 TLS1.0-1.2 套件；TLS1.3 套件由 Go TLS 运行态管理，不能通过 tls.Config.CipherSuites 自定义。"
		}
		if invalid := tlsmeta.InvalidTLSConfigCipherSuiteToken(raw); invalid != "" {
			detail = joinRuntimeDetail(detail, "第一个未进入 tls.Config.CipherSuites 的 token 为 "+invalid+"。")
		}
	}
	detail = joinRuntimeDetail(detail, "prefer_server_cipher_suites="+strconv.FormatBool(tlsDefaults.PreferServerCipherSuites)+" 已写入 tls.Config.PreferServerCipherSuites；当前 Go 文档标记该字段为 legacy 且 ignored，实际 cipher suite 选择由 Go TLS 运行态决定。")
	return TLSCapabilityStatus{
		Key:    "cipher_suites",
		Label:  "TLS Cipher Suites",
		Status: status,
		Detail: detail,
	}
}

func runtimeCurvePreferencesCapability(tlsDefaults snapshot.TLSDefaults) TLSCapabilityStatus {
	raw := strings.TrimSpace(tlsDefaults.CurvePreferences)
	curves := snapshot.ParseCurvePreferences(raw)
	status := "enabled"
	if len(curves) == 0 {
		status = "supported"
		curves = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
		detail := "当前 TLS 默认 curve_preferences 未解析出有效曲线；运行态回退 " + strconv.Itoa(len(curves)) + " 个 tls.Config.CurvePreferences：" + runtimeCurveIDsDetail(curves) + "。"
		detail = joinRuntimeDetail(detail, "该配置同时进入 HTTPS TLS 与 HTTP/3 UDP/QUIC 的 tls.Config.CurvePreferences。")
		return TLSCapabilityStatus{
			Key:    "curve_preferences",
			Label:  "TLS 曲线优先级",
			Status: status,
			Detail: detail,
		}
	}
	detail := "当前 TLS 默认 curve_preferences 解析为 " + strconv.Itoa(len(curves)) + " 个 tls.Config.CurvePreferences：" + runtimeCurveIDsDetail(curves) + "。"
	detail = joinRuntimeDetail(detail, "该配置同时进入 HTTPS TLS 与 HTTP/3 UDP/QUIC 的 tls.Config.CurvePreferences。")
	return TLSCapabilityStatus{
		Key:    "curve_preferences",
		Label:  "TLS 曲线优先级",
		Status: status,
		Detail: detail,
	}
}

func runtimeCurveIDsDetail(curves []tls.CurveID) string {
	if len(curves) == 0 {
		return ""
	}
	parts := make([]string, 0, len(curves))
	for _, curve := range curves {
		parts = append(parts, curve.String())
	}
	return strings.Join(parts, ",")
}

func tlsVersionCapability(key string, label string, tlsDefaults snapshot.TLSDefaults, version string) TLSCapabilityStatus {
	runtimeToken := tlsmeta.NormalizeRuntimeVersionToken(version)
	if runtimeToken == "" {
		return TLSCapabilityStatus{
			Key:     key,
			Label:   label,
			Status:  "not_supported",
			Detail:  label + " 不受当前 Go TLS 运行态支持。",
			Missing: true,
		}
	}
	enabled := tlsVersionAllowedByDefaults(tlsDefaults, runtimeToken)
	status := "disabled"
	if enabled {
		status = "supported"
	}
	return TLSCapabilityStatus{
		Key:     key,
		Label:   label,
		Status:  status,
		Detail:  label + tlsVersionCapabilityDetail(enabled, tlsDefaults),
		Missing: false,
	}
}

func tlsVersionCapabilityDetail(enabled bool, tlsDefaults snapshot.TLSDefaults) string {
	minVersion, maxVersion := runtimeTLSDefaultVersionRange(tlsDefaults)
	if enabled {
		return " 在当前 TLS 默认版本范围内；当前范围为 " + minVersion + " 到 " + maxVersion + "。"
	}
	return " 不在当前 TLS 默认版本范围内；当前范围为 " + minVersion + " 到 " + maxVersion + "。"
}

func tlsVersionAllowedByDefaults(tlsDefaults snapshot.TLSDefaults, version string) bool {
	targetToken := tlsmeta.NormalizeRuntimeVersionToken(version)
	target := snapshot.ParseTLSVersion(targetToken)
	if target == 0 {
		return false
	}
	minToken, maxToken := runtimeTLSDefaultVersionRange(tlsDefaults)
	minVersion := snapshot.ParseTLSVersion(minToken)
	maxVersion := snapshot.ParseTLSVersion(maxToken)
	return target >= minVersion && target <= maxVersion
}

func runtimeTLSDefaultVersionRange(tlsDefaults snapshot.TLSDefaults) (string, string) {
	defaults := snapshot.DefaultTLSDefaults()
	minVersion := tlsmeta.NormalizeRuntimeVersionToken(tlsDefaults.MinVersion)
	if minVersion == "" {
		minVersion = tlsmeta.NormalizeRuntimeVersionToken(defaults.MinVersion)
	}
	maxVersion := tlsmeta.NormalizeRuntimeVersionToken(tlsDefaults.MaxVersion)
	if maxVersion == "" {
		maxVersion = tlsmeta.NormalizeRuntimeVersionToken(defaults.MaxVersion)
	}
	if minVersion == "" {
		minVersion = "TLS10"
	}
	if maxVersion == "" {
		maxVersion = "TLS13"
	}
	if !tlsmeta.RuntimeVersionRangeValid(minVersion, maxVersion) {
		minVersion = tlsmeta.NormalizeRuntimeVersionToken(defaults.MinVersion)
		maxVersion = tlsmeta.NormalizeRuntimeVersionToken(defaults.MaxVersion)
	}
	return minVersion, maxVersion
}

func boolStatus(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func boolDetail(enabled bool, on string, off string) string {
	if enabled {
		return on
	}
	return off
}

func maskDSN(dsn string) string {
	trimmed := strings.TrimSpace(dsn)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err == nil && u.User != nil {
		if username := u.User.Username(); username != "" {
			u.User = url.UserPassword(username, "******")
		} else {
			u.User = url.UserPassword("******", "******")
		}
		return u.String()
	}
	if strings.Contains(trimmed, "password=") || strings.Contains(trimmed, "passwd=") || strings.Contains(trimmed, "pwd=") {
		parts := strings.Fields(trimmed)
		for i, part := range parts {
			lower := strings.ToLower(part)
			for _, key := range []string{"password=", "passwd=", "pwd="} {
				if strings.HasPrefix(lower, key) {
					parts[i] = part[:len(key)] + "******"
				}
			}
		}
		return strings.Join(parts, " ")
	}
	return trimmed
}

func loadRuntimeDropEnabled(settingsRepo *repository.SystemSettingsRepo, fallback bool) bool {
	if settingsRepo == nil {
		return fallback
	}
	val, err := settingsRepo.Get("drop_policy")
	if err != nil || strings.TrimSpace(val) == "" {
		return fallback
	}
	var stored struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.Unmarshal([]byte(val), &stored); err != nil || stored.Enabled == nil {
		return fallback
	}
	return *stored.Enabled
}
