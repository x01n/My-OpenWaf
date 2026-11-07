package app

/*
本文件为「全部 TLS 端口都支持 QUIC / HTTP-3」新增的验证，不改动任何既有测试文件。

覆盖两条主线：

 1. 机制断言（进程内，直接调用真 `buildHTTP3ServerPlans` /
    `buildHTTP3AltSvcAdvertisement`）：开启 network_config.http3_per_port_enabled 后，
    两个不同 TCP 端口的 TLS 站点各自得到独立的 UDP 监听，且各自 Alt-Svc
    通告自己那个 UDP 端口；关闭（默认）时行为与既有实现逐字节一致。
 2. 端到端断言（跨进程）：真起一个 WAF 进程、两个 TLS 站点，用真 QUIC 客户端
    分别连 Alt-Svc 通告的端口并确认拿到 200，同时确认「另一个端口上拿这个
    站点的 Host 会被路由到它自己的上游」这一 h3 路由语义。

边界覆盖：TCP bind 无端口、明文站点、同端口不同 host、以及「两个 TCP 端口共用
一个全局 http3_bind」在开关开启后必须拆成两个监听。
*/

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"My-OpenWaf/internal/acme"
	adminsystem "My-OpenWaf/internal/admin/system"
	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

// h3PerPortRuntime 构造一个开启/关闭 http3_per_port_enabled 的 TLS 站点运行时。
func h3PerPortRuntime(id uint, bind string, host string, perPort bool) snapshotpkg.SiteRuntime {
	return snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         id,
			Bind:       bind,
			Host:       host,
			TLSEnabled: true,
			ALPN:       "h2,h3,http/1.1",
		},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			HTTP2Enabled:        true,
			HTTP3Enabled:        true,
			HTTP3Bind:           ":8443",
			HTTP3PerPortEnabled: perPort,
			DefaultALPN:         "h2,h3,http/1.1",
			DefaultNetwork:      "tcp",
		},
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
	}
}

// h3PerPortSnapshot 把运行时按站点主机名放进快照。
func h3PerPortSnapshot(runtimes ...snapshotpkg.SiteRuntime) *snapshotpkg.Snapshot {
	sites := make(map[string]*snapshotpkg.SiteRuntime, len(runtimes)*2)
	for i := range runtimes {
		rt := runtimes[i]
		for _, host := range strings.Split(rt.Site.Host, ",") {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			sites[snapshotpkg.SiteMapKey(rt.Bind, host)] = &rt
		}
	}
	return &snapshotpkg.Snapshot{
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites:       sites,
	}
}

func h3PlanKeys(plans map[string]http3ServerPlan) []string {
	keys := make([]string, 0, len(plans))
	for key := range plans {
		keys = append(keys, key)
	}
	return keys
}

// TestHTTP3PerPortPlansGiveEachTLSPortItsOwnUDPListener 是本任务的核心机制断言：
// 两个不同 TCP 端口的 TLS 站点在开关开启后必须各自拥有独立的 UDP 监听，
// 且 Alt-Svc 通告的端口分别等于各自的 TCP 端口。
func TestHTTP3PerPortPlansGiveEachTLSPortItsOwnUDPListener(t *testing.T) {
	rtA := h3PerPortRuntime(1, "127.0.0.1:10443", "per-port-a.example.test", true)
	rtB := h3PerPortRuntime(2, "127.0.0.1:11443", "per-port-b.example.test", true)
	sn := h3PerPortSnapshot(rtA, rtB)

	plans := buildHTTP3ServerPlans(sn)
	if len(plans) != 2 {
		t.Fatalf("per-port mode plans = %d (%v), want 2 (one UDP listener per TLS port)", len(plans), h3PlanKeys(plans))
	}
	planA, ok := plans["h3::10443"]
	if !ok {
		t.Fatalf("missing plan h3::10443, got %v", h3PlanKeys(plans))
	}
	planB, ok := plans["h3::11443"]
	if !ok {
		t.Fatalf("missing plan h3::11443, got %v", h3PlanKeys(plans))
	}
	if planA.Bind != ":10443" || planB.Bind != ":11443" {
		t.Fatalf("plan binds = %q / %q, want :10443 / :11443", planA.Bind, planB.Bind)
	}
	// 每个 UDP 监听只服务自己那个 TCP bind。
	if got, ok := planA.RouteTable.Resolve("per-port-a.example.test"); !ok || got != "127.0.0.1:10443" {
		t.Fatalf("route for a = %q,%v; want 127.0.0.1:10443,true", got, ok)
	}
	if got, ok := planB.RouteTable.Resolve("per-port-b.example.test"); !ok || got != "127.0.0.1:11443" {
		t.Fatalf("route for b = %q,%v; want 127.0.0.1:11443,true", got, ok)
	}
	if got, ok := planA.RouteTable.Resolve("per-port-b.example.test"); ok {
		t.Fatalf("plan A should not resolve B's host, got %q", got)
	}

	advA, ok := buildHTTP3AltSvcAdvertisement(rtA, sn)
	if !ok {
		t.Fatal("site A has no Alt-Svc advertisement")
	}
	advB, ok := buildHTTP3AltSvcAdvertisement(rtB, sn)
	if !ok {
		t.Fatal("site B has no Alt-Svc advertisement")
	}
	if advA.value != `h3=":10443"; ma=86400` {
		t.Fatalf("site A Alt-Svc = %q, want h3=\":10443\"", advA.value)
	}
	if advB.value != `h3=":11443"; ma=86400` {
		t.Fatalf("site B Alt-Svc = %q, want h3=\":11443\"", advB.value)
	}
	if advA.udpBind != ":10443" || advB.udpBind != ":11443" {
		t.Fatalf("advertised udp binds = %q / %q", advA.udpBind, advB.udpBind)
	}
	if got, ok := advA.valueForHost("per-port-a.example.test"); !ok || got != `h3=":10443"; ma=86400` {
		t.Fatalf("site A valueForHost(own host) = %q,%v", got, ok)
	}
	if got, ok := advA.valueForHost("per-port-b.example.test"); ok {
		t.Fatalf("site A must not advertise for B's host, got %q", got)
	}
	// 两个监听地址必须真的能同时绑上（各自独立，不抢同一个端口）。
	for _, bind := range []string{planA.Bind, planB.Bind} {
		pc, err := net.ListenPacket("udp", bind)
		if err != nil {
			t.Fatalf("per-port UDP listener %q is not bindable: %v", bind, err)
		}
		if err := pc.Close(); err != nil {
			t.Fatalf("close per-port UDP listener %q: %v", bind, err)
		}
	}
}

// TestHTTP3PerPortDisabledMatchesLegacySingleUDPListener 锁定「默认关闭 = 现状不变」：
// 同样的两个站点，开关关闭时仍然只有一个 :8443 监听，Alt-Svc 也仍通告 :8443。
func TestHTTP3PerPortDisabledMatchesLegacySingleUDPListener(t *testing.T) {
	rtA := h3PerPortRuntime(1, "127.0.0.1:10443", "legacy-a.example.test", false)
	rtB := h3PerPortRuntime(2, "127.0.0.1:11443", "legacy-b.example.test", false)
	sn := h3PerPortSnapshot(rtA, rtB)

	plans := buildHTTP3ServerPlans(sn)
	if len(plans) != 1 {
		t.Fatalf("legacy mode plans = %d (%v), want 1", len(plans), h3PlanKeys(plans))
	}
	plan, ok := plans["h3::8443"]
	if !ok {
		t.Fatalf("missing legacy plan h3::8443, got %v", h3PlanKeys(plans))
	}
	if plan.Bind != ":8443" {
		t.Fatalf("legacy plan bind = %q, want :8443", plan.Bind)
	}
	for _, rt := range []snapshotpkg.SiteRuntime{rtA, rtB} {
		adv, ok := buildHTTP3AltSvcAdvertisement(rt, sn)
		if !ok {
			t.Fatalf("site %d has no Alt-Svc advertisement in legacy mode", rt.Site.ID)
		}
		if adv.value != `h3=":8443"; ma=86400` {
			t.Fatalf("legacy Alt-Svc for site %d = %q, want h3=\":8443\"", rt.Site.ID, adv.value)
		}
	}

	// 与既有实现逐字节一致：显式 http3_bind 时，同一组运行时在两种模式下
	// 生成的计划键与 tag 必须完全相同。
	legacyTag := http3ListenerFingerprint(":8443", []snapshotpkg.SiteRuntime{rtA, rtB}, plan.RouteTable, sn)
	if plan.Tag != legacyTag {
		t.Fatalf("legacy plan tag = %q, want %q (tag must match the legacy fingerprint)", plan.Tag, legacyTag)
	}
}

// TestHTTP3PerPortFingerprintFollowsModeSwitch 锁定热重载判据：开关本身必须进哈希，
// 否则从关闭切到开启时 tag 不变，监听不会被重建。
func TestHTTP3PerPortFingerprintFollowsModeSwitch(t *testing.T) {
	legacyRT := h3PerPortRuntime(1, "127.0.0.1:10443", "fingerprint.example.test", false)
	perPortRT := h3PerPortRuntime(1, "127.0.0.1:10443", "fingerprint.example.test", true)

	legacyRuntimes := []snapshotpkg.SiteRuntime{legacyRT}
	perPortRuntimes := []snapshotpkg.SiteRuntime{perPortRT}
	legacyTag := http3ListenerFingerprint(":8443", legacyRuntimes, buildHTTP3RouteTable(legacyRuntimes), h3PerPortSnapshot(legacyRT))
	perPortTag := http3ListenerFingerprint(":10443", perPortRuntimes, buildHTTP3RouteTable(perPortRuntimes), h3PerPortSnapshot(perPortRT))
	if legacyTag == perPortTag {
		t.Fatal("switching http3_per_port_enabled must change the HTTP/3 listener fingerprint")
	}

	// 仅切换开关、bind 与监听地址都不变时也必须变（守卫哈希确实吃到了该字段）。
	legacySameBind := http3ListenerFingerprint(":10443", legacyRuntimes, buildHTTP3RouteTable(legacyRuntimes), h3PerPortSnapshot(legacyRT))
	perPortSameBind := http3ListenerFingerprint(":10443", perPortRuntimes, buildHTTP3RouteTable(perPortRuntimes), h3PerPortSnapshot(perPortRT))
	if legacySameBind == perPortSameBind {
		t.Fatal("fingerprint with identical udp bind must still differ when http3_per_port_enabled changes")
	}

	// 站点侧监听指纹同样必须跟随，否则 h3 端口换了但 TCP 监听不重建。
	base := siteListenerFingerprint("127.0.0.1:10443", h3PerPortSnapshot(legacyRT))
	changed := siteListenerFingerprint("127.0.0.1:10443", h3PerPortSnapshot(perPortRT))
	if base == changed {
		t.Fatal("switching http3_per_port_enabled must change the site listener fingerprint")
	}
}

// TestHTTP3PerPortSkipsBindWithoutPort 覆盖边界：TCP bind 没有端口时跳过该站点，
// 不能退化成无端口监听（那会让整个 UDP 绑定失败），也不能 panic。
func TestHTTP3PerPortSkipsBindWithoutPort(t *testing.T) {
	bad := h3PerPortRuntime(1, "127.0.0.1", "no-port.example.test", true)
	good := h3PerPortRuntime(2, "127.0.0.1:10443", "with-port.example.test", true)
	sn := h3PerPortSnapshot(bad, good)

	plans := buildHTTP3ServerPlans(sn)
	if len(plans) != 1 {
		t.Fatalf("plans = %d (%v), want only the site with a usable port", len(plans), h3PlanKeys(plans))
	}
	if _, ok := plans["h3::10443"]; !ok {
		t.Fatalf("missing plan h3::10443, got %v", h3PlanKeys(plans))
	}
	if _, ok := buildHTTP3AltSvcAdvertisement(bad, sn); ok {
		t.Fatal("site with port-less TCP bind must not advertise HTTP/3")
	}
	// 空 bind 同样必须返回 false，而不是回退到 rt.Bind。
	empty := h3PerPortRuntime(3, "", "empty-bind.example.test", true)
	if bind, ok := snapshotpkg.HTTP3BindFromTCPBind(empty.Bind); ok || bind != "" {
		t.Fatalf("HTTP3BindFromTCPBind(%q) = %q,%v; want empty,false", empty.Bind, bind, ok)
	}
	if _, ok := buildHTTP3AltSvcAdvertisementWithPlans(empty, sn, plans); ok {
		t.Fatal("empty TCP bind must not produce an Alt-Svc advertisement")
	}
}

// TestHTTP3PerPortIgnoresPlainHTTPSites 覆盖边界：明文站点不建监听、不通告。
func TestHTTP3PerPortIgnoresPlainHTTPSites(t *testing.T) {
	plain := h3PerPortRuntime(1, "127.0.0.1:10443", "plain-per-port.example.test", true)
	plain.Site.TLSEnabled = false
	tlsSite := h3PerPortRuntime(2, "127.0.0.1:11443", "tls-per-port.example.test", true)
	sn := h3PerPortSnapshot(plain, tlsSite)

	plans := buildHTTP3ServerPlans(sn)
	if len(plans) != 1 {
		t.Fatalf("plans = %d (%v), want only the TLS site", len(plans), h3PlanKeys(plans))
	}
	if _, ok := plans["h3::11443"]; !ok {
		t.Fatalf("missing plan h3::11443, got %v", h3PlanKeys(plans))
	}
	if _, ok := buildHTTP3AltSvcAdvertisement(plain, sn); ok {
		t.Fatal("plain HTTP site must not advertise HTTP/3 even in per-port mode")
	}
}

// TestHTTP3PerPortGroupsSamePortDifferentHostsIntoOneUDPListener 覆盖边界：
// 同端口不同 host（含 IPv6 字面量写法）必须汇聚到一个 UDP 监听，
// 否则会尝试在同一个 UDP 端口上绑定两次，其中一个必然 address already in use。
func TestHTTP3PerPortGroupsSamePortDifferentHostsIntoOneUDPListener(t *testing.T) {
	rtA := h3PerPortRuntime(1, "127.0.0.1:12443", "same-port-a.example.test", true)
	rtB := h3PerPortRuntime(2, "[::1]:12443", "same-port-b.example.test", true)
	sn := h3PerPortSnapshot(rtA, rtB)

	plans := buildHTTP3ServerPlans(sn)
	if len(plans) != 1 {
		t.Fatalf("plans = %d (%v), want one UDP listener for the shared port", len(plans), h3PlanKeys(plans))
	}
	plan, ok := plans["h3::12443"]
	if !ok {
		t.Fatalf("missing plan h3::12443, got %v", h3PlanKeys(plans))
	}
	// 两个 TCP bind 都在同一 UDP 监听的路由表里。
	gotA, okA := plan.RouteTable.Resolve("same-port-a.example.test")
	gotB, okB := plan.RouteTable.Resolve("same-port-b.example.test")
	if !okA || gotA != "127.0.0.1:12443" {
		t.Fatalf("route a = %q,%v; want 127.0.0.1:12443,true", gotA, okA)
	}
	if !okB || gotB != "[::1]:12443" {
		t.Fatalf("route b = %q,%v; want [::1]:12443,true", gotB, okB)
	}

	// 该 UDP 监听必须真的能绑上（端口只被占用一次）。
	pc, err := net.ListenPacket("udp", plan.Bind)
	if err != nil {
		t.Fatalf("per-port UDP listener %q is not bindable: %v", plan.Bind, err)
	}
	if err := pc.Close(); err != nil {
		t.Fatalf("close per-port UDP listener: %v", err)
	}
}

// TestHTTP3BindFromTCPBindDerivesPortOnly 直接锁定地址推导规则本身。
func TestHTTP3BindFromTCPBindDerivesPortOnly(t *testing.T) {
	tests := []struct {
		name    string
		tcpBind string
		want    string
		ok      bool
	}{
		{name: "loopback", tcpBind: "127.0.0.1:8443", want: ":8443", ok: true},
		{name: "wildcard", tcpBind: "0.0.0.0:8443", want: ":8443", ok: true},
		{name: "ipv6 literal", tcpBind: "[::1]:8443", want: ":8443", ok: true},
		{name: "port only", tcpBind: ":8443", want: ":8443", ok: true},
		{name: "with spaces", tcpBind: " 127.0.0.1:8443 ", want: ":8443", ok: true},
		{name: "no port", tcpBind: "127.0.0.1", ok: false},
		{name: "empty", tcpBind: "", ok: false},
		{name: "zero port", tcpBind: "127.0.0.1:0", ok: false},
		{name: "port overflow", tcpBind: "127.0.0.1:65536", ok: false},
		{name: "bad port", tcpBind: "127.0.0.1:abc", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := snapshotpkg.HTTP3BindFromTCPBind(tt.tcpBind)
			if ok != tt.ok {
				t.Fatalf("HTTP3BindFromTCPBind(%q) ok = %v, want %v", tt.tcpBind, ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("HTTP3BindFromTCPBind(%q) = %q, want %q", tt.tcpBind, got, tt.want)
			}
		})
	}
}

// TestHTTP3PerPortSplitsSingleGlobalBindAcrossPorts 说明开关的作用点：
// 即使全局 http3_bind 显式配了一个端口，开启 per-port 后也必须按 TCP 端口拆开。
func TestHTTP3PerPortSplitsSingleGlobalBindAcrossPorts(t *testing.T) {
	rtA := h3PerPortRuntime(1, "127.0.0.1:13443", "split-a.example.test", true)
	rtB := h3PerPortRuntime(2, "127.0.0.1:14443", "split-b.example.test", true)
	if rtA.NetworkDefaults.HTTP3Bind != ":8443" || rtB.NetworkDefaults.HTTP3Bind != ":8443" {
		t.Fatalf("test precondition: both sites must share a global http3_bind, got %q / %q",
			rtA.NetworkDefaults.HTTP3Bind, rtB.NetworkDefaults.HTTP3Bind)
	}
	sn := h3PerPortSnapshot(rtA, rtB)

	plans := buildHTTP3ServerPlans(sn)
	if _, ok := plans["h3::8443"]; ok {
		t.Fatalf("global http3_bind must be ignored in per-port mode, got %v", h3PlanKeys(plans))
	}
	for _, want := range []string{"h3::13443", "h3::14443"} {
		if _, ok := plans[want]; !ok {
			t.Fatalf("missing %s in per-port plans %v", want, h3PlanKeys(plans))
		}
	}
}

/*
端到端部分：真起一个 WAF 进程 + 两个 TLS 站点，用真 QUIC 客户端验证
「Alt-Svc 通告的端口真的能连上 h3」。
*/

// TestRunPerPortHTTP3ServesEachTLSPortInSeparateProcess 是唯一能证明
// Alt-Svc 通告端口可达的证据：两个站点分别监听不同 TCP 端口，各自通过
// HTTPS 拿到 Alt-Svc，再用 QUIC 连通告的端口取回上游响应。
func TestRunPerPortHTTP3ServesEachTLSPortInSeparateProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping per-port HTTP/3 process test in -short mode")
	}

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "per-port http3 upstream A:"+r.URL.Path)
	}))
	t.Cleanup(upstreamA.Close)
	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "per-port http3 upstream B:"+r.URL.Path)
	}))
	t.Cleanup(upstreamB.Close)

	portA := reserveAppProcessPort(t)
	portB := reserveAppProcessPort(t)
	if portA == portB {
		t.Fatalf("reserved identical ports %d for both sites", portA)
	}
	tcpBindA := "127.0.0.1:" + strconv.Itoa(portA)
	tcpBindB := "127.0.0.1:" + strconv.Itoa(portB)
	udpBindA := ":" + strconv.Itoa(portA)
	udpBindB := ":" + strconv.Itoa(portB)

	const hostA = "per-port-e2e-a.example.test"
	const hostB = "per-port-e2e-b.example.test"
	const requestPath = "/per-port-h3"
	wantBodyA := "per-port http3 upstream A:" + requestPath
	wantBodyB := "per-port http3 upstream B:" + requestPath

	netCfgBytes, err := json.Marshal(adminsystem.NetworkConfig{
		HTTP2Enabled:        true,
		HTTP3Enabled:        true,
		HTTP3Bind:           ":443",
		HTTP3PerPortEnabled: true,
		DefaultALPN:         "h2,h3,http/1.1",
		DefaultNetwork:      "tcp",
	})
	if err != nil {
		t.Fatalf("marshal network_config: %v", err)
	}

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(netCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}
		for _, spec := range []struct {
			host     string
			bind     string
			upstream string
		}{{hostA, tcpBindA, upstreamA.URL}, {hostB, tcpBindB, upstreamB.URL}} {
			site := store.Site{
				Host:         spec.host,
				UpstreamURLs: spec.upstream,
				Bind:         spec.bind,
				Network:      "tcp",
				Enabled:      true,
				TLSEnabled:   true,
				ALPN:         "",
			}
			if err := db.Create(&site).Error; err != nil {
				return fmt.Errorf("create site %s: %w", spec.host, err)
			}
		}
		return nil
	})

	// 每个 TCP 端口都必须通告自己那个 UDP 端口。
	for _, spec := range []struct {
		host    string
		tcpBind string
		udpPort int
	}{{hostA, tcpBindA, portA}, {hostB, tcpBindB, portB}} {
		wantAltSvc := fmt.Sprintf(`h3=":%d"; ma=86400`, spec.udpPort)
		resp, body := appProc.waitHTTPSProtocolAltSvc(t, spec.tcpBind, spec.host, requestPath, 2, "h2", wantAltSvc)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s HTTPS status = %d, want 200; body=%s\n%s", spec.host, resp.StatusCode, body, appProc.output.String())
		}
	}

	// 再用真 QUIC 客户端连 Alt-Svc 通告的端口，并按各站点自己的上游校验响应体。
	for _, spec := range []struct {
		host     string
		udpBind  string
		wantBody string
	}{{hostA, udpBindA, wantBodyA}, {hostB, udpBindB, wantBodyB}} {
		resp, body := appProc.waitHTTP3Response(t, spec.udpBind, spec.host, requestPath, func(resp *http.Response, body string) bool {
			return resp.StatusCode == http.StatusOK && body == spec.wantBody
		})
		if resp.ProtoMajor != 3 {
			t.Fatalf("%s HTTP/3 proto major = %d, want 3", spec.host, resp.ProtoMajor)
		}
		if resp.TLS == nil || resp.TLS.NegotiatedProtocol != "h3" {
			t.Fatalf("%s HTTP/3 negotiated protocol = %+v, want h3", spec.host, resp.TLS)
		}
		gotAltSvc := resp.Header.Get("Alt-Svc")
		wantAltSvc := fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(spec.udpBind))
		if gotAltSvc != wantAltSvc {
			t.Fatalf("%s HTTP/3 Alt-Svc = %q, want %q", spec.host, gotAltSvc, wantAltSvc)
		}
		if body != spec.wantBody {
			t.Fatalf("%s HTTP/3 body = %q, want %q", spec.host, body, spec.wantBody)
		}
	}

	// 同一条站点 B 的 GET，改从端口 A 的 UDP 监听上发：既不能返回站点 A 的
	// 上游内容（说明路由表没有串），也不能返回站点 B 的上游内容（说明两个
	// 端口确实是两个独立监听，而不是共享一个路由表）。
	respCross, bodyCross := appProc.waitHTTP3Response(t, udpBindA, hostB, requestPath, func(resp *http.Response, body string) bool {
		return resp.StatusCode == http.StatusOK && body != wantBodyA
	})
	if respCross.ProtoMajor != 3 {
		t.Fatalf("cross-port HTTP/3 proto major = %d, want 3", respCross.ProtoMajor)
	}
	if bodyCross == wantBodyA {
		t.Fatalf("host B on %s was proxied to site A's upstream; per-port listeners are not isolated", udpBindA)
	}
	if bodyCross == wantBodyB {
		t.Fatalf("host B on %s reached site B's upstream; the two UDP listeners share one route table", udpBindA)
	}
}

// reserveAppProcessPort 预约一个 TCP 与 UDP 都空闲的端口号：
// per-port 模式下 UDP 端口就等于 TCP 端口，两边都必须空闲。
func reserveAppProcessPort(t *testing.T) int {
	t.Helper()

	for attempt := 0; attempt < 256; attempt++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve tcp port: %v", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		if err := ln.Close(); err != nil {
			t.Fatalf("release tcp port: %v", err)
		}
		if port <= 0 || port > 65535 {
			continue
		}
		pc, err := net.ListenPacket("udp", ":"+strconv.Itoa(port))
		if err != nil {
			continue
		}
		if err := pc.Close(); err != nil {
			t.Fatalf("release udp port: %v", err)
		}
		if reserveAppProcessBindOnce("tcp", "127.0.0.1:"+strconv.Itoa(port)) &&
			reserveAppProcessBindOnce("udp", ":"+strconv.Itoa(port)) {
			return port
		}
	}
	t.Fatal("reserve per-port bind: exhausted attempts")
	return 0
}

// perPortHotReloadCertID 保存热重载用例里预先建好的站点 B 证书 ID。
// 站点 B 经 Admin API 创建，TLS 站点必须引用有效 cert_id。
var perPortHotReloadCertID uint

// seedPerPortCertificate 为指定主机生成自签证书并落库，返回其 ID。
func seedPerPortCertificate(db *gorm.DB, host string) (uint, error) {
	certPEM, keyPEM, err := acme.GenerateSelfSignedPEM(host, []string{host}, nil, time.Hour)
	if err != nil {
		return 0, fmt.Errorf("generate certificate for %s: %w", host, err)
	}
	cert := store.Certificate{
		Name:    "per-port h3 " + host,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}
	if err := db.Create(&cert).Error; err != nil {
		return 0, fmt.Errorf("create certificate for %s: %w", host, err)
	}
	return cert.ID, nil
}

// postPerPortJSON 发送带 API Key 的 JSON POST，接受 200 与 201。
// 既有的 harness.postJSON 只接受 200，而站点创建返回的是 201。
func postPerPortJSON(t *testing.T, h *appProcessHarness, path string, body []byte, out any) {
	t.Helper()

	if exited, err := h.pollExit(); exited {
		t.Fatalf("app helper process exited before POST %s: %v\n%s", path, err, h.output.String())
	}
	req, err := http.NewRequest(http.MethodPost, h.adminURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build POST %s: %v", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+h.apiToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s failed: %v\n%s", path, err, h.output.String())
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read POST %s response: %v", path, err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST %s status = %d, want 200 or 201, body=%s\n%s", path, resp.StatusCode, string(respBody), h.output.String())
	}
	if out == nil {
		return
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		t.Fatalf("decode POST %s response: %v, body=%s", path, err, string(respBody))
	}
}

// TestRunPerPortHTTP3HotReloadAddsListenerInSeparateProcess 覆盖热重载：
// 通过 Admin API 增加第二个 TLS 端口后，新端口的 h3 必须自动出现，旧端口保持可用。
func TestRunPerPortHTTP3HotReloadAddsListenerInSeparateProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping per-port HTTP/3 hot reload test in -short mode")
	}

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "per-port reload upstream A:"+r.URL.Path)
	}))
	t.Cleanup(upstreamA.Close)
	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "per-port reload upstream B:"+r.URL.Path)
	}))
	t.Cleanup(upstreamB.Close)

	portA := reserveAppProcessPort(t)
	portB := reserveAppProcessPort(t)
	if portA == portB {
		t.Fatalf("reserved identical ports %d", portA)
	}
	tcpBindA := "127.0.0.1:" + strconv.Itoa(portA)
	tcpBindB := "127.0.0.1:" + strconv.Itoa(portB)
	udpBindA := ":" + strconv.Itoa(portA)
	udpBindB := ":" + strconv.Itoa(portB)

	const hostA = "per-port-reload-a.example.test"
	const hostB = "per-port-reload-b.example.test"
	const requestPath = "/per-port-reload"
	wantBodyA := "per-port reload upstream A:" + requestPath
	wantBodyB := "per-port reload upstream B:" + requestPath

	netCfgBytes, err := json.Marshal(adminsystem.NetworkConfig{
		HTTP2Enabled:        true,
		HTTP3Enabled:        true,
		HTTP3Bind:           ":443",
		HTTP3PerPortEnabled: true,
		DefaultALPN:         "h2,h3,http/1.1",
		DefaultNetwork:      "tcp",
	})
	if err != nil {
		t.Fatalf("marshal network_config: %v", err)
	}

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(netCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}
		// 站点 B 要经 Admin API 建，TLS 站点必须带可解析的 cert_id。
		certB, err := seedPerPortCertificate(db, hostB)
		if err != nil {
			return err
		}
		site := store.Site{
			Host:         hostA,
			UpstreamURLs: upstreamA.URL,
			Bind:         tcpBindA,
			Network:      "tcp",
			Enabled:      true,
			TLSEnabled:   true,
			ALPN:         "",
		}
		if err := db.Create(&site).Error; err != nil {
			return fmt.Errorf("create site A: %w", err)
		}
		perPortHotReloadCertID = certB
		return nil
	})

	appProc.waitHTTP3Response(t, udpBindA, hostA, requestPath, func(resp *http.Response, body string) bool {
		return resp.StatusCode == http.StatusOK && body == wantBodyA
	})

	// 新增第二个 TLS 站点（走 Admin API，与真实流程一致）。
	createBody, err := json.Marshal(map[string]any{
		"host":          hostB,
		"bind":          tcpBindB,
		"network":       "tcp",
		"enabled":       true,
		"tls_enabled":   true,
		"cert_id":       perPortHotReloadCertID,
		"upstream_urls": upstreamB.URL,
	})
	if err != nil {
		t.Fatalf("marshal site create: %v", err)
	}
	var createResp map[string]any
	postPerPortJSON(t, appProc, "/api/v1/sites", createBody, &createResp)

	// 新端口的 h3 必须自动出现。
	appProc.waitHTTP3Response(t, udpBindB, hostB, requestPath, func(resp *http.Response, body string) bool {
		return resp.StatusCode == http.StatusOK && body == wantBodyB
	})
	// 旧端口必须仍然可用。
	appProc.waitHTTP3Response(t, udpBindA, hostA, requestPath, func(resp *http.Response, body string) bool {
		return resp.StatusCode == http.StatusOK && body == wantBodyA
	})
}

// TestRunPerPortHTTP3DisabledKeepsSingleGlobalBindInSeparateProcess 反向锁定默认行为：
// 开关关闭时，两个 TLS 端口上仍只应存在全局 http3_bind 那一个 h3 监听。
func TestRunPerPortHTTP3DisabledKeepsSingleGlobalBindInSeparateProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping per-port HTTP/3 disabled-mode process test in -short mode")
	}

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "legacy http3 upstream A:"+r.URL.Path)
	}))
	t.Cleanup(upstreamA.Close)
	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "legacy http3 upstream B:"+r.URL.Path)
	}))
	t.Cleanup(upstreamB.Close)

	udpBind := reserveAppProcessUDPBind(t)
	portA := reserveAppProcessPort(t)
	portB := reserveAppProcessPort(t)
	if portA == portB {
		t.Fatalf("reserved identical ports %d", portA)
	}
	tcpBindA := "127.0.0.1:" + strconv.Itoa(portA)
	tcpBindB := "127.0.0.1:" + strconv.Itoa(portB)

	const hostA = "legacy-mode-a.example.test"
	const hostB = "legacy-mode-b.example.test"
	const requestPath = "/legacy-mode-h3"
	wantBodyA := "legacy http3 upstream A:" + requestPath
	wantBodyB := "legacy http3 upstream B:" + requestPath

	netCfgBytes, err := json.Marshal(adminsystem.NetworkConfig{
		HTTP2Enabled:        true,
		HTTP3Enabled:        true,
		HTTP3Bind:           udpBind,
		HTTP3PerPortEnabled: false,
		DefaultALPN:         "h2,h3,http/1.1",
		DefaultNetwork:      "tcp",
	})
	if err != nil {
		t.Fatalf("marshal network_config: %v", err)
	}

	appProc := startAppProcessHarnessWithSetup(t, func(db *gorm.DB) error {
		if err := db.Create(&store.SystemSettings{
			Key:   "network_config",
			Value: string(netCfgBytes),
		}).Error; err != nil {
			return fmt.Errorf("create network_config: %w", err)
		}
		for _, spec := range []struct {
			host     string
			bind     string
			upstream string
		}{{hostA, tcpBindA, upstreamA.URL}, {hostB, tcpBindB, upstreamB.URL}} {
			site := store.Site{
				Host:         spec.host,
				UpstreamURLs: spec.upstream,
				Bind:         spec.bind,
				Network:      "tcp",
				Enabled:      true,
				TLSEnabled:   true,
				ALPN:         "",
			}
			if err := db.Create(&site).Error; err != nil {
				return fmt.Errorf("create site %s: %w", spec.host, err)
			}
		}
		return nil
	})

	wantAltSvc := fmt.Sprintf(`h3=":%s"; ma=86400`, extractPort(udpBind))
	for _, spec := range []struct {
		host     string
		tcpBind  string
		wantBody string
	}{{hostA, tcpBindA, wantBodyA}, {hostB, tcpBindB, wantBodyB}} {
		appProc.waitHTTPSProtocolAltSvc(t, spec.tcpBind, spec.host, requestPath, 2, "h2", wantAltSvc)
		appProc.waitHTTP3Response(t, udpBind, spec.host, requestPath, func(resp *http.Response, body string) bool {
			return resp.StatusCode == http.StatusOK && body == spec.wantBody
		})
	}

	// 两个 TCP 端口本身不得各自多出 UDP 监听。
	for _, port := range []int{portA, portB} {
		appProc.requireHTTP3Unavailable(t, ":"+strconv.Itoa(port), hostA, requestPath)
	}
}
