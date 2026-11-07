package snapshot

import "testing"

// TestNetworkDefaultsDefaultDisablesHTTP3PerPort 锁定默认值：
// 新增开关必须默认关闭，否则「所有 h3 集中到 http3_bind」的既有行为会被改变。
func TestNetworkDefaultsDefaultDisablesHTTP3PerPort(t *testing.T) {
	defaults := DefaultNetworkDefaults()
	if defaults.HTTP3PerPortEnabled {
		t.Fatalf("DefaultNetworkDefaults().HTTP3PerPortEnabled = true, want false: %#v", defaults)
	}
	if defaults.HTTP3Bind != ":443" {
		t.Fatalf("DefaultNetworkDefaults().HTTP3Bind = %q, want :443", defaults.HTTP3Bind)
	}
}

// TestLoadNetworkDefaultsReadsHTTP3PerPortSwitch 覆盖 JSON 往返：
// 省略时保持 false，显式 true 时读回 true，其余既有字段不受影响。
func TestLoadNetworkDefaultsReadsHTTP3PerPortSwitch(t *testing.T) {
	omitted := LoadNetworkDefaults(`{"http3_enabled":true,"http3_bind":":8443","default_alpn":"h2,h3,http/1.1","default_network":"tcp"}`)
	if omitted.HTTP3PerPortEnabled {
		t.Fatalf("omitted http3_per_port_enabled = true, want false: %#v", omitted)
	}
	if omitted.HTTP3Bind != ":8443" {
		t.Fatalf("http3_bind = %q, want :8443", omitted.HTTP3Bind)
	}

	explicit := LoadNetworkDefaults(`{"http3_enabled":true,"http3_bind":":8443","http3_per_port_enabled":true,"default_alpn":"h2,h3,http/1.1","default_network":"tcp"}`)
	if !explicit.HTTP3PerPortEnabled {
		t.Fatalf("explicit http3_per_port_enabled=true was not loaded: %#v", explicit)
	}
	if explicit.HTTP3Bind != ":8443" {
		t.Fatalf("http3_bind = %q, want :8443", explicit.HTTP3Bind)
	}
}

// TestHTTP3BindFromTCPBindRejectsUnusableBinds 覆盖推导函数的拒绝分支，
// 与 internal/app 的机制断言共用同一条规则来源。
func TestHTTP3BindFromTCPBindRejectsUnusableBinds(t *testing.T) {
	tests := []struct {
		name    string
		tcpBind string
		want    string
		ok      bool
	}{
		{name: "loopback", tcpBind: "127.0.0.1:8443", want: ":8443", ok: true},
		{name: "ipv6", tcpBind: "[::1]:9443", want: ":9443", ok: true},
		{name: "port only", tcpBind: ":10443", want: ":10443", ok: true},
		{name: "missing port", tcpBind: "127.0.0.1"},
		{name: "empty", tcpBind: ""},
		{name: "zero port", tcpBind: ":0"},
		{name: "port overflow", tcpBind: ":65536"},
		{name: "non numeric port", tcpBind: ":http"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := HTTP3BindFromTCPBind(tt.tcpBind)
			if ok != tt.ok {
				t.Fatalf("HTTP3BindFromTCPBind(%q) ok = %v, want %v", tt.tcpBind, ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("HTTP3BindFromTCPBind(%q) = %q, want %q", tt.tcpBind, got, tt.want)
			}
		})
	}
}

// TestNormalizeNetworkDefaultsZeroValueUnchanged 锁定「全零结构体仍回落默认值」，
// 保证新增字段没有破坏既有的零值判定。
func TestNormalizeNetworkDefaultsZeroValueUnchanged(t *testing.T) {
	got := normalizeNetworkDefaults(NetworkDefaults{})
	want := DefaultNetworkDefaults()
	if got != want {
		t.Fatalf("normalizeNetworkDefaults(zero) = %#v, want %#v", got, want)
	}
}
