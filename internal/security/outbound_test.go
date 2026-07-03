package security

import (
	"net"
	"net/http"
	"testing"
)

func TestApplyOutboundForwarding(t *testing.T) {
	t.Run("sets forwarding headers", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://origin.local/path", nil)
		if err != nil {
			t.Fatal(err)
		}

		ApplyOutboundForwarding(req, net.ParseIP("203.0.113.10"), "client.example", true, "", "https")

		if got := req.Header.Get("X-Forwarded-For"); got != "203.0.113.10" {
			t.Fatalf("X-Forwarded-For = %q", got)
		}
		if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
			t.Fatalf("X-Forwarded-Proto = %q", got)
		}
		if req.Host != "client.example" {
			t.Fatalf("Host = %q", req.Host)
		}
		if got := req.Header.Get("X-Forwarded-Host"); got != "client.example" {
			t.Fatalf("X-Forwarded-Host = %q", got)
		}
	})

	t.Run("appends existing forwarded for after trimming", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://origin.local/path", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Forwarded-For", " 198.51.100.7 ")

		ApplyOutboundForwarding(req, net.ParseIP("203.0.113.10"), "", false, "", "")

		if got := req.Header.Get("X-Forwarded-For"); got != "198.51.100.7, 203.0.113.10" {
			t.Fatalf("X-Forwarded-For = %q", got)
		}
		if got := req.Header.Get("X-Forwarded-Proto"); got != "" {
			t.Fatalf("X-Forwarded-Proto = %q", got)
		}
		if got := req.Header.Get("X-Forwarded-Host"); got != "" {
			t.Fatalf("X-Forwarded-Host = %q", got)
		}
	})

	t.Run("preserves repeated forwarded for values", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://origin.local/path", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Add("X-Forwarded-For", " 198.51.100.7 ")
		req.Header.Add("X-Forwarded-For", "")
		req.Header.Add("X-Forwarded-For", " 198.51.100.8, 198.51.100.9 ")

		ApplyOutboundForwarding(req, net.ParseIP("203.0.113.10"), "", false, "", "")

		if got := req.Header.Get("X-Forwarded-For"); got != "198.51.100.7, 198.51.100.8, 198.51.100.9, 203.0.113.10" {
			t.Fatalf("X-Forwarded-For = %q", got)
		}
	})

	t.Run("does not preserve host when disabled", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://origin.local/path", nil)
		if err != nil {
			t.Fatal(err)
		}
		initialHost := req.Host

		ApplyOutboundForwarding(req, nil, "client.example", false, "", "http")

		if req.Host != initialHost {
			t.Fatalf("Host = %q", req.Host)
		}
		if got := req.Header.Get("X-Forwarded-Host"); got != "" {
			t.Fatalf("X-Forwarded-Host = %q", got)
		}
		if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
			t.Fatalf("X-Forwarded-Proto = %q", got)
		}
	})

	t.Run("canonical getters prefer updated forwarding values", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://origin.local/path", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header["x-forwarded-proto"] = []string{"old"}
		req.Header["x-forwarded-host"] = []string{"old.example"}

		ApplyOutboundForwarding(req, nil, "client.example", true, "", "https")

		if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
			t.Fatalf("X-Forwarded-Proto = %q", got)
		}
		if got := req.Header.Get("X-Forwarded-Host"); got != "client.example" {
			t.Fatalf("X-Forwarded-Host = %q", got)
		}
	})
}

func BenchmarkApplyOutboundForwardingProtoOnly(b *testing.B) {
	req, err := http.NewRequest(http.MethodGet, "http://origin.local/path", nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req.Header.Del("X-Forwarded-Proto")
		ApplyOutboundForwarding(req, nil, "", false, "", "https")
	}
}

func BenchmarkApplyOutboundForwardingFull(b *testing.B) {
	clientIP := net.ParseIP("203.0.113.10")
	req, err := http.NewRequest(http.MethodGet, "http://origin.local/path", nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Forwarded-Proto")
		req.Header.Del("X-Forwarded-Host")
		req.Host = ""
		ApplyOutboundForwarding(req, clientIP, "client.example", true, "", "https")
	}
}

func TestApplyOutboundForwardingUsesExplicitUpstreamHostOverride(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://origin.local/path", nil)
	if err != nil {
		t.Fatal(err)
	}

	ApplyOutboundForwarding(req, nil, "client.example", false, "backend.example.com", "http")

	if req.Host != "backend.example.com" {
		t.Fatalf("Host = %q", req.Host)
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "" {
		t.Fatalf("X-Forwarded-Host = %q", got)
	}
}
