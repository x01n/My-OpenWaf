package upstream

import (
	"crypto/tls"
	"testing"
)

func TestSharedDialTLSConfigReusesInstancePerKey(t *testing.T) {
	first := sharedDialTLSConfig("reuse.example.test", false)
	second := sharedDialTLSConfig("reuse.example.test", false)
	if first != second {
		t.Fatal("expected the same *tls.Config instance for an identical key")
	}
	if first.ClientSessionCache == nil {
		t.Fatal("expected a ClientSessionCache so handshakes can resume")
	}
}

func TestSharedDialTLSConfigIsolatesServerNameAndVerifyPolicy(t *testing.T) {
	base := sharedDialTLSConfig("isolated-a.example.test", false)
	otherName := sharedDialTLSConfig("isolated-b.example.test", false)
	otherVerify := sharedDialTLSConfig("isolated-a.example.test", true)

	if base == otherName {
		t.Fatal("configs for different server names must not be shared")
	}
	if base == otherVerify {
		t.Fatal("configs for different verification policies must not be shared")
	}
	if base.ClientSessionCache == otherName.ClientSessionCache {
		t.Fatal("session caches for different server names must not be shared")
	}
	if base.ClientSessionCache == otherVerify.ClientSessionCache {
		t.Fatal("session caches for different verification policies must not be shared")
	}
	if base.ServerName != "isolated-a.example.test" || otherName.ServerName != "isolated-b.example.test" {
		t.Fatalf("unexpected ServerName values: %q, %q", base.ServerName, otherName.ServerName)
	}
	if base.InsecureSkipVerify || !otherVerify.InsecureSkipVerify {
		t.Fatalf("unexpected InsecureSkipVerify values: %v, %v", base.InsecureSkipVerify, otherVerify.InsecureSkipVerify)
	}
}

// The shared config must not weaken the settings HTTPSClientTLSConfig produces.
func TestSharedDialTLSConfigPreservesSecurityParameters(t *testing.T) {
	reference := HTTPSClientTLSConfig("parity.example.test", false)
	shared := sharedDialTLSConfig("parity.example.test", false)

	if shared.MinVersion != reference.MinVersion {
		t.Fatalf("MinVersion = %#x, want %#x", shared.MinVersion, reference.MinVersion)
	}
	if len(shared.CipherSuites) != len(reference.CipherSuites) {
		t.Fatalf("cipher suite count = %d, want %d", len(shared.CipherSuites), len(reference.CipherSuites))
	}
	for i := range reference.CipherSuites {
		if shared.CipherSuites[i] != reference.CipherSuites[i] {
			t.Fatalf("cipher suite[%d] = %#x, want %#x", i, shared.CipherSuites[i], reference.CipherSuites[i])
		}
	}
	if shared.InsecureSkipVerify != reference.InsecureSkipVerify {
		t.Fatalf("InsecureSkipVerify = %v, want %v", shared.InsecureSkipVerify, reference.InsecureSkipVerify)
	}
}

// HTTPSClientTLSConfig keeps returning fresh instances because callers such as
// http3LoopbackTLSConfig mutate NextProtos on the returned value.
func TestHTTPSClientTLSConfigReturnsIndependentInstances(t *testing.T) {
	first := HTTPSClientTLSConfig("independent.example.test", false)
	second := HTTPSClientTLSConfig("independent.example.test", false)
	if first == second {
		t.Fatal("HTTPSClientTLSConfig must return a fresh config callers can mutate")
	}

	first.NextProtos = []string{"h2", "http/1.1"}
	if len(second.NextProtos) != 0 {
		t.Fatalf("mutating one config leaked into another: %#v", second.NextProtos)
	}

	shared := sharedDialTLSConfig("independent.example.test", false)
	if shared == first || shared == second {
		t.Fatal("shared dial config must not alias a caller-mutable instance")
	}

	first.CipherSuites[0] = tls.TLS_RSA_WITH_AES_128_CBC_SHA
	if shared.CipherSuites[0] == tls.TLS_RSA_WITH_AES_128_CBC_SHA && len(shared.CipherSuites) > 0 {
		fresh := HTTPSClientTLSConfig("independent.example.test", false)
		if fresh.CipherSuites[0] != shared.CipherSuites[0] {
			t.Fatal("cipher suite slice is shared between configs")
		}
	}
}
