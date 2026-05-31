package bot

import (
	"crypto/tls"
	"net"
	"testing"
)

func TestHeaderOrderScoreDetectsAlphabeticOrder(t *testing.T) {
	score, reasons := headerOrderScore(BotRequest{HeaderKeys: []string{"accept", "accept-encoding", "host", "user-agent", "x-test"}})
	if score == 0 || len(reasons) == 0 {
		t.Fatalf("expected suspicious score for alphabetic header order, score=%d reasons=%v", score, reasons)
	}
}

func TestParseTLSClientHelloEmptyInput(t *testing.T) {
	fp, err := ParseTLSClientHello(nil)
	if err != nil {
		t.Fatalf("empty input should not error: %v", err)
	}
	if fp.JA3 != "" || fp.JA4 != "" {
		t.Fatalf("empty input should not produce fingerprints: %+v", fp)
	}
}

func TestDeepScoreDoesNotTreatJA4PresenceAsRisk(t *testing.T) {
	bs := DeepScore(BotRequest{
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		AcceptHeader:   "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.9",
		AcceptEncoding: "gzip, deflate, br",
		TLS:            TLSClientFingerprint{JA4: "t13d1516h2_8daaf6152771_e5627efa2ab1"},
	}, nil, nil)
	if bs.FingerprintScore != 0 {
		t.Fatalf("JA4 presence alone should not add fingerprint score, got %d", bs.FingerprintScore)
	}
	if bs.IsHighRisk {
		t.Fatal("benign request with JA4 presence alone should not be high risk")
	}
}

func TestTLSFingerprintFromTLSConnWrappedBaseConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	expected := TLSClientFingerprint{JA3Hash: "abc123", JA4: "t13d"}
	wrapped := WrapFingerprintConn(server, expected)
	tlsConn := tls.Server(wrapped, &tls.Config{Certificates: []tls.Certificate{{}}})

	actual, ok := TLSFingerprintFromConn(tlsConn)
	if !ok {
		t.Fatal("expected fingerprint from wrapped tls.Conn base connection")
	}
	if actual.JA3Hash != expected.JA3Hash || actual.JA4 != expected.JA4 {
		t.Fatalf("unexpected fingerprint: %+v", actual)
	}
}
