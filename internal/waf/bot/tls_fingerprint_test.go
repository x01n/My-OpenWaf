package bot

import (
	"crypto/md5"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"

	utls "github.com/refraction-networking/utls"
	ja4 "github.com/wu238121-a11y/go-ja4"
)

func TestHeaderOrderScoreDetectsAlphabeticOrder(t *testing.T) {
	score, reasons := headerOrderScore(BotRequest{HeaderKeys: []string{"accept", "accept-encoding", "host", "user-agent", "x-test"}})
	if score == 0 || len(reasons) == 0 {
		t.Fatalf("expected suspicious score for alphabetic header order, score=%d reasons=%v", score, reasons)
	}
}

func TestTLSVersionStringSupportsSSL3(t *testing.T) {
	if got := tlsVersionString(0x0300); got != "SSL3" {
		t.Fatalf("tlsVersionString(0x0300) = %q, want %q", got, "SSL3")
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

func TestParseTLSClientHelloFromTLSRecord(t *testing.T) {
	record := clientHelloRecordForTest(t)
	fp, err := ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("ParseTLSClientHello() error: %v", err)
	}
	if fp.JA3 == "" || fp.JA3Hash == "" || fp.JA4 == "" {
		t.Fatalf("expected TLS fingerprints, got %+v", fp)
	}
	if fp.TLSVersion == "" {
		t.Fatalf("expected TLS version, got %+v", fp)
	}
	if len(fp.CipherSuites) == 0 || len(fp.Extensions) == 0 {
		t.Fatalf("expected cipher suites and extensions, got %+v", fp)
	}
	if len(fp.ALPN) != 2 || fp.ALPN[0] != "h2" || fp.ALPN[1] != "http/1.1" {
		t.Fatalf("unexpected ALPN protocols: %+v", fp.ALPN)
	}
	if len(fp.PointFormats) == 0 {
		t.Fatalf("expected point formats, got %+v", fp)
	}
}

func TestReadRawClientHelloRejectsMalformedRecords(t *testing.T) {
	valid := clientHelloRecordForTest(t)
	tests := []struct {
		name    string
		record  []byte
		wantErr string
	}{
		{
			name:    "short_record",
			record:  []byte{0x16, 0x03, 0x01, 0x00, 0x00},
			wantErr: "tls record is too short",
		},
		{
			name:    "not_handshake_record",
			record:  mutateTLSRecordForTest(valid, func(record []byte) { record[0] = 0x17 }),
			wantErr: "tls record is not a handshake",
		},
		{
			name: "invalid_record_length",
			record: mutateTLSRecordForTest(valid, func(record []byte) {
				record[3] = 0xff
				record[4] = 0xff
			}),
			wantErr: "tls record length is invalid",
		},
		{
			name: "not_client_hello",
			record: mutateTLSRecordForTest(valid, func(record []byte) {
				record[5] = 0x02
			}),
			wantErr: "tls handshake is not client hello",
		},
		{
			name: "invalid_client_hello_length",
			record: mutateTLSRecordForTest(valid, func(record []byte) {
				record[6] = 0xff
				record[7] = 0xff
				record[8] = 0xff
			}),
			wantErr: "client hello length is invalid",
		},
		{
			name:    "short_client_hello_body",
			record:  tlsClientHelloRecordWithHandshakeForTest([]byte{0x01, 0x00, 0x00, 0x01, 0x03}),
			wantErr: "client hello body is too short",
		},
		{
			name:    "missing_session_id",
			record:  tlsClientHelloRecordWithHelloForTest(make([]byte, 34)),
			wantErr: "client hello missing session id",
		},
		{
			name: "invalid_session_id",
			record: tlsClientHelloRecordWithHelloForTest(func() []byte {
				hello := make([]byte, 37)
				hello[34] = 4
				return hello
			}()),
			wantErr: "client hello session id is invalid",
		},
		{
			name: "invalid_cipher_suites",
			record: tlsClientHelloRecordWithHelloForTest(func() []byte {
				hello := minimalRawClientHelloForTest()
				hello[35] = 0
				hello[36] = 1
				return hello
			}()),
			wantErr: "client hello cipher suites are invalid",
		},
		{
			name: "invalid_compression_methods",
			record: tlsClientHelloRecordWithHelloForTest(func() []byte {
				hello := minimalRawClientHelloForTest()
				hello[39] = 2
				hello = hello[:41]
				return hello
			}()),
			wantErr: "client hello compression methods are invalid",
		},
		{
			name: "missing_extensions_length",
			record: tlsClientHelloRecordWithHelloForTest(func() []byte {
				hello := minimalRawClientHelloForTest()
				hello = hello[:42]
				return hello
			}()),
			wantErr: "client hello extensions length is missing",
		},
		{
			name: "invalid_extensions_length",
			record: tlsClientHelloRecordWithHelloForTest(func() []byte {
				hello := minimalRawClientHelloForTest()
				hello[41] = 0
				hello[42] = 1
				return hello
			}()),
			wantErr: "client hello extensions are invalid",
		},
		{
			name: "invalid_extension_header",
			record: tlsClientHelloRecordWithHelloForTest(func() []byte {
				hello := minimalRawClientHelloForTest()
				hello[41] = 0
				hello[42] = 3
				hello = append(hello, 0, 0, 0)
				return hello
			}()),
			wantErr: "client hello extension header is invalid",
		},
		{
			name: "invalid_extension_data",
			record: tlsClientHelloRecordWithHelloForTest(func() []byte {
				hello := minimalRawClientHelloForTest()
				hello[41] = 0
				hello[42] = 4
				hello = append(hello, 0, 16, 0, 1)
				return hello
			}()),
			wantErr: "client hello extension data is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := readRawClientHello(tt.record); err == nil || err.Error() != tt.wantErr {
				t.Fatalf("readRawClientHello() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseTLSClientHelloRawAcceptsClientHelloWithoutExtensions(t *testing.T) {
	record := tlsClientHelloRecordWithHelloForTest(minimalRawClientHelloWithoutExtensionsForTest())
	got, err := ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("ParseTLSClientHello() error: %v", err)
	}
	if got.TLSVersion != "TLS12" {
		t.Fatalf("TLSVersion = %q, want %q", got.TLSVersion, "TLS12")
	}
	if got.JA3 != "771,4865,,," {
		t.Fatalf("JA3 = %q, want %q", got.JA3, "771,4865,,,")
	}
	if got.JA3Hash == "" || got.JA4 == "" {
		t.Fatalf("expected hashes, got %+v", got)
	}
	if !reflect.DeepEqual(got.CipherSuites, []uint16{4865}) {
		t.Fatalf("CipherSuites = %+v, want %+v", got.CipherSuites, []uint16{4865})
	}
	if len(got.Extensions) != 0 || len(got.Curves) != 0 || len(got.PointFormats) != 0 || len(got.ALPN) != 0 {
		t.Fatalf("expected no extensions-derived fields, got %+v", got)
	}
}

func TestParseTLSClientHelloRawAcceptsEmptyExtensionsList(t *testing.T) {
	record := tlsClientHelloRecordWithHelloForTest(minimalRawClientHelloForTest())
	got, err := ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("ParseTLSClientHello() error: %v", err)
	}
	if got.TLSVersion != "TLS12" {
		t.Fatalf("TLSVersion = %q, want %q", got.TLSVersion, "TLS12")
	}
	if got.JA3 != "771,4865,,," {
		t.Fatalf("JA3 = %q, want %q", got.JA3, "771,4865,,,")
	}
	if got.JA3Hash == "" || got.JA4 == "" {
		t.Fatalf("expected hashes, got %+v", got)
	}
	if len(got.Extensions) != 0 {
		t.Fatalf("Extensions = %+v, want empty", got.Extensions)
	}
}

func TestParseTLSClientHelloRawAcceptsEmptySessionTicketExtension(t *testing.T) {
	hello := rawClientHelloWithExtensionsForTest(rawTLSExtensionForTest(35, nil))
	record := tlsClientHelloRecordWithHelloForTest(hello)
	got := requireTLSClientHelloMatchesUTLSReference(t, record)
	if !reflect.DeepEqual(got.Extensions, []uint16{35}) {
		t.Fatalf("Extensions = %+v, want %+v", got.Extensions, []uint16{35})
	}
	if len(got.ALPN) != 0 {
		t.Fatalf("ALPN = %+v, want empty", got.ALPN)
	}
}

func TestParseTLSClientHelloMatchesUTLSReference(t *testing.T) {
	record := clientHelloRecordForTest(t)
	got := requireTLSClientHelloMatchesUTLSReference(t, record)
	if got.SNI != "example.com" {
		t.Fatalf("SNI = %q, want %q", got.SNI, "example.com")
	}
}

func TestParseTLSClientHelloMatchesUTLSReferenceParrotProfiles(t *testing.T) {
	tests := []struct {
		name string
		id   utls.ClientHelloID
	}{
		{name: "chrome_120", id: utls.HelloChrome_120},
		{name: "chrome_133", id: utls.HelloChrome_133},
		{name: "firefox_120", id: utls.HelloFirefox_120},
		{name: "ios_14", id: utls.HelloIOS_14},
		{name: "android_11_okhttp", id: utls.HelloAndroid_11_OkHttp},
		{name: "edge_85", id: utls.HelloEdge_85},
		{name: "safari_16_0", id: utls.HelloSafari_16_0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := utlsClientHelloRecordForTest(t, tt.id)
			got := requireTLSClientHelloMatchesUTLSReference(t, record)
			if got.JA3 == "" || got.JA3Hash == "" || got.JA4 == "" {
				t.Fatalf("expected TLS fingerprints, got %+v", got)
			}
			if len(got.CipherSuites) == 0 || len(got.Extensions) == 0 {
				t.Fatalf("expected cipher suites and extensions, got %+v", got)
			}
			if got.SNI != "example.com" {
				t.Fatalf("SNI = %q, want %q", got.SNI, "example.com")
			}
		})
	}
}

func TestParseTLSClientHelloMatchesUTLSReferenceVariants(t *testing.T) {
	tests := []struct {
		name                           string
		config                         tls.Config
		wantALPN                       []string
		wantSNIExtension               bool
		wantSupportedVersionsExtension bool
		wantTLSVersion                 string
	}{
		{
			name: "default_sni_alpn",
			config: tls.Config{
				ServerName: "example.com",
				NextProtos: []string{"h2", "http/1.1"},
			},
			wantALPN:                       []string{"h2", "http/1.1"},
			wantSNIExtension:               true,
			wantSupportedVersionsExtension: true,
			wantTLSVersion:                 "TLS13",
		},
		{
			name: "no_alpn",
			config: tls.Config{
				ServerName: "example.com",
			},
			wantSNIExtension:               true,
			wantSupportedVersionsExtension: true,
			wantTLSVersion:                 "TLS13",
		},
		{
			name: "no_sni",
			config: tls.Config{
				NextProtos: []string{"h2", "http/1.1"},
			},
			wantALPN:                       []string{"h2", "http/1.1"},
			wantSupportedVersionsExtension: true,
			wantTLSVersion:                 "TLS13",
		},
		{
			name: "tls12_only",
			config: tls.Config{
				ServerName: "example.com",
				NextProtos: []string{"http/1.1"},
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
			},
			wantALPN:                       []string{"http/1.1"},
			wantSNIExtension:               true,
			wantSupportedVersionsExtension: true,
			wantTLSVersion:                 "TLS12",
		},
		{
			name: "tls12_no_sni_no_alpn",
			config: tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
			},
			wantSupportedVersionsExtension: true,
			wantTLSVersion:                 "TLS12",
		},
		{
			name: "tls13_no_alpn",
			config: tls.Config{
				ServerName: "example.com",
				MinVersion: tls.VersionTLS13,
				MaxVersion: tls.VersionTLS13,
			},
			wantSNIExtension:               true,
			wantSupportedVersionsExtension: true,
			wantTLSVersion:                 "TLS13",
		},
		{
			name: "ip_server_name_no_sni",
			config: tls.Config{
				ServerName: "127.0.0.1",
				NextProtos: []string{"h2"},
			},
			wantALPN:                       []string{"h2"},
			wantSupportedVersionsExtension: true,
			wantTLSVersion:                 "TLS13",
		},
		{
			name: "many_alpn_protocols",
			config: tls.Config{
				ServerName: "example.com",
				NextProtos: []string{"h2", "http/1.1", "acme-tls/1", "grpc-exp", "customproto"},
			},
			wantALPN:                       []string{"h2", "http/1.1", "acme-tls/1", "grpc-exp", "customproto"},
			wantSNIExtension:               true,
			wantSupportedVersionsExtension: true,
			wantTLSVersion:                 "TLS13",
		},
	}

	for i := range tests {
		tt := &tests[i]
		t.Run(tt.name, func(t *testing.T) {
			record := clientHelloRecordWithConfigForTest(t, &tt.config)
			got := requireTLSClientHelloMatchesUTLSReference(t, record)
			if got.JA3 == "" || got.JA3Hash == "" || got.JA4 == "" {
				t.Fatalf("expected TLS fingerprints, got %+v", got)
			}
			if got.TLSVersion != tt.wantTLSVersion {
				t.Fatalf("TLSVersion = %q, want %q", got.TLSVersion, tt.wantTLSVersion)
			}
			if tt.config.ServerName != "" && tt.config.ServerName != "127.0.0.1" && got.SNI != tt.config.ServerName {
				t.Fatalf("SNI = %q, want %q", got.SNI, tt.config.ServerName)
			}
			if !reflect.DeepEqual(got.ALPN, tt.wantALPN) {
				t.Fatalf("ALPN = %+v, want %+v", got.ALPN, tt.wantALPN)
			}
			if hasTLSUint16ForTest(got.Extensions, 0) != tt.wantSNIExtension {
				t.Fatalf("SNI extension presence in %+v does not match want %v", got.Extensions, tt.wantSNIExtension)
			}
			if hasTLSUint16ForTest(got.Extensions, 43) != tt.wantSupportedVersionsExtension {
				t.Fatalf("supported_versions extension presence in %+v does not match want %v", got.Extensions, tt.wantSupportedVersionsExtension)
			}
		})
	}
}

func TestParseTLSClientHelloMatchesUTLSReferenceWithoutSupportedVersions(t *testing.T) {
	record := clientHelloRecordWithConfigForTest(t, &tls.Config{
		ServerName: "example.com",
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	})
	record = removeTLSClientHelloExtensionForTest(t, record, 43)
	got := requireTLSClientHelloMatchesUTLSReference(t, record)
	if hasTLSUint16ForTest(got.Extensions, 43) {
		t.Fatalf("supported_versions extension should be absent in %+v", got.Extensions)
	}
	if got.TLSVersion != "TLS12" {
		t.Fatalf("TLSVersion = %q, want %q", got.TLSVersion, "TLS12")
	}
	if got.SNI != "example.com" {
		t.Fatalf("SNI = %q, want %q", got.SNI, "example.com")
	}
}

func TestParseTLSClientHelloMatchesUTLSReferenceWithMovedExtension(t *testing.T) {
	record := moveTLSClientHelloExtensionToFrontForTest(t, clientHelloRecordForTest(t), 16)
	got := requireTLSClientHelloMatchesUTLSReference(t, record)
	if len(got.Extensions) == 0 || got.Extensions[0] != 16 {
		t.Fatalf("first extension = %+v, want extension 16 first", got.Extensions)
	}
	if !reflect.DeepEqual(got.ALPN, []string{"h2", "http/1.1"}) {
		t.Fatalf("ALPN = %+v, want %+v", got.ALPN, []string{"h2", "http/1.1"})
	}
}

func TestParseTLSClientHelloMatchesUTLSReferenceWithDuplicateSupportedVersions(t *testing.T) {
	record := duplicateTLSClientHelloExtensionForTest(t, clientHelloRecordForTest(t), 43, []byte{0x02, 0x03, 0x03})
	got := requireTLSClientHelloMatchesUTLSReference(t, record)
	if got.TLSVersion != "TLS13" {
		t.Fatalf("TLSVersion = %q, want %q", got.TLSVersion, "TLS13")
	}
}

func TestParseTLSClientHelloMatchesUTLSReferenceWithDuplicateALPN(t *testing.T) {
	record := duplicateTLSClientHelloExtensionForTest(t, clientHelloRecordForTest(t), 16, []byte{
		0x00, 0x05,
		0x04, 'h', '3', '-', '2',
	})
	got := requireTLSClientHelloMatchesUTLSReference(t, record)
	want := []string{"h2", "http/1.1", "h3-2"}
	if !reflect.DeepEqual(got.ALPN, want) {
		t.Fatalf("ALPN = %+v, want %+v", got.ALPN, want)
	}
}

func TestParseTLSClientHelloCommonALPNPathDoesNotLeakAcrossCalls(t *testing.T) {
	baseRecord := clientHelloRecordForTest(t)
	duplicateRecord := duplicateTLSClientHelloExtensionForTest(t, baseRecord, 16, []byte{
		0x00, 0x05,
		0x04, 'h', '3', '-', '2',
	})

	first := requireTLSClientHelloMatchesUTLSReference(t, baseRecord)
	if !reflect.DeepEqual(first.ALPN, []string{"h2", "http/1.1"}) {
		t.Fatalf("first ALPN = %+v, want %+v", first.ALPN, []string{"h2", "http/1.1"})
	}

	duplicate := requireTLSClientHelloMatchesUTLSReference(t, duplicateRecord)
	if !reflect.DeepEqual(duplicate.ALPN, []string{"h2", "http/1.1", "h3-2"}) {
		t.Fatalf("duplicate ALPN = %+v, want %+v", duplicate.ALPN, []string{"h2", "http/1.1", "h3-2"})
	}

	second := requireTLSClientHelloMatchesUTLSReference(t, baseRecord)
	if !reflect.DeepEqual(second.ALPN, []string{"h2", "http/1.1"}) {
		t.Fatalf("second ALPN = %+v, want %+v", second.ALPN, []string{"h2", "http/1.1"})
	}
}

func TestParseTLSClientHelloMatchesUTLSReferenceWithDuplicateSupportedGroups(t *testing.T) {
	record := duplicateTLSClientHelloExtensionForTest(t, clientHelloRecordForTest(t), 10, []byte{
		0x00, 0x04,
		0x00, 0x1d,
		0x00, 0x17,
	})
	got := requireTLSClientHelloMatchesUTLSReference(t, record)
	wantSuffix := []uint16{29, 23}
	if len(got.Curves) < len(wantSuffix) || !reflect.DeepEqual(got.Curves[len(got.Curves)-len(wantSuffix):], wantSuffix) {
		t.Fatalf("Curves = %+v, want suffix %+v", got.Curves, wantSuffix)
	}
}

func TestParseTLSClientHelloMatchesUTLSReferenceWithDuplicatePointFormats(t *testing.T) {
	record := duplicateTLSClientHelloExtensionForTest(t, clientHelloRecordForTest(t), 11, []byte{0x02, 0x00, 0x01})
	got := requireTLSClientHelloMatchesUTLSReference(t, record)
	wantSuffix := []uint8{0, 1}
	if len(got.PointFormats) < len(wantSuffix) || !reflect.DeepEqual(got.PointFormats[len(got.PointFormats)-len(wantSuffix):], wantSuffix) {
		t.Fatalf("PointFormats = %+v, want suffix %+v", got.PointFormats, wantSuffix)
	}
}

func TestParseTLSClientHelloMatchesUTLSReferenceWithDuplicateSignatureAlgorithms(t *testing.T) {
	record := duplicateTLSClientHelloExtensionForTest(t, clientHelloRecordForTest(t), 13, []byte{
		0x00, 0x04,
		0x08, 0x04,
		0x04, 0x03,
	})
	got := requireTLSClientHelloMatchesUTLSReference(t, record)
	if got.JA4 == "" {
		t.Fatalf("expected JA4, got %+v", got)
	}
}

func TestParseTLSClientHelloMatchesUTLSReferenceWithUnknownExtension(t *testing.T) {
	const extensionID uint16 = 0x1234
	record := duplicateTLSClientHelloExtensionForTest(t, clientHelloRecordForTest(t), extensionID, []byte{0x01, 0x02, 0x03})
	got := requireTLSClientHelloMatchesUTLSReference(t, record)
	if !hasTLSUint16ForTest(got.Extensions, extensionID) {
		t.Fatalf("Extensions = %+v, want extension %d", got.Extensions, extensionID)
	}
}

func requireTLSClientHelloMatchesUTLSReference(t *testing.T, record []byte) TLSClientFingerprint {
	t.Helper()
	got, err := ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("ParseTLSClientHello() error: %v", err)
	}
	want, err := parseTLSClientHelloWithUTLS(record)
	if err != nil {
		t.Fatalf("parseTLSClientHelloWithUTLS() error: %v", err)
	}
	want.SNI = got.SNI
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseTLSClientHello() = %+v, want %+v", got, want)
	}
	return got
}

func BenchmarkParseTLSClientHello(b *testing.B) {
	record := clientHelloRecordForTest(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fp, err := ParseTLSClientHello(record)
		if err != nil || fp.JA3 == "" || fp.JA3Hash == "" || fp.JA4 == "" {
			b.Fatalf("ParseTLSClientHello() = %+v, %v", fp, err)
		}
	}
}

func BenchmarkParseTLSClientHelloAlternatingRecords(b *testing.B) {
	records := [][]byte{
		clientHelloRecordForTest(b),
		clientHelloRecordWithConfigForTest(b, &tls.Config{
			ServerName: "api.example.com",
			NextProtos: []string{"http/1.1"},
		}),
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		record := records[i&1]
		fp, err := ParseTLSClientHello(record)
		if err != nil || fp.JA3 == "" || fp.JA3Hash == "" || fp.JA4 == "" {
			b.Fatalf("ParseTLSClientHello() = %+v, %v", fp, err)
		}
	}
}

func TestParseTLSClientHelloCacheSeparatesDistinctRecords(t *testing.T) {
	firstRecord := clientHelloRecordForTest(t)
	secondRecord := clientHelloRecordWithConfigForTest(t, &tls.Config{
		ServerName: "api.example.com",
		NextProtos: []string{"http/1.1"},
	})

	first, err := ParseTLSClientHello(firstRecord)
	if err != nil {
		t.Fatalf("first ParseTLSClientHello() error: %v", err)
	}
	second, err := ParseTLSClientHello(secondRecord)
	if err != nil {
		t.Fatalf("second ParseTLSClientHello() error: %v", err)
	}
	firstAgain, err := ParseTLSClientHello(firstRecord)
	if err != nil {
		t.Fatalf("firstAgain ParseTLSClientHello() error: %v", err)
	}
	secondAgain, err := ParseTLSClientHello(secondRecord)
	if err != nil {
		t.Fatalf("secondAgain ParseTLSClientHello() error: %v", err)
	}

	if !reflect.DeepEqual(first, firstAgain) {
		t.Fatalf("first cached fingerprint = %+v, want %+v", firstAgain, first)
	}
	if !reflect.DeepEqual(second, secondAgain) {
		t.Fatalf("second cached fingerprint = %+v, want %+v", secondAgain, second)
	}
	if first.SNI == second.SNI {
		t.Fatalf("expected distinct cached SNI values, got first=%q second=%q", first.SNI, second.SNI)
	}
}

func TestParseTLSClientHelloCacheClonesStoredSlices(t *testing.T) {
	record := clientHelloRecordForTest(t)

	first, err := ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("first ParseTLSClientHello() error: %v", err)
	}
	want, err := ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("want ParseTLSClientHello() error: %v", err)
	}

	if len(first.ALPN) == 0 || len(first.CipherSuites) == 0 || len(first.Extensions) == 0 || len(first.Curves) == 0 || len(first.PointFormats) == 0 {
		t.Fatalf("expected populated TLS slices, got %+v", first)
	}

	first.ALPN[0] = "mutated"
	first.CipherSuites[0] = 0
	first.Extensions[0] = 0
	first.Curves[0] = 0
	first.PointFormats[0] = 255

	got, err := ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("cached ParseTLSClientHello() error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cached fingerprint changed after caller mutation: got %+v want %+v", got, want)
	}
}

func clientHelloRecordForTest(tb testing.TB) []byte {
	tb.Helper()
	return clientHelloRecordWithConfigForTest(tb, &tls.Config{
		ServerName: "example.com",
		NextProtos: []string{"h2", "http/1.1"},
	})
}

func clientHelloRecordWithConfigForTest(tb testing.TB, config *tls.Config) []byte {
	tb.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	tlsConfig := &tls.Config{}
	if config != nil {
		tlsConfig = config.Clone()
	}
	tlsConfig.InsecureSkipVerify = true
	go func() {
		defer client.Close()
		tlsClient := tls.Client(client, tlsConfig)
		done <- tlsClient.Handshake()
	}()

	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		server.Close()
		tb.Fatalf("read TLS record header: %v", err)
	}
	if header[0] != 0x16 {
		server.Close()
		tb.Fatalf("record content type = %d, want 22", header[0])
	}
	recordLen := int(header[3])<<8 | int(header[4])
	body := make([]byte, recordLen)
	if _, err := io.ReadFull(server, body); err != nil {
		server.Close()
		tb.Fatalf("read TLS record body: %v", err)
	}
	server.Close()
	<-done

	record := make([]byte, 0, len(header)+len(body))
	record = append(record, header...)
	record = append(record, body...)
	return record
}

func utlsClientHelloRecordForTest(tb testing.TB, id utls.ClientHelloID) []byte {
	tb.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer client.Close()
		tlsClient := utls.UClient(client, &utls.Config{
			ServerName:         "example.com",
			InsecureSkipVerify: true,
		}, id)
		done <- tlsClient.Handshake()
	}()

	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		server.Close()
		tb.Fatalf("read uTLS record header: %v", err)
	}
	if header[0] != 0x16 {
		server.Close()
		tb.Fatalf("uTLS record content type = %d, want 22", header[0])
	}
	recordLen := int(header[3])<<8 | int(header[4])
	body := make([]byte, recordLen)
	if _, err := io.ReadFull(server, body); err != nil {
		server.Close()
		tb.Fatalf("read uTLS record body: %v", err)
	}
	server.Close()
	<-done

	record := make([]byte, 0, len(header)+len(body))
	record = append(record, header...)
	record = append(record, body...)
	return record
}

func hasTLSUint16ForTest(vals []uint16, want uint16) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

func mutateTLSRecordForTest(record []byte, mutate func([]byte)) []byte {
	out := append([]byte(nil), record...)
	mutate(out)
	return out
}

func tlsClientHelloRecordWithHandshakeForTest(handshake []byte) []byte {
	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	record[3] = byte(len(handshake) >> 8)
	record[4] = byte(len(handshake))
	copy(record[5:], handshake)
	return record
}

func tlsClientHelloRecordWithHelloForTest(hello []byte) []byte {
	handshake := make([]byte, 4+len(hello))
	handshake[0] = 0x01
	handshake[1] = byte(len(hello) >> 16)
	handshake[2] = byte(len(hello) >> 8)
	handshake[3] = byte(len(hello))
	copy(handshake[4:], hello)
	return tlsClientHelloRecordWithHandshakeForTest(handshake)
}

func minimalRawClientHelloForTest() []byte {
	hello := make([]byte, 43)
	hello[0] = 0x03
	hello[1] = 0x03
	hello[34] = 0
	hello[35] = 0
	hello[36] = 2
	hello[37] = 0x13
	hello[38] = 0x01
	hello[39] = 1
	hello[40] = 0
	hello[41] = 0
	hello[42] = 0
	return hello
}

func minimalRawClientHelloWithoutExtensionsForTest() []byte {
	hello := minimalRawClientHelloForTest()
	return hello[:41]
}

func rawClientHelloWithExtensionsForTest(blocks ...[]byte) []byte {
	hello := minimalRawClientHelloForTest()
	extLen := 0
	for _, block := range blocks {
		extLen += len(block)
	}
	hello[41] = byte(extLen >> 8)
	hello[42] = byte(extLen)
	for _, block := range blocks {
		hello = append(hello, block...)
	}
	return hello
}

func rawTLSExtensionForTest(extensionID uint16, data []byte) []byte {
	block := make([]byte, 4+len(data))
	block[0] = byte(extensionID >> 8)
	block[1] = byte(extensionID)
	block[2] = byte(len(data) >> 8)
	block[3] = byte(len(data))
	copy(block[4:], data)
	return block
}

func duplicateTLSClientHelloExtensionForTest(tb testing.TB, record []byte, extensionID uint16, data []byte) []byte {
	tb.Helper()
	return rewriteTLSClientHelloExtensionsForTest(tb, record, func(blocks [][]byte) [][]byte {
		next := make([][]byte, 0, len(blocks)+1)
		next = append(next, blocks...)
		block := make([]byte, 4+len(data))
		block[0] = byte(extensionID >> 8)
		block[1] = byte(extensionID)
		block[2] = byte(len(data) >> 8)
		block[3] = byte(len(data))
		copy(block[4:], data)
		next = append(next, block)
		return next
	})
}

func removeTLSClientHelloExtensionForTest(tb testing.TB, record []byte, extensionID uint16) []byte {
	tb.Helper()
	removed := false
	out := rewriteTLSClientHelloExtensionsForTest(tb, record, func(blocks [][]byte) [][]byte {
		next := make([][]byte, 0, len(blocks))
		for _, block := range blocks {
			if tlsExtensionIDForTest(block) == extensionID {
				removed = true
				continue
			}
			next = append(next, block)
		}
		return next
	})
	if !removed {
		tb.Fatalf("extension %d was not present", extensionID)
	}
	return out
}

func moveTLSClientHelloExtensionToFrontForTest(tb testing.TB, record []byte, extensionID uint16) []byte {
	tb.Helper()
	moved := false
	out := rewriteTLSClientHelloExtensionsForTest(tb, record, func(blocks [][]byte) [][]byte {
		next := make([][]byte, 0, len(blocks))
		for _, block := range blocks {
			if tlsExtensionIDForTest(block) == extensionID {
				next = append(next, block)
				moved = true
				break
			}
		}
		for _, block := range blocks {
			if tlsExtensionIDForTest(block) != extensionID {
				next = append(next, block)
			}
		}
		return next
	})
	if !moved {
		tb.Fatalf("extension %d was not present", extensionID)
	}
	return out
}

func rewriteTLSClientHelloExtensionsForTest(tb testing.TB, record []byte, rewrite func([][]byte) [][]byte) []byte {
	tb.Helper()
	if len(record) < 9 {
		tb.Fatalf("tls record is too short: %d", len(record))
	}
	recordLen := int(record[3])<<8 | int(record[4])
	if len(record) < 5+recordLen {
		tb.Fatalf("tls record length %d exceeds record size %d", recordLen, len(record))
	}
	handshake := record[5 : 5+recordLen]
	if len(handshake) < 4 || handshake[0] != 0x01 {
		tb.Fatalf("record does not contain a client hello")
	}
	helloLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+helloLen {
		tb.Fatalf("client hello length %d exceeds handshake size %d", helloLen, len(handshake))
	}
	hello := handshake[4 : 4+helloLen]
	extLenOffset, extStart, extEnd := tlsClientHelloExtensionBoundsForTest(tb, hello)
	blocks := tlsClientHelloExtensionBlocksForTest(tb, hello[extStart:extEnd])
	nextBlocks := rewrite(blocks)
	nextExtLen := 0
	for _, block := range nextBlocks {
		nextExtLen += len(block)
	}
	if nextExtLen > 0xffff {
		tb.Fatalf("extension block length %d exceeds uint16", nextExtLen)
	}

	nextHello := make([]byte, 0, len(hello)-(extEnd-extStart)+nextExtLen)
	nextHello = append(nextHello, hello[:extLenOffset]...)
	nextHello = append(nextHello, byte(nextExtLen>>8), byte(nextExtLen))
	for _, block := range nextBlocks {
		nextHello = append(nextHello, block...)
	}
	nextHello = append(nextHello, hello[extEnd:]...)

	nextHandshake := make([]byte, 4+len(nextHello))
	nextHandshake[0] = handshake[0]
	nextHandshake[1] = byte(len(nextHello) >> 16)
	nextHandshake[2] = byte(len(nextHello) >> 8)
	nextHandshake[3] = byte(len(nextHello))
	copy(nextHandshake[4:], nextHello)

	nextRecord := make([]byte, 5+len(nextHandshake))
	copy(nextRecord[:5], record[:5])
	nextRecordLen := len(nextHandshake)
	nextRecord[3] = byte(nextRecordLen >> 8)
	nextRecord[4] = byte(nextRecordLen)
	copy(nextRecord[5:], nextHandshake)
	return nextRecord
}

func tlsClientHelloExtensionBoundsForTest(tb testing.TB, hello []byte) (int, int, int) {
	tb.Helper()
	if len(hello) < 38 {
		tb.Fatalf("client hello body is too short: %d", len(hello))
	}
	pos := 2 + 32
	if pos >= len(hello) {
		tb.Fatalf("client hello missing session id")
	}
	sessionLen := int(hello[pos])
	pos++
	if len(hello) < pos+sessionLen+2 {
		tb.Fatalf("client hello session id is invalid")
	}
	pos += sessionLen
	cipherLen := int(hello[pos])<<8 | int(hello[pos+1])
	pos += 2
	if cipherLen%2 != 0 || cipherLen == 0 || len(hello) < pos+cipherLen+1 {
		tb.Fatalf("client hello cipher suites are invalid")
	}
	pos += cipherLen
	compressionLen := int(hello[pos])
	pos++
	if len(hello) < pos+compressionLen {
		tb.Fatalf("client hello compression methods are invalid")
	}
	pos += compressionLen
	if len(hello) < pos+2 {
		tb.Fatalf("client hello extensions length is missing")
	}
	extLenOffset := pos
	extensionsLen := int(hello[pos])<<8 | int(hello[pos+1])
	extStart := pos + 2
	extEnd := extStart + extensionsLen
	if len(hello) < extEnd {
		tb.Fatalf("client hello extensions length %d exceeds body size %d", extensionsLen, len(hello))
	}
	return extLenOffset, extStart, extEnd
}

func tlsClientHelloExtensionBlocksForTest(tb testing.TB, data []byte) [][]byte {
	tb.Helper()
	var blocks [][]byte
	for pos := 0; pos < len(data); {
		if len(data)-pos < 4 {
			tb.Fatalf("extension header is invalid")
		}
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		end := pos + 4 + extLen
		if end > len(data) {
			tb.Fatalf("extension length %d exceeds remaining data %d", extLen, len(data)-pos)
		}
		block := make([]byte, end-pos)
		copy(block, data[pos:end])
		blocks = append(blocks, block)
		pos = end
	}
	return blocks
}

func tlsExtensionIDForTest(block []byte) uint16 {
	return uint16(block[0])<<8 | uint16(block[1])
}

func TestBuildJA3StringPreservesFormatAndFiltersGREASE(t *testing.T) {
	spec := &utls.ClientHelloSpec{
		TLSVersMax:   tls.VersionTLS13,
		CipherSuites: []uint16{0x0a0a, 4865, 4866, 0x1a1a, 4867},
	}
	extensions := []uint16{0, 0x2a2a, 10, 11, 43}
	curves := []uint16{0x3a3a, 29, 23}
	pointFormats := []uint8{0, 1}

	got := buildJA3String(spec, extensions, curves, pointFormats)
	want := "772,4865-4866-4867,0-10-11-43,29-23,0-1"
	if got != want {
		t.Fatalf("buildJA3String() = %q, want %q", got, want)
	}
}

func TestBuildJA3StringHandlesLongInput(t *testing.T) {
	spec := &utls.ClientHelloSpec{TLSVersMax: tls.VersionTLS13}
	for i := uint16(1); i <= 80; i++ {
		spec.CipherSuites = append(spec.CipherSuites, 40000+i)
	}
	extensions := make([]uint16, 0, 80)
	for i := uint16(1); i <= 80; i++ {
		extensions = append(extensions, 50000+i)
	}
	curves := []uint16{60001, 60002, 60003, 60004, 60005}
	pointFormats := []uint8{0, 1, 2}

	got := buildJA3String(spec, extensions, curves, pointFormats)
	if len(got) <= 256 {
		t.Fatalf("buildJA3String() length = %d, want > 256", len(got))
	}
	wantPrefix := "772,40001-40002-40003"
	if len(got) < len(wantPrefix) {
		t.Fatalf("buildJA3String() length = %d, want at least %d", len(got), len(wantPrefix))
	}
	if got[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("buildJA3String() prefix = %q, want %q", got[:len(wantPrefix)], wantPrefix)
	}
	wantSuffix := ",60001-60002-60003-60004-60005,0-1-2"
	if len(got) < len(wantSuffix) {
		t.Fatalf("buildJA3String() length = %d, want at least %d", len(got), len(wantSuffix))
	}
	if got[len(got)-len(wantSuffix):] != wantSuffix {
		t.Fatalf("buildJA3String() suffix = %q, want %q", got[len(got)-len(wantSuffix):], wantSuffix)
	}
}

func ja4ReferenceSpec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			0x0a0a, 4865, 4866, 4867, 49195, 49199, 49196, 49200,
			52393, 52392, 49171, 49172, 156, 157, 47, 53,
		},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{Value: 0x1a1a},
			&utls.SNIExtension{ServerName: "lptag.liveperson.net"},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519, Data: []byte{1, 2, 3, 4}}}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.ExtendedMasterSecretExtension{},
			&utls.SupportedVersionsExtension{Versions: []uint16{0xdada, utls.VersionTLS13, utls.VersionTLS12}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.CurveID(0x1a1a), utls.X25519, utls.CurveP256, utls.CurveP384}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{1}},
			&utls.StatusRequestExtension{},
			&utls.SessionTicketExtension{},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&utls.GenericExtension{Id: 0x4469, Data: []byte{0x02, 0x68, 0x32}},
			&utls.UtlsPaddingExtension{PaddingLen: 8, WillPad: true},
		},
	}
}

func TestBuildJA4StringMatchesReferenceLibrary(t *testing.T) {
	spec := ja4ReferenceSpec()
	got, err := buildJA4String(spec, 't')
	if err != nil {
		t.Fatalf("buildJA4String() error: %v", err)
	}
	var reference ja4.JA4Fingerprint
	if err := reference.Unmarshal(spec, 't'); err != nil {
		t.Fatalf("reference Unmarshal() error: %v", err)
	}
	want := reference.String()
	if got != want {
		t.Fatalf("buildJA4String() = %q, want %q", got, want)
	}
}

func TestTLSFingerprintFromClientHelloInfoMatchesReferenceLibrary(t *testing.T) {
	info := &tls.ClientHelloInfo{
		CipherSuites:    []uint16{0x0a0a, 4865, 4866, 4867, 49195},
		ServerName:      "quic.example",
		SupportedCurves: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		SupportedPoints: []uint8{0},
		SignatureSchemes: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.PSSWithSHA256,
		},
		SupportedProtos: []string{"h3", "h2"},
		SupportedVersions: []uint16{
			0x0a0a,
			tls.VersionTLS13,
			tls.VersionTLS12,
		},
		Extensions: []uint16{0x0a0a, 0, 11, 10, 35, 16, 13, 43, 45, 51, 21},
	}

	fp := TLSFingerprintFromClientHelloInfo(info, 'q')
	if fp.JA3 == "" || fp.JA3Hash == "" || fp.JA4 == "" {
		t.Fatalf("expected complete fingerprints, got %+v", fp)
	}
	if fp.TLSVersion != "TLS13" {
		t.Fatalf("TLSVersion = %q, want %q", fp.TLSVersion, "TLS13")
	}
	if fp.SNI != "quic.example" {
		t.Fatalf("SNI = %q, want %q", fp.SNI, "quic.example")
	}
	if !reflect.DeepEqual(fp.ALPN, []string{"h3", "h2"}) {
		t.Fatalf("ALPN = %+v, want %+v", fp.ALPN, []string{"h3", "h2"})
	}
	if !reflect.DeepEqual(fp.Curves, []uint16{uint16(tls.X25519), uint16(tls.CurveP256), uint16(tls.CurveP384)}) {
		t.Fatalf("Curves = %+v", fp.Curves)
	}

	var reference ja4.JA4Fingerprint
	if err := reference.Unmarshal(clientHelloInfoReferenceSpecForTest(), 'q'); err != nil {
		t.Fatalf("reference Unmarshal() error: %v", err)
	}
	if fp.JA4 != reference.String() {
		t.Fatalf("JA4 = %q, want %q", fp.JA4, reference.String())
	}
}

func clientHelloInfoReferenceSpecForTest() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			0x0a0a, 4865, 4866, 4867, 49195,
		},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{ServerName: "quic.example"},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h3", "h2"}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{utls.SignatureScheme(tls.ECDSAWithP256AndSHA256), utls.SignatureScheme(tls.PSSWithSHA256)}},
			&utls.SupportedVersionsExtension{Versions: []uint16{0x0a0a, tls.VersionTLS13, tls.VersionTLS12}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
			&utls.UtlsPaddingExtension{PaddingLen: 8, WillPad: true},
		},
	}
}

func TestJA4ExtensionIDFastPathMatchesWireID(t *testing.T) {
	for _, ext := range ja4ReferenceSpec().Extensions {
		switch ext.(type) {
		case *utls.UtlsGREASEExtension, *utls.SNIExtension, *utls.ALPNExtension:
			continue
		}

		want, err := wireJA4ExtensionIDForTest(ext)
		if err != nil {
			t.Fatalf("wireJA4ExtensionIDForTest(%T) error: %v", ext, err)
		}
		got, err := ja4ExtensionID(ext)
		if err != nil {
			t.Fatalf("ja4ExtensionID(%T) error: %v", ext, err)
		}
		if got != want {
			t.Fatalf("ja4ExtensionID(%T) = %d, want %d", ext, got, want)
		}
	}
}

func wireJA4ExtensionIDForTest(ext utls.TLSExtension) (uint16, error) {
	if padding, ok := ext.(*utls.UtlsPaddingExtension); ok {
		padding.WillPad = true
	}
	length := ext.Len()
	if length == 0 {
		return 0, errors.New("extension data should not be empty")
	}
	buf := make([]byte, length)
	n, err := ext.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	if n < 2 {
		return 0, errors.New("extension data is too short")
	}
	return uint16(buf[0])<<8 | uint16(buf[1]), nil
}

func BenchmarkBuildJA4String(b *testing.B) {
	spec := ja4ReferenceSpec()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if got, err := buildJA4String(spec, 't'); err != nil || got == "" {
			b.Fatalf("buildJA4String() = %q, %v", got, err)
		}
	}
}

func BenchmarkReferenceJA4String(b *testing.B) {
	spec := ja4ReferenceSpec()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var reference ja4.JA4Fingerprint
		if err := reference.Unmarshal(spec, 't'); err != nil {
			b.Fatalf("reference Unmarshal() error: %v", err)
		}
		if reference.String() == "" {
			b.Fatal("empty JA4")
		}
	}
}

func BenchmarkBuildJA3String(b *testing.B) {
	spec := &utls.ClientHelloSpec{
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			0x0a0a, 4865, 4866, 4867, 49195, 49199, 49196, 49200,
			52393, 52392, 49171, 49172, 156, 157, 47, 53,
		},
	}
	extensions := []uint16{0, 11, 10, 35, 16, 5, 13, 18, 23, 65281, 43, 45, 51, 21}
	curves := []uint16{0x2a2a, 29, 23, 24, 25, 256, 257}
	pointFormats := []uint8{0}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if buildJA3String(spec, extensions, curves, pointFormats) == "" {
			b.Fatal("empty JA3")
		}
	}
}

var benchmarkJA3MD5Sum [16]byte

func TestMD5SumStringMatchesBytes(t *testing.T) {
	ja3 := "772,4865-4866-4867,0-10-11-43,29-23,0-1"
	got := md5SumString(ja3)
	want := md5.Sum([]byte(ja3))
	if got != want {
		t.Fatalf("md5SumString() = %x, want %x", got, want)
	}
}

func BenchmarkMD5SumString(b *testing.B) {
	ja3 := buildJA3String(ja4ReferenceSpec(), []uint16{0, 11, 10, 35, 16, 5, 13, 18, 23, 65281, 43, 45, 51, 21}, []uint16{29, 23, 24, 25}, []uint8{0})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkJA3MD5Sum = md5SumString(ja3)
	}
}

func BenchmarkMD5SumBytes(b *testing.B) {
	ja3 := buildJA3String(ja4ReferenceSpec(), []uint16{0, 11, 10, 35, 16, 5, 13, 18, 23, 65281, 43, 45, 51, 21}, []uint16{29, 23, 24, 25}, []uint8{0})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkJA3MD5Sum = md5.Sum([]byte(ja3))
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
