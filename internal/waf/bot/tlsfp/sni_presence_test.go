package tlsfp

import (
	"crypto/tls"
	"testing"
)

/**
 * TestSNIPresenceFromValuesCoversAllThreeStates 覆盖存在性判定的三态口径与
 * 「已解析 ClientHello 但 JA4 缺位」这条边界。
 *
 * 口径见 sni_presence.go：JA4 的 a 段标记只在确实解析过 ClientHello 时可信。
 */
func TestSNIPresenceFromValuesCoversAllThreeStates(t *testing.T) {
	cases := []struct {
		name          string
		sni           string
		ja4           string
		hasCHMetadata bool
		want          string
	}{
		{name: "sni_present_wins_regardless_of_ja4", sni: "app.example", ja4: "", hasCHMetadata: false, want: SNIPresencePresent},
		{name: "ja4_d_marker_means_present", sni: "", ja4: "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb", hasCHMetadata: true, want: SNIPresencePresent},
		{name: "ja4_i_marker_means_absent", sni: "", ja4: "t13i1515h2_aaaaaaaaaaaa_bbbbbbbbbbbb", hasCHMetadata: true, want: SNIPresenceAbsent},
		{name: "no_metadata_stays_unknown", sni: "", ja4: "", hasCHMetadata: false, want: SNIPresenceUnknown},
		{name: "metadata_without_ja4_means_absent", sni: "", ja4: "", hasCHMetadata: true, want: SNIPresenceAbsent},
		{name: "short_ja4_without_metadata_is_unknown", sni: "", ja4: "t13", hasCHMetadata: false, want: SNIPresenceUnknown},
		{name: "short_ja4_with_metadata_is_absent", sni: "", ja4: "t13", hasCHMetadata: true, want: SNIPresenceAbsent},
		{name: "unexpected_marker_is_unknown", sni: "", ja4: "t13x1515h2_aaaaaaaaaaaa_bbbbbbbbbbbb", hasCHMetadata: true, want: SNIPresenceUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SNIPresenceFromValues(tc.sni, tc.ja4, tc.hasCHMetadata); got != tc.want {
				t.Fatalf("SNIPresenceFromValues(%q, %q, %v) = %q, want %q", tc.sni, tc.ja4, tc.hasCHMetadata, got, tc.want)
			}
		})
	}
}

/**
 * TestSNIPresenceTreatsHandshakeOnlyFingerprintAsAbsent 覆盖「只有握手信息、
 * 没有 JA4」这一形态，它是 MY_OPENWAF_H2WS_PEEKER_OFF 逃生门路径的真实产物。
 *
 * 该路径不打 ClientHello 前缀窃读，因此 JA3/JA4 恒为空；但服务端 TLS 栈仍会
 * 通过连接级握手信息回填 TLSVersion 与 ServerName。此时 SNI 名为空意味着
 * 「客户端确实没发 server_name 扩展」——因为 ServerName 正是 Go 的 crypto/tls
 * 自己从 ClientHello 读出来的（IP 字面量在 hostnameInSNI 里被显式置空）。
 *
 * 断言的是完整形态而不是单个字段：同一份形态必须判 absent，而一旦连握手信息
 * 也不存在，同一份 JA4 缺位的形态必须回落 unknown——两者对比才排除了
 * 「absent 恒成立」这种假阳性。
 */
func TestSNIPresenceTreatsHandshakeOnlyFingerprintAsAbsent(t *testing.T) {
	// 逃生门路径上 SetTLSHandshakeInfo 只写 version / sni / alpn，
	// 其余字段（JA3、JA3Hash、JA4、CipherSuites…）保持零值。
	handshakeOnly := TLSClientFingerprint{
		TLSVersion: "TLS13",
		SNI:        "",
	}
	handshakeOnly.SetNegotiatedALPN("http/1.1")

	if !handshakeOnly.HasClientHelloMetadata() {
		t.Fatal("握手上的 TLSVersion 必须被视作 ClientHello 已解析的证据")
	}
	if got := handshakeOnly.SNIPresence(); got != SNIPresenceAbsent {
		t.Fatalf("SNIPresence() = %q, want %q（JA4 为空但有握手信息）", got, SNIPresenceAbsent)
	}

	// 同形态但无握手信息：必须区分开，落在 unknown。
	noEvidence := TLSClientFingerprint{}
	if noEvidence.HasClientHelloMetadata() {
		t.Fatal("空指纹不得被视作携带 ClientHello 元数据")
	}
	if got := noEvidence.SNIPresence(); got != SNIPresenceUnknown {
		t.Fatalf("SNIPresence() = %q, want %q（无任何证据）", got, SNIPresenceUnknown)
	}
}

/**
 * TestTLSClientFingerprintSNIPresenceMatchesJA4Builder 用真实 ClientHello 验证
 * 判定与 JA4 构建器自洽：同一份字节解析出的 JA4 标记与判定结果必须一致。
 *
 * 这里刻意不引入外部夹具包——本包已有的 clientHelloRecordWithConfigForTest
 * 就是从真实握手抓下来的 ClientHello 记录。
 */
func TestTLSClientFingerprintSNIPresenceMatchesJA4Builder(t *testing.T) {
	withSNI := clientHelloRecordWithConfigForTest(t, &tls.Config{ServerName: "presence.example", NextProtos: []string{"h2"}})
	withoutSNI := clientHelloRecordWithConfigForTest(t, &tls.Config{ServerName: "127.0.0.1", NextProtos: []string{"h2"}})

	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{name: "domain_client", raw: withSNI, want: SNIPresencePresent},
		{name: "ip_literal_client", raw: withoutSNI, want: SNIPresenceAbsent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fp, err := ParseTLSClientHello(tc.raw)
			if err != nil {
				t.Fatalf("ParseTLSClientHello: %v", err)
			}
			if got := fp.SNIPresence(); got != tc.want {
				t.Fatalf("SNIPresence() = %q, want %q (ja4=%q sni=%q)", got, tc.want, fp.JA4, fp.SNI)
			}
			// 与 JA4 第 4 位标记交叉核对，确保判定不是碰巧相等。
			marker := fp.JA4[3]
			if tc.want == SNIPresencePresent && marker != 'd' {
				t.Fatalf("ja4 marker = %q, want 'd' for %s", marker, tc.name)
			}
			if tc.want == SNIPresenceAbsent && marker != 'i' {
				t.Fatalf("ja4 marker = %q, want 'i' for %s", marker, tc.name)
			}
		})
	}
}
