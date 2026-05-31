package bot

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"
	ja4 "github.com/wu238121-a11y/go-ja4"
)

type TLSClientFingerprint struct {
	JA3          string
	JA3Hash      string
	JA4          string
	TLSVersion   string
	SNI          string
	ALPN         []string
	CipherSuites []uint16
	Extensions   []uint16
	Curves       []uint16
	PointFormats []uint8
}

func ParseTLSClientHello(record []byte) (TLSClientFingerprint, error) {
	var out TLSClientFingerprint
	if len(record) == 0 {
		return out, nil
	}

	spec := &utls.ClientHelloSpec{}
	if err := spec.FromRaw(record, true, false); err != nil {
		return out, err
	}

	var fp ja4.JA4Fingerprint
	if err := fp.Unmarshal(spec, 't'); err == nil {
		out.JA4 = fp.String()
	}

	out.CipherSuites = append(out.CipherSuites, spec.CipherSuites...)
	out.TLSVersion = tlsVersionString(spec.TLSVersMax)
	if out.TLSVersion == "" {
		out.TLSVersion = tlsVersionString(highestSupportedVersion(spec.Extensions))
	}

	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SNIExtension:
			out.SNI = e.ServerName
			out.Extensions = append(out.Extensions, 0)
		case *utls.ALPNExtension:
			out.ALPN = append(out.ALPN, e.AlpnProtocols...)
			out.Extensions = append(out.Extensions, 16)
		case *utls.SupportedVersionsExtension:
			out.Extensions = append(out.Extensions, 43)
		case *utls.SupportedCurvesExtension:
			for _, curve := range e.Curves {
				out.Curves = append(out.Curves, uint16(curve))
			}
			out.Extensions = append(out.Extensions, 10)
		case *utls.SupportedPointsExtension:
			out.PointFormats = append(out.PointFormats, e.SupportedPoints...)
			out.Extensions = append(out.Extensions, 11)
		case *utls.SignatureAlgorithmsExtension:
			out.Extensions = append(out.Extensions, 13)
		case *utls.UtlsPaddingExtension:
			out.Extensions = append(out.Extensions, 21)
		case *utls.UtlsGREASEExtension:
			continue
		default:
			out.Extensions = append(out.Extensions, extensionID(ext))
		}
	}

	out.JA3 = buildJA3String(spec, out.Extensions, out.Curves, out.PointFormats)
	if out.JA3 != "" {
		sum := md5.Sum([]byte(out.JA3))
		out.JA3Hash = hex.EncodeToString(sum[:])
	}
	return out, nil
}

func buildJA3String(spec *utls.ClientHelloSpec, extensions []uint16, curves []uint16, pointFormats []uint8) string {
	version := spec.TLSVersMax
	if version == 0 {
		version = highestSupportedVersion(spec.Extensions)
	}
	return strings.Join([]string{
		fmt.Sprintf("%d", version),
		joinUint16s(filterGREASE(spec.CipherSuites)),
		joinUint16s(filterGREASE(extensions)),
		joinUint16s(filterGREASE(curves)),
		joinUint8s(pointFormats),
	}, ",")
}

func highestSupportedVersion(exts []utls.TLSExtension) uint16 {
	var max uint16
	for _, ext := range exts {
		if e, ok := ext.(*utls.SupportedVersionsExtension); ok {
			for _, v := range e.Versions {
				if !isGREASE(v) && v > max {
					max = v
				}
			}
		}
	}
	return max
}

func extensionID(ext utls.TLSExtension) uint16 {
	switch e := ext.(type) {
	case *utls.GenericExtension:
		return e.Id
	case *utls.StatusRequestExtension:
		return 5
	case *utls.SessionTicketExtension:
		return 35
	case *utls.ExtendedMasterSecretExtension:
		return 23
	case *utls.RenegotiationInfoExtension:
		return 65281
	case *utls.KeyShareExtension:
		return 51
	case *utls.PSKKeyExchangeModesExtension:
		return 45
	case *utls.SignatureAlgorithmsCertExtension:
		return 50
	case *utls.ApplicationSettingsExtension:
		return 17513
	case *utls.ApplicationSettingsExtensionNew:
		return 17613
	case *utls.SCTExtension:
		return 18
	}
	return 0
}

func filterGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

func joinUint16s(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, fmt.Sprintf("%d", v))
	}
	return strings.Join(parts, "-")
}

func joinUint8s(vals []uint8) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, fmt.Sprintf("%d", v))
	}
	return strings.Join(parts, "-")
}

func tlsVersionString(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS10"
	case 0x0302:
		return "TLS11"
	case 0x0303:
		return "TLS12"
	case 0x0304:
		return "TLS13"
	default:
		return ""
	}
}

func headerOrderScore(r BotRequest) (int, []string) {
	if len(r.HeaderKeys) == 0 {
		return 0, nil
	}
	lower := make([]string, 0, len(r.HeaderKeys))
	for _, key := range r.HeaderKeys {
		lower = append(lower, strings.ToLower(strings.TrimSpace(key)))
	}
	score := 0
	var reasons []string
	if sort.StringsAreSorted(append([]string(nil), lower...)) && len(lower) >= 5 {
		score += 8
		reasons = append(reasons, "alphabetic_header_order")
	}
	if containsHeader(lower, "user-agent") && containsHeader(lower, "host") && indexHeader(lower, "user-agent") < indexHeader(lower, "host") {
		score += 6
		reasons = append(reasons, "ua_before_host")
	}
	return score, reasons
}

func containsHeader(keys []string, target string) bool { return indexHeader(keys, target) >= 0 }

func indexHeader(keys []string, target string) int {
	for i, key := range keys {
		if key == target {
			return i
		}
	}
	return -1
}
