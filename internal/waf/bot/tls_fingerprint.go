package bot

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	utls "github.com/refraction-networking/utls"
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

	if out, err := parseTLSClientHelloRaw(record); err == nil {
		return out, nil
	}

	return parseTLSClientHelloWithUTLS(record)
}

func parseTLSClientHelloWithUTLS(record []byte) (TLSClientFingerprint, error) {
	var out TLSClientFingerprint

	spec := &utls.ClientHelloSpec{}
	if err := spec.FromRaw(record, true, false); err != nil {
		return out, err
	}

	if ja4, err := buildJA4String(spec, 't'); err == nil {
		out.JA4 = ja4
	}

	out.CipherSuites = spec.CipherSuites
	out.TLSVersion = tlsVersionString(spec.TLSVersMax)
	if out.TLSVersion == "" {
		out.TLSVersion = tlsVersionString(highestSupportedVersion(spec.Extensions))
	}

	out.Extensions = make([]uint16, 0, len(spec.Extensions))
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SNIExtension:
			out.SNI = e.ServerName
			out.Extensions = append(out.Extensions, 0)
		case *utls.ALPNExtension:
			if len(out.ALPN) == 0 {
				out.ALPN = e.AlpnProtocols
			} else {
				out.ALPN = append(out.ALPN, e.AlpnProtocols...)
			}
			out.Extensions = append(out.Extensions, 16)
		case *utls.SupportedVersionsExtension:
			out.Extensions = append(out.Extensions, 43)
		case *utls.SupportedCurvesExtension:
			if len(e.Curves) > 0 && out.Curves == nil {
				out.Curves = make([]uint16, 0, len(e.Curves))
			}
			for _, curve := range e.Curves {
				out.Curves = append(out.Curves, uint16(curve))
			}
			out.Extensions = append(out.Extensions, 10)
		case *utls.SupportedPointsExtension:
			if len(out.PointFormats) == 0 {
				out.PointFormats = e.SupportedPoints
			} else {
				out.PointFormats = append(out.PointFormats, e.SupportedPoints...)
			}
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
		sum := md5SumString(out.JA3)
		out.JA3Hash = hex.EncodeToString(sum[:])
	}
	return out, nil
}

type rawClientHello struct {
	tlsVersion        uint16
	highestVersion    uint16
	cipherSuites      []uint16
	extensions        []uint16
	curves            []uint16
	pointFormats      []uint8
	hasSNI            bool
	sni               string
	alpn              []string
	ja4ExtensionIDs   []uint16
	ja4ExtensionCount int
	signatureAlgs     []uint16
}

func parseTLSClientHelloRaw(record []byte) (TLSClientFingerprint, error) {
	raw, err := readRawClientHello(record)
	if err != nil {
		return TLSClientFingerprint{}, err
	}

	version := raw.tlsVersion
	if raw.highestVersion != 0 {
		version = raw.highestVersion
	}

	var out TLSClientFingerprint
	out.CipherSuites = raw.cipherSuites
	out.TLSVersion = tlsVersionString(version)
	out.SNI = raw.sni
	out.ALPN = raw.alpn
	out.Extensions = raw.extensions
	out.Curves = raw.curves
	out.PointFormats = raw.pointFormats
	out.JA3 = buildJA3StringWithVersion(version, raw.cipherSuites, raw.extensions, raw.curves, raw.pointFormats)
	if out.JA3 != "" {
		sum := md5SumString(out.JA3)
		out.JA3Hash = hex.EncodeToString(sum[:])
	}
	out.JA4 = buildJA4StringRaw(&raw, version)
	return out, nil
}

func readRawClientHello(record []byte) (rawClientHello, error) {
	var raw rawClientHello
	if len(record) < 9 {
		return raw, errors.New("tls record is too short")
	}
	if record[0] != 0x16 {
		return raw, errors.New("tls record is not a handshake")
	}
	recordLen := int(record[3])<<8 | int(record[4])
	if recordLen <= 0 || len(record) < 5+recordLen {
		return raw, errors.New("tls record length is invalid")
	}
	handshake := record[5 : 5+recordLen]
	if len(handshake) < 4 || handshake[0] != 0x01 {
		return raw, errors.New("tls handshake is not client hello")
	}
	helloLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if helloLen <= 0 || len(handshake) < 4+helloLen {
		return raw, errors.New("client hello length is invalid")
	}
	hello := handshake[4 : 4+helloLen]
	if len(hello) < 34 {
		return raw, errors.New("client hello body is too short")
	}

	pos := 0
	raw.tlsVersion = uint16(hello[pos])<<8 | uint16(hello[pos+1])
	pos += 2 + 32
	if pos >= len(hello) {
		return raw, errors.New("client hello missing session id")
	}
	sessionLen := int(hello[pos])
	pos++
	if len(hello) < pos+sessionLen+2 {
		return raw, errors.New("client hello session id is invalid")
	}
	pos += sessionLen

	cipherLen := int(hello[pos])<<8 | int(hello[pos+1])
	pos += 2
	if cipherLen%2 != 0 || cipherLen == 0 || len(hello) < pos+cipherLen+1 {
		return raw, errors.New("client hello cipher suites are invalid")
	}
	raw.cipherSuites = make([]uint16, 0, cipherLen/2)
	for end := pos + cipherLen; pos < end; pos += 2 {
		raw.cipherSuites = append(raw.cipherSuites, tlsFingerprintValueForRaw(uint16(hello[pos])<<8|uint16(hello[pos+1])))
	}

	compressionLen := int(hello[pos])
	pos++
	if len(hello) < pos+compressionLen {
		return raw, errors.New("client hello compression methods are invalid")
	}
	pos += compressionLen
	if pos == len(hello) {
		return raw, nil
	}
	if len(hello) < pos+2 {
		return raw, errors.New("client hello extensions length is missing")
	}
	extensionsLen := int(hello[pos])<<8 | int(hello[pos+1])
	pos += 2
	if len(hello) < pos+extensionsLen {
		return raw, errors.New("client hello extensions are invalid")
	}

	raw.extensions = make([]uint16, 0, 16)
	raw.ja4ExtensionIDs = make([]uint16, 0, 16)
	extensionsEnd := pos + extensionsLen
	for pos < extensionsEnd {
		if extensionsEnd-pos < 4 {
			return raw, errors.New("client hello extension header is invalid")
		}
		id := uint16(hello[pos])<<8 | uint16(hello[pos+1])
		extLen := int(hello[pos+2])<<8 | int(hello[pos+3])
		pos += 4
		if extensionsEnd-pos < extLen {
			return raw, errors.New("client hello extension data is invalid")
		}
		extData := hello[pos : pos+extLen]
		pos += extLen
		if isGREASE(id) {
			continue
		}

		raw.extensions = append(raw.extensions, rawUTLSExtensionID(id))
		raw.ja4ExtensionCount++
		switch id {
		case 0:
			parseRawSNI(extData, &raw)
		case 10:
			raw.curves = parseRawUint16Vector(extData, raw.curves)
			raw.ja4ExtensionIDs = append(raw.ja4ExtensionIDs, id)
		case 11:
			raw.pointFormats = parseRawUint8Vector(extData, raw.pointFormats)
			raw.ja4ExtensionIDs = append(raw.ja4ExtensionIDs, id)
		case 13:
			if len(raw.signatureAlgs) == 0 {
				raw.signatureAlgs = parseRawUint16Vector(extData, raw.signatureAlgs)
			}
			raw.ja4ExtensionIDs = append(raw.ja4ExtensionIDs, id)
		case 16:
			parseRawALPN(extData, &raw)
		case 43:
			if v := highestRawSupportedVersion(extData); v > raw.highestVersion {
				raw.highestVersion = v
			}
			raw.ja4ExtensionIDs = append(raw.ja4ExtensionIDs, id)
		default:
			raw.ja4ExtensionIDs = append(raw.ja4ExtensionIDs, id)
		}
	}
	return raw, nil
}

func parseRawSNI(data []byte, raw *rawClientHello) {
	if len(data) < 5 {
		return
	}
	listLen := int(data[0])<<8 | int(data[1])
	pos := 2
	end := pos + listLen
	if listLen <= 0 || len(data) < end {
		return
	}
	for pos+3 <= end {
		nameType := data[pos]
		nameLen := int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3
		if pos+nameLen > end {
			return
		}
		if nameType == 0 {
			raw.hasSNI = true
			raw.sni = string(data[pos : pos+nameLen])
			return
		}
		pos += nameLen
	}
}

func parseRawALPN(data []byte, raw *rawClientHello) {
	if len(data) < 2 {
		return
	}
	listLen := int(data[0])<<8 | int(data[1])
	pos := 2
	end := pos + listLen
	if listLen <= 0 || len(data) < end {
		return
	}
	protocols := raw.alpn
	for pos < end {
		nameLen := int(data[pos])
		pos++
		if nameLen == 0 || pos+nameLen > end {
			return
		}
		protocols = append(protocols, string(data[pos:pos+nameLen]))
		pos += nameLen
	}
	raw.alpn = protocols
}

func parseRawUint16Vector(data []byte, out []uint16) []uint16 {
	if len(data) < 2 {
		return out
	}
	listLen := int(data[0])<<8 | int(data[1])
	if listLen <= 0 || listLen%2 != 0 || len(data) < 2+listLen {
		return out
	}
	pos := 2
	for end := pos + listLen; pos < end; pos += 2 {
		out = append(out, tlsFingerprintValueForRaw(uint16(data[pos])<<8|uint16(data[pos+1])))
	}
	return out
}

func tlsFingerprintValueForRaw(v uint16) uint16 {
	if isGREASE(v) {
		return utls.GREASE_PLACEHOLDER
	}
	return v
}

func rawUTLSExtensionID(id uint16) uint16 {
	return id
}

func parseRawUint8Vector(data []byte, out []uint8) []uint8 {
	if len(data) < 1 {
		return out
	}
	listLen := int(data[0])
	if listLen <= 0 || len(data) < 1+listLen {
		return out
	}
	return append(out, data[1:1+listLen]...)
}

func highestRawSupportedVersion(data []byte) uint16 {
	if len(data) < 1 {
		return 0
	}
	listLen := int(data[0])
	if listLen <= 0 || listLen%2 != 0 || len(data) < 1+listLen {
		return 0
	}
	var max uint16
	for pos, end := 1, 1+listLen; pos < end; pos += 2 {
		v := uint16(data[pos])<<8 | uint16(data[pos+1])
		if !isGREASE(v) && v > max {
			max = v
		}
	}
	return max
}

func buildJA4StringRaw(raw *rawClientHello, version uint16) string {
	var b strings.Builder
	b.Grow(40)
	b.WriteByte('t')
	writeJA4TLSVersionValue(&b, version)
	if raw.hasSNI {
		b.WriteByte('d')
	} else {
		b.WriteByte('i')
	}
	writeTwoDigit(&b, countJA4CipherSuites(raw.cipherSuites))
	writeTwoDigit(&b, raw.ja4ExtensionCount)
	b.WriteString(ja4FirstALPNStrings(raw.alpn))
	ja4a := b.String()

	var cipherScratch [64]uint16
	cipherSuites := ja4CipherSuites(raw.cipherSuites, cipherScratch[:0])
	var extensionScratch [64]uint16
	extensions := append(extensionScratch[:0], raw.ja4ExtensionIDs...)
	sortUint16s(extensions)

	b.Reset()
	b.Grow(len(ja4a) + 26)
	b.WriteString(ja4a)
	b.WriteByte('_')
	writeTruncatedSHA256Hex(&b, cipherSuites, nil)
	b.WriteByte('_')
	writeTruncatedSHA256Hex(&b, extensions, raw.signatureAlgs)
	return b.String()
}

func buildJA3String(spec *utls.ClientHelloSpec, extensions []uint16, curves []uint16, pointFormats []uint8) string {
	version := spec.TLSVersMax
	if version == 0 {
		version = highestSupportedVersion(spec.Extensions)
	}

	return buildJA3StringWithVersion(version, spec.CipherSuites, extensions, curves, pointFormats)
}

func buildJA3StringWithVersion(version uint16, cipherSuites []uint16, extensions []uint16, curves []uint16, pointFormats []uint8) string {
	var stack [256]byte
	out := stack[:0]
	out = appendJA3Uint(out, uint64(version))
	out = append(out, ',')
	out = appendJA3Uint16s(out, cipherSuites, true)
	out = append(out, ',')
	out = appendJA3Uint16s(out, extensions, true)
	out = append(out, ',')
	out = appendJA3Uint16s(out, curves, true)
	out = append(out, ',')
	out = appendJA3Uint8s(out, pointFormats)
	return string(out)
}

func md5SumString(s string) [16]byte {
	if s == "" {
		var empty [0]byte
		return md5.Sum(empty[:])
	}
	return md5.Sum(unsafe.Slice(unsafe.StringData(s), len(s)))
}

func writeUint(b *strings.Builder, v uint64) {
	var buf [20]byte
	b.Write(strconv.AppendUint(buf[:0], v, 10))
}

func writeUint16s(b *strings.Builder, vals []uint16, skipGREASE bool) {
	wrote := false
	for _, v := range vals {
		if skipGREASE && isGREASE(v) {
			continue
		}
		if wrote {
			b.WriteByte('-')
		}
		writeUint(b, uint64(v))
		wrote = true
	}
}

func writeUint8s(b *strings.Builder, vals []uint8) {
	for i, v := range vals {
		if i > 0 {
			b.WriteByte('-')
		}
		writeUint(b, uint64(v))
	}
}

func appendJA3Uint(out []byte, v uint64) []byte {
	return strconv.AppendUint(out, v, 10)
}

func appendJA3Uint16s(out []byte, vals []uint16, skipGREASE bool) []byte {
	wrote := false
	for _, v := range vals {
		if skipGREASE && isGREASE(v) {
			continue
		}
		if wrote {
			out = append(out, '-')
		}
		out = appendJA3Uint(out, uint64(v))
		wrote = true
	}
	return out
}

func appendJA3Uint8s(out []byte, vals []uint8) []byte {
	for i, v := range vals {
		if i > 0 {
			out = append(out, '-')
		}
		out = appendJA3Uint(out, uint64(v))
	}
	return out
}

func buildJA4String(spec *utls.ClientHelloSpec, protocol byte) (string, error) {
	var b strings.Builder
	b.Grow(40)
	b.WriteByte(protocol)
	writeJA4TLSVersion(&b, spec)
	b.WriteByte(ja4SNI(spec))
	writeTwoDigit(&b, countJA4CipherSuites(spec.CipherSuites))
	writeTwoDigit(&b, countJA4Extensions(spec.Extensions))
	b.WriteString(ja4FirstALPN(spec.Extensions))
	ja4a := b.String()

	var cipherScratch [64]uint16
	cipherSuites := ja4CipherSuites(spec.CipherSuites, cipherScratch[:0])
	var extensionScratch [64]uint16
	extensions, err := ja4Extensions(spec.Extensions, extensionScratch[:0])
	if err != nil {
		return "", err
	}
	var signatureAlgorithmScratch [32]uint16
	signatureAlgorithms := ja4SignatureAlgorithms(spec.Extensions, signatureAlgorithmScratch[:0])

	b.Reset()
	b.Grow(len(ja4a) + 26)
	b.WriteString(ja4a)
	b.WriteByte('_')
	writeTruncatedSHA256Hex(&b, cipherSuites, nil)
	b.WriteByte('_')
	writeTruncatedSHA256Hex(&b, extensions, signatureAlgorithms)
	return b.String(), nil
}

func writeJA4TLSVersion(b *strings.Builder, spec *utls.ClientHelloSpec) {
	version := spec.TLSVersMax
	if version == 0 {
		version = highestSupportedVersion(spec.Extensions)
	}
	writeJA4TLSVersionValue(b, version)
}

func writeJA4TLSVersionValue(b *strings.Builder, version uint16) {
	switch version {
	case utls.VersionTLS10:
		b.WriteString("10")
	case utls.VersionTLS11:
		b.WriteString("11")
	case utls.VersionTLS12:
		b.WriteString("12")
	case utls.VersionTLS13:
		b.WriteString("13")
	default:
		b.WriteString("00")
	}
}

func ja4SNI(spec *utls.ClientHelloSpec) byte {
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*utls.SNIExtension); ok {
			return 'd'
		}
	}
	return 'i'
}

func countJA4CipherSuites(cipherSuites []uint16) int {
	count := 0
	for _, suite := range cipherSuites {
		if !isGREASE(suite) {
			count++
		}
	}
	return count
}

func countJA4Extensions(exts []utls.TLSExtension) int {
	count := 0
	for _, ext := range exts {
		if _, ok := ext.(*utls.UtlsGREASEExtension); ok {
			continue
		}
		count++
	}
	return count
}

func writeTwoDigit(b *strings.Builder, n int) {
	if n > 99 {
		n = 99
	}
	if n < 10 {
		b.WriteByte('0')
	}
	writeUint(b, uint64(n))
}

func ja4FirstALPN(exts []utls.TLSExtension) string {
	for _, ext := range exts {
		alpnExt, ok := ext.(*utls.ALPNExtension)
		if !ok || len(alpnExt.AlpnProtocols) == 0 {
			continue
		}
		return ja4FirstALPNStrings(alpnExt.AlpnProtocols)
	}
	return "00"
}

func ja4FirstALPNStrings(protocols []string) string {
	if len(protocols) == 0 {
		return "00"
	}
	alpn := protocols[0]
	if alpn == "" {
		return "00"
	}
	if len(alpn) > 2 {
		alpn = string(alpn[0]) + string(alpn[len(alpn)-1])
	}
	if alpn[0] > 127 {
		return "99"
	}
	return alpn
}

func ja4CipherSuites(cipherSuites []uint16, out []uint16) []uint16 {
	out = out[:0]
	for _, suite := range cipherSuites {
		if !isGREASE(suite) {
			out = append(out, suite)
		}
	}
	sortUint16s(out)
	return out
}

func sortUint16s(vals []uint16) {
	for i := 1; i < len(vals); i++ {
		v := vals[i]
		j := i - 1
		for j >= 0 && vals[j] > v {
			vals[j+1] = vals[j]
			j--
		}
		vals[j+1] = v
	}
}

func ja4Extensions(exts []utls.TLSExtension, out []uint16) ([]uint16, error) {
	out = out[:0]
	for _, ext := range exts {
		if _, ok := ext.(*utls.UtlsGREASEExtension); ok {
			continue
		}
		if _, ok := ext.(*utls.SNIExtension); ok {
			continue
		}
		if _, ok := ext.(*utls.ALPNExtension); ok {
			continue
		}
		id, err := ja4ExtensionID(ext)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	sortUint16s(out)
	return out, nil
}

func ja4ExtensionID(ext utls.TLSExtension) (uint16, error) {
	switch e := ext.(type) {
	case *utls.GenericExtension:
		return e.Id, nil
	case *utls.SupportedVersionsExtension:
		return 43, nil
	case *utls.SupportedCurvesExtension:
		return 10, nil
	case *utls.SupportedPointsExtension:
		return 11, nil
	case *utls.SignatureAlgorithmsExtension:
		return 13, nil
	case *utls.UtlsPaddingExtension:
		e.WillPad = true
		return 21, nil
	case *utls.StatusRequestExtension:
		return 5, nil
	case *utls.SessionTicketExtension:
		return 35, nil
	case *utls.ExtendedMasterSecretExtension:
		return 23, nil
	case *utls.RenegotiationInfoExtension:
		return 65281, nil
	case *utls.KeyShareExtension:
		return 51, nil
	case *utls.PSKKeyExchangeModesExtension:
		return 45, nil
	case *utls.SignatureAlgorithmsCertExtension:
		return 50, nil
	case *utls.ApplicationSettingsExtension:
		return 17513, nil
	case *utls.ApplicationSettingsExtensionNew:
		return 17613, nil
	case *utls.SCTExtension:
		return 18, nil
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

func ja4SignatureAlgorithms(exts []utls.TLSExtension, out []uint16) []uint16 {
	for _, ext := range exts {
		sig, ok := ext.(*utls.SignatureAlgorithmsExtension)
		if !ok {
			continue
		}
		out = out[:0]
		for _, alg := range sig.SupportedSignatureAlgorithms {
			out = append(out, uint16(alg))
		}
		return out
	}
	return nil
}

func writeTruncatedSHA256Hex(b *strings.Builder, first []uint16, second []uint16) {
	inputLen := ja4Uint16sHexLen(first)
	if len(second) > 0 {
		inputLen += 1 + ja4Uint16sHexLen(second)
	}

	var stack [256]byte
	input := stack[:0]
	if inputLen > cap(input) {
		input = make([]byte, 0, inputLen)
	}
	input = appendJA4Uint16sHex(input, first)
	if len(second) > 0 {
		input = append(input, '_')
		input = appendJA4Uint16sHex(input, second)
	}

	sum := sha256.Sum256(input)
	const hexChars = "0123456789abcdef"
	for i := 0; i < 6; i++ {
		b.WriteByte(hexChars[sum[i]>>4])
		b.WriteByte(hexChars[sum[i]&0x0f])
	}
}

func ja4Uint16sHexLen(vals []uint16) int {
	if len(vals) == 0 {
		return 0
	}
	return len(vals)*4 + len(vals) - 1
}

func appendJA4Uint16sHex(dst []byte, vals []uint16) []byte {
	const hexChars = "0123456789abcdef"
	for i, v := range vals {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst,
			hexChars[(v>>12)&0x0f],
			hexChars[(v>>8)&0x0f],
			hexChars[(v>>4)&0x0f],
			hexChars[v&0x0f],
		)
	}
	return dst
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
	id, err := ja4ExtensionID(ext)
	if err != nil {
		return 0
	}
	return id
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
	var b strings.Builder
	b.Grow(len(vals) * 6)
	writeUint16s(&b, vals, false)
	return b.String()
}

func joinUint8s(vals []uint8) string {
	if len(vals) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(vals) * 4)
	writeUint8s(&b, vals)
	return b.String()
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
