package waf

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	fpMaxEntries    = 100000
	fpCleanInterval = 60 * time.Second
	fpEntryTTL      = 5 * time.Minute
)

// TLSFingerprinter captures JA3-style fingerprints from TLS handshakes.
type TLSFingerprinter struct {
	mu      sync.RWMutex
	entries map[string]*tlsEntry
	closed  atomic.Bool
}

type tlsEntry struct {
	info    *TLSClientInfo
	created time.Time
}

// TLSClientInfo holds fingerprint data extracted from a TLS ClientHello.
type TLSClientInfo struct {
	JA3Hash     string
	JA3Raw      string
	TLSVersion  uint16
	CipherCount int
	HasSNI      bool
	ServerName  string
	ALPNProtos  []string
}

// NewTLSFingerprinter creates a new fingerprinter instance.
func NewTLSFingerprinter() *TLSFingerprinter {
	fp := &TLSFingerprinter{
		entries: make(map[string]*tlsEntry, 1024),
	}
	go fp.cleanupLoop()
	return fp
}

// Close stops the cleanup goroutine.
func (fp *TLSFingerprinter) Close() {
	fp.closed.Store(true)
}

// WrapTLSConfig wraps a tls.Config to capture ClientHello fingerprints.
func (fp *TLSFingerprinter) WrapTLSConfig(orig *tls.Config) *tls.Config {
	if orig == nil {
		return nil
	}
	wrapped := orig.Clone()
	origCallback := orig.GetConfigForClient
	wrapped.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		fp.recordHello(hello)
		if origCallback != nil {
			return origCallback(hello)
		}
		return nil, nil
	}
	return wrapped
}

// Lookup retrieves the TLS fingerprint for a given remote IP.
func (fp *TLSFingerprinter) Lookup(remoteIP string) *TLSClientInfo {
	fp.mu.RLock()
	e, ok := fp.entries[remoteIP]
	fp.mu.RUnlock()
	if !ok {
		return nil
	}
	return e.info
}

func (fp *TLSFingerprinter) recordHello(hello *tls.ClientHelloInfo) {
	if hello == nil || hello.Conn == nil {
		return
	}
	remoteIP := extractIP(hello.Conn.RemoteAddr())
	if remoteIP == "" {
		return
	}

	info := &TLSClientInfo{
		CipherCount: len(hello.CipherSuites),
		HasSNI:      hello.ServerName != "",
		ServerName:  hello.ServerName,
		ALPNProtos:  hello.SupportedProtos,
	}

	// Determine TLS version from supported versions.
	if len(hello.SupportedVersions) > 0 {
		info.TLSVersion = hello.SupportedVersions[0]
		for _, v := range hello.SupportedVersions {
			if v > info.TLSVersion {
				info.TLSVersion = v
			}
		}
	}

	info.JA3Raw = computeJA3Raw(hello)
	hash := md5.Sum([]byte(info.JA3Raw))
	info.JA3Hash = fmt.Sprintf("%x", hash)

	fp.mu.Lock()
	fp.entries[remoteIP] = &tlsEntry{info: info, created: time.Now()}
	fp.mu.Unlock()
}

func (fp *TLSFingerprinter) cleanupLoop() {
	ticker := time.NewTicker(fpCleanInterval)
	defer ticker.Stop()
	for range ticker.C {
		if fp.closed.Load() {
			return
		}
		fp.evict()
	}
}

func (fp *TLSFingerprinter) evict() {
	now := time.Now()
	fp.mu.Lock()
	defer fp.mu.Unlock()

	// Time-based eviction: remove entries older than TTL.
	for ip, e := range fp.entries {
		if now.Sub(e.created) > fpEntryTTL {
			delete(fp.entries, ip)
		}
	}

	// Size-based eviction: if still too large, drop oldest entries.
	if len(fp.entries) > fpMaxEntries {
		oldest := now
		var oldestKey string
		for ip, e := range fp.entries {
			if e.created.Before(oldest) {
				oldest = e.created
				oldestKey = ip
			}
		}
		if oldestKey != "" {
			delete(fp.entries, oldestKey)
		}
	}
}

func computeJA3Raw(hello *tls.ClientHelloInfo) string {
	var parts [5]string

	maxVer := uint16(0)
	for _, v := range hello.SupportedVersions {
		if v > maxVer {
			maxVer = v
		}
	}
	parts[0] = strconv.FormatUint(uint64(maxVer), 10)

	ciphers := make([]string, 0, len(hello.CipherSuites))
	for _, c := range hello.CipherSuites {
		if !isGREASE(uint16(c)) {
			ciphers = append(ciphers, strconv.FormatUint(uint64(c), 10))
		}
	}
	parts[1] = strings.Join(ciphers, "-")

	var exts []string
	if hello.ServerName != "" {
		exts = append(exts, "0")
	}
	if len(hello.SupportedProtos) > 0 {
		exts = append(exts, "16")
	}
	if len(hello.SupportedVersions) > 0 {
		exts = append(exts, "43")
	}
	if len(hello.SignatureSchemes) > 0 {
		exts = append(exts, "13")
	}
	if len(hello.SupportedCurves) > 0 {
		exts = append(exts, "10")
	}
	if len(hello.SupportedPoints) > 0 {
		exts = append(exts, "11")
	}
	sort.Strings(exts)
	parts[2] = strings.Join(exts, "-")

	curves := make([]string, 0, len(hello.SupportedCurves))
	for _, c := range hello.SupportedCurves {
		if !isGREASE(uint16(c)) {
			curves = append(curves, strconv.FormatUint(uint64(c), 10))
		}
	}
	parts[3] = strings.Join(curves, "-")

	points := make([]string, 0, len(hello.SupportedPoints))
	for _, p := range hello.SupportedPoints {
		points = append(points, strconv.FormatUint(uint64(p), 10))
	}
	parts[4] = strings.Join(points, "-")

	return strings.Join(parts[:], ",")
}

func isGREASE(val uint16) bool {
	return (val&0x0f0f) == 0x0a0a && (val>>8) == (val&0xff)
}

func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

var globalFingerprinter *TLSFingerprinter

func SetTLSFingerprinter(fp *TLSFingerprinter) { globalFingerprinter = fp }
func GetTLSFingerprinter() *TLSFingerprinter    { return globalFingerprinter }

// LookupTLSFingerprint retrieves the JA3 hash for a remote IP from the global fingerprinter.
func LookupTLSFingerprint(remoteIP string) string {
	if globalFingerprinter == nil {
		return ""
	}
	info := globalFingerprinter.Lookup(remoteIP)
	if info == nil {
		return ""
	}
	return info.JA3Hash
}
