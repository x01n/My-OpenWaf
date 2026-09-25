package bot

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// roundTripFunc 把普通函数包装成 http.RoundTripper，构造 fake transport。
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// geoServeBytes 起本地 httptest 源，返回 (URL, 字节数)；测试无需真实网络。
func geoServeBytes(t *testing.T, data []byte) (string, int64) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, int64(len(data))
}

// geoTestCandidates 是无锚点（Sha256 空 Size<=0）的两面候选，探针桩通过时下载前
// 不会触发网络；锚点条目才需要 sha256/尺寸。sha 与尺寸锚点必须在清单里显式写。
func geoTestCandidates() []publicGeoIPEntry {
	return []publicGeoIPEntry{
		{Filename: "fake-city.mmdb", Kind: "city", URL: "-", Sha256: "", Size: 0},
		{Filename: "fake-asn.mmdb", Kind: "asn", URL: "-", Sha256: "", Size: 0},
	}
}

func writeGeo(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

/**
 * TestEnsureGeoIPAssetsExistingKeepsPaths 验证已落盘且探针通过的资产直接被
 * 采用满足两面，且不触发任何网络请求。
 */
func TestEnsureGeoIPAssetsExistingKeepsPaths(t *testing.T) {
	dir := t.TempDir()
	originalProbe := geoIPFileProbe
	geoIPFileProbe = func(string) bool { return true }
	t.Cleanup(func() { geoIPFileProbe = originalProbe })
	writeGeo(t, filepath.Join(dir, "fake-city.mmdb"), []byte("city"))
	writeGeo(t, filepath.Join(dir, "fake-asn.mmdb"), []byte("asn"))

	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("no network request expected when assets exist")
		return nil, nil
	})}
	city, asn, _, _, failed := ensureGeoIPAssets(dir, geoTestCandidates(), geoIPFetchOptions{
		Client:   client,
		MaxBytes: 64,
	})
	if city == "" || asn == "" {
		t.Fatalf("existing assets must satisfy both facets: city=%q asn=%q", city, asn)
	}
	if len(failed) != 0 {
		t.Fatalf("existing assets must not report failures: %v", failed)
	}
}

/**
 * TestGeoIPFetchVetoedNotRemoved 验证探针桩拒绝的文件（Vetoed/OpenFailed 语义）
 * 在 AllowRemoval 关闭时被保留，且缺位侧面可以回退到第二个候选下载。
 */
func TestGeoIPFetchVetoedNotRemoved(t *testing.T) {
	dir := t.TempDir()
	originalProbe := geoIPFileProbe
	t.Cleanup(func() { geoIPFileProbe = originalProbe })

	// 第一次执行：city 文件探针被拒（模拟不可打开的库），ASN 面通过。
	probeStep := 0
	geoIPFileProbe = func(path string) bool {
		if path == "" {
			return false
		}
		name := filepath.Base(path)
		if strings.Contains(name, "tmp") {
			// 下载落地探针：city 候选全失败，asn 候选成功。
			return !strings.HasPrefix(name, ".first-city") && !strings.HasPrefix(name, ".second-city")
		}
		return name == "fake-asn.mmdb"
	}
	writeGeo(t, filepath.Join(dir, "fake-city.mmdb"), []byte("corrupt"))
	writeGeo(t, filepath.Join(dir, "fake-asn.mmdb"), []byte("ok"))

	candidates := []publicGeoIPEntry{
		{Filename: "fake-city.mmdb", Kind: "city", URL: "-", Sha256: "0f7edc57b4bf56691c42719ea9f2b0c3d44a86fc1e38f9a06c25448f2a78ff82", Size: 7},
		{Filename: "third-city.mmdb", Kind: "city", URL: "badurl://nowhere", Sha256: "", Size: 0},
		{Filename: "fake-asn.mmdb", Kind: "asn", URL: "-", Sha256: "", Size: 0},
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		probeStep++
		return nil, fmt.Errorf("no network expected")
	})}
	city, asn, specs, succeeded, failed := ensureGeoIPAssets(dir, candidates, geoIPFetchOptions{
		Client: client, MaxBytes: 64,
		// AllowRemoval 关闭：tainted 文件保留在目录。
	})
	if city != "" {
		t.Fatalf("rejected city assets must not satisfy the facet: city=%q", city)
	}
	if asn == "" {
		t.Fatalf("asn facet must be satisfied by existing file: specs=%+v succeeded=%v failed=%v", specs, succeeded, failed)
	}
	// 第一个候选 tainted 必须被报告；它按 TaintedPresent 跳过（不下载），
	// 仅备胎 third-city 发起一次下载尝试（badurl 失败）——共 1 次 HTTP 调用。
	if probeStep != 1 {
		t.Fatalf("want exactly one HTTP attempt for third-city fallback: probeStep=%d", probeStep)
	}
	if _, err := os.Stat(filepath.Join(dir, "fake-city.mmdb")); err != nil {
		t.Fatalf("AllowRemoval=false must keep vetoed file: %v", err)
	}
}

/**
 * TestTryFetchGeoIPVerifiesShaAndSize 验证下载器逐步校验:
 * sha 不匹配 -> 拒绝；尺寸不匹配 -> 拒绝；匹配 -> 落地；探针拒绝 -> 拒绝。
 */
func TestTryFetchGeoIPVerifiesShaAndSize(t *testing.T) {
	dir := t.TempDir()
	originalProbe := geoIPFileProbe
	t.Cleanup(func() { geoIPFileProbe = originalProbe })

	payload := []byte("0123456789abcdef") // 16 字节
	url, size := geoServeBytes(t, payload)
	sum := sha256Hex(payload)

	geoIPFileProbe = func(string) bool { return true }

	c := publicGeoIPEntry{Filename: "x.mmdb", URL: url, Kind: "asn",
		Sha256: strings.Repeat("b", 64), Size: size}
	path, status := tryFetchGeoIP(dir, c, geoIPFetchOptions{MaxBytes: 64})
	if path != "" || status == fetchStatusOK {
		t.Fatalf("sha mismatch must be rejected: path=%q status=%q", path, status)
	}
	if !strings.HasPrefix(status, "ShaAnchor") {
		t.Fatalf("want ShaAnchor reason, got %q", status)
	}
	if _, err := os.Stat(filepath.Join(dir, c.Filename)); err == nil {
		t.Fatalf("rejected download must not land on %s", c.Filename)
	}

	cSize := publicGeoIPEntry{Filename: "x.mmdb", URL: url, Kind: "asn", Sha256: sum, Size: size + 1}
	if path, status = tryFetchGeoIP(dir, cSize, geoIPFetchOptions{MaxBytes: 64}); path != "" || !strings.HasPrefix(status, "SizeAnchor") {
		t.Fatalf("size mismatch must be rejected: path=%q status=%q", path, status)
	}

	cOK := publicGeoIPEntry{Filename: "x.mmdb", URL: url, Kind: "asn", Sha256: sum, Size: size}
	path, status = tryFetchGeoIP(dir, cOK, geoIPFetchOptions{MaxBytes: 64})
	if status != fetchStatusOK {
		t.Fatalf("matching payload must land: status=%q", status)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != string(payload) {
		t.Fatalf("landed file mismatch: %v data=%q", err, data)
	}

	geoIPFileProbe = func(string) bool { return false }
	cProbe := publicGeoIPEntry{Filename: "x.mmdb", URL: url, Kind: "asn", Sha256: sum, Size: size}
	if path, status = tryFetchGeoIP(dir, cProbe, geoIPFetchOptions{MaxBytes: 64}); path != "" || status != "OpenFailed" {
		t.Fatalf("probe rejection must return OpenFailed: path=%q status=%q", path, status)
	}
}

/**
 * TestEnsureGeoIPAssetsFetchFallback 验证组合下载的回退路径：
 * 城市面第一候选 500 -> 第二候选成功落地；ASN 面第一候选即成功。
 */
func TestEnsureGeoIPAssetsFetchFallback(t *testing.T) {
	dir := t.TempDir()
	originalProbe := geoIPFileProbe
	t.Cleanup(func() { geoIPFileProbe = originalProbe })
	geoIPFileProbe = func(string) bool { return true }

	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	t.Cleanup(badSrv.Close)

	okPayload := []byte("mmdb")
	okURL, okSize := geoServeBytes(t, okPayload)

	candidates := []publicGeoIPEntry{
		{Filename: "first-city.mmdb", Kind: "city", URL: badSrv.URL, Sha256: "", Size: 0},
		{Filename: "second-city.mmdb", Kind: "city", URL: okURL, Sha256: "", Size: okSize},
		{Filename: "first-asn.mmdb", Kind: "asn", URL: okURL, Sha256: "", Size: okSize},
	}
	city, asn, _, _, failed := ensureGeoIPAssets(dir, candidates, geoIPFetchOptions{MaxBytes: 64})

	if city == "" || asn == "" {
		t.Fatalf("fallback download must satisfy facets: city=%q asn=%q failed=%v", city, asn, failed)
	}
	if !strings.Contains(strings.Join(failed, ","), "first-city.mmdb") {
		t.Fatalf("first candidate failure must be reported: failed=%v", failed)
	}
	if _, err := os.Stat(filepath.Join(dir, "second-city.mmdb")); err != nil {
		t.Fatalf("second candidate must land: %v", err)
	}
}
