package bot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type publicGeoIPEntry struct {
	Filename string // 落地文件名，唯一标识
	URL      string // 固定下载地址
	Kind     string // city / asn / country
	Sha256   string // 实抓样本 sha256 hex，逐字节校验
	Size     int64  // 实抓样本字节数
}

func geoIPCandidates() []publicGeoIPEntry {
	return []publicGeoIPEntry{
		{
			Filename: "GeoLite2-City.mmdb",
			URL:      "https://ip.adysec.com/GeoLite2-City.mmdb",
			Kind:     "city", Sha256: "", Size: -1,
		},
		{
			Filename: "GeoLite2-Country.mmdb",
			URL:      "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb",
			Kind:     "country",
			Sha256:   "7ca6753b093a69441a5e9185f498ee1e767c24ef6c0915494d1f68090cca032d",
			Size:     8514483,
		},
		{
			Filename: "dbip-asn-lite.mmdb",
			URL:      "https://ip.adysec.com/db-ip/dbip-asn-lite.mmdb",
			Kind:     "asn",
			Sha256:   "0108423d4e7a8fce56fd11b177b8d8835b7202f7bb821490e4cd3ca5fb482dbe",
			Size:     6772963,
		},
		{
			Filename: "dbip-country-lite.mmdb",
			URL:      "https://ip.adysec.com/db-ip/dbip-country-lite.mmdb",
			Kind:     "country",
			Sha256:   "b98568cef7cee1a588c9c78a9db02936c4a4d94f20aff7629da22c74563b0f5b",
			Size:     3563355,
		},
	}
}

// GeoIPMember 聚合一次自举的结论，供调用方与测试挑拣路径。
// 组合按功能面划分：城市面（city/country）与 ASN 面，任一面可用即提供对应路径。
type GeoIPMember struct {
	CityPath  string // 城市面库路径（"" 表示该面不可用）
	ASNPath   string // ASN 面库路径（"" 表示该面不可用）
	Specs     []geoIPEntrySpec
	Succeeded []string
	Failed    []string
}

// GeoIPBootstrap 是启动时自动下载的入口钩子。
//
// 语义：
//   - explicitPath（MY_OPENWAF_GEOIP_DB）非空且文件存在：直接以该文件同时满足
//     城市/ASN 两面（当前 MaxMindResolver 对显式路径的既有语义），自举不做任何事；
//   - 否则在 dataDir/geoip 下执行 ensureGeoIPAssets 自举。
//
// 任何失败都不致命：失败仅告警并返回空路径，绝不阻塞启动。
func GeoIPBootstrap(explicitPath, dataDir string) *GeoIPMember {
	if explicitPath != "" {
		if fi, err := os.Stat(explicitPath); err == nil && fi.Mode().IsRegular() {
			return &GeoIPMember{CityPath: explicitPath, ASNPath: explicitPath}
		}
		slog.Warn("geoip: explicit database missing, fall back to auto-download",
			"path", explicitPath)
	}
	dir := filepath.Join(dataDir, "geoip")
	city, asn, specs, succeeded, failed := ensureGeoIPAssets(dir, geoIPCandidates(), geoIPFetchOptions{})
	return &GeoIPMember{CityPath: city, ASNPath: asn, Specs: specs, Succeeded: succeeded, Failed: failed}
}

// geoIPFetchOptions 控制 ensureGeoIPAssets 在一次运行里的行为。
type geoIPFetchOptions struct {
	Client       *http.Client // nil => 20s 全链路超时的默认客户端
	AllowRemoval bool         // 为 true 时，分诊异常的治理文件会被删除后重新下载
	MaxBytes     int64        // 单文件最大接受字节数，<=0 => geoipMaxDownloadBytes
}

// geoipMaxDownloadBytes 是单文件下载上限；超过视为源异常直接拒绝。
const geoipMaxDownloadBytes = 16 << 20

// geoIPEntrySpec 记录一条候选的处置结论，供启动告警与测试断言使用。
type geoIPEntrySpec struct {
	Filename string // 候选 Filename
	URL      string
	Kind     string
	Status   string // Kept / Tainted / Fetched / Failed / Skipped
	Reason   string // Status 的具体原因
}

func reportGeoIPBootstrap(msg string, specs []geoIPEntrySpec, succeeded, failed []string) {
	sort.Strings(succeeded)
	sort.Strings(failed)
	slog.Warn("geoip auto-download", slog.String("msg", msg),
		slog.String("succeeded", strings.Join(succeeded, ",")),
		slog.String("failed", strings.Join(failed, ",")),
		slog.String("details", geoEntrySpecReport(specs)))
}

func geoEntrySpecReport(specs []geoIPEntrySpec) string {
	parts := make([]string, 0, len(specs))
	for _, s := range specs {
		parts = append(parts, fmt.Sprintf("%s[%s:%s]", s.Filename, s.Status, s.Reason))
	}
	return strings.Join(parts, "; ")
}

func ensureGeoIPAssets(dir string, candidates []publicGeoIPEntry, opts geoIPFetchOptions) (cityPath, asnPath string, specs []geoIPEntrySpec, succeeded, failed []string) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = geoipMaxDownloadBytes
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 20 * time.Second}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		specs = append(specs, geoIPEntrySpec{Filename: "-", URL: "-", Kind: "-", Status: "Failed", Reason: "NoAssetDir"})
		reportGeoIPBootstrap("cannot create asset directory", specs, succeeded, failed)
		return "", "", specs, succeeded, failed
	}
	kept, anomalies := triageExistingGeoIPAssets(dir, candidates, opts.MaxBytes)
	tainted := make(map[string]bool, len(anomalies))
	for _, a := range anomalies {
		specs = append(specs, a.spec)
		failed = append(failed, a.Filename)
		tainted[a.Filename] = true
		if opts.AllowRemoval {
			_ = os.Remove(filepath.Join(dir, a.Filename))
			delete(tainted, a.Filename) // 删除后可按锚点重新下载
		}
	}
	cityPath, asnPath, succeeded = chooseKeptGeoIPAssets(dir, kept, candidates)

	fetchGroup := func(kind string, slot *string) {
		if *slot != "" {
			return
		}
		path, groupSpecs, failedNames, hasSucceeded := fetchGeoIPGroup(dir, kind, candidates, kept, tainted, opts)
		specs = append(specs, groupSpecs...)
		failed = append(failed, failedNames...)
		if hasSucceeded {
			*slot = path
			succeeded = append(succeeded, filepath.Base(path))
		}
	}
	fetchGroup(kindCity, &cityPath)
	fetchGroup(kindASN, &asnPath)

	sort.Strings(succeeded)
	sort.Strings(failed)
	reportGeoIPBootstrap("city/asn bootstrap attempt finished", specs, succeeded, failed)
	return cityPath, asnPath, specs, succeeded, failed
}

// kindCity / kindASN 是功能面名，不直接对应文件名。
const (
	kindCity = "city"
	kindASN  = "asn"
)

// triageAnomaly 是本地资产分诊的异常结论。
type triageAnomaly struct {
	Filename string
	spec     geoIPEntrySpec
}

// triageExistingGeoIPAssets 分诊目录里的自举治理文件。
// 返回 (kept: filename -> entry, anomalies)。
func triageExistingGeoIPAssets(dir string, candidates []publicGeoIPEntry, maxBytes int64) (map[string]publicGeoIPEntry, []triageAnomaly) {
	kept := make(map[string]publicGeoIPEntry)
	var anomalies []triageAnomaly
	byFile := make(map[string]publicGeoIPEntry, len(candidates))
	for _, c := range candidates {
		byFile[c.Filename] = c
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return kept, anomalies
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		candidate, known := byFile[name]
		if !known {
			continue // 非清单治理文件（如用户手工放置），不评估不替换
		}
		path := filepath.Join(dir, name)
		fi, infoErr := e.Info()
		if infoErr != nil || !fi.Mode().IsRegular() {
			anomalies = append(anomalies, triageAnomaly{Filename: name,
				spec: geoIPEntrySpec{Filename: name, URL: candidate.URL, Kind: candidate.Kind, Status: "Tainted", Reason: "NotRegular"}})
			continue
		}
		if fi.Size() > maxBytes {
			anomalies = append(anomalies, triageAnomaly{Filename: name,
				spec: geoIPEntrySpec{Filename: name, URL: candidate.URL, Kind: candidate.Kind, Status: "Tainted", Reason: "Oversize"}})
			continue
		}
		if candidate.Sha256 != "" || candidate.Size > 0 {
			sum, ok := fileSha256Hex(path)
			if !ok || !strings.EqualFold(sum, candidate.Sha256) || fi.Size() != candidate.Size {
				reason := "ShaAnchored"
				if ok && strings.EqualFold(sum, candidate.Sha256) && fi.Size() != candidate.Size {
					reason = "SizeAnchored"
				}
				anomalies = append(anomalies, triageAnomaly{Filename: name,
					spec: geoIPEntrySpec{Filename: name, URL: candidate.URL, Kind: candidate.Kind, Status: "Tainted", Reason: reason}})
				continue
			}
		}
		if !geoIPFileProbe(path) {
			anomalies = append(anomalies, triageAnomaly{Filename: name,
				spec: geoIPEntrySpec{Filename: name, URL: candidate.URL, Kind: candidate.Kind, Status: "Tainted", Reason: "OpenFailed"}})
			continue
		}
		kept[name] = candidate
	}
	return kept, anomalies
}

// fileSha256Hex 返回文件的 sha256 hex；失败返回 (ok=false)。
func fileSha256Hex(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// chooseKeptGeoIPAssets 按清单顺序挑两个功能面的已接受文件。
// 城市面包含 Kind 为 city 或 country 的候选。
func chooseKeptGeoIPAssets(dir string, kept map[string]publicGeoIPEntry, candidates []publicGeoIPEntry) (cityPath, asnPath string, succeeded []string) {
	for _, c := range candidates {
		entry, ok := kept[c.Filename]
		if !ok {
			continue
		}
		path := filepath.Join(dir, c.Filename)
		switch entry.Kind {
		case "asn":
			if asnPath == "" {
				asnPath = path
				succeeded = append(succeeded, c.Filename)
			}
		case "city", "country":
			if cityPath == "" {
				cityPath = path
				succeeded = append(succeeded, c.Filename)
			}
		}
	}
	return cityPath, asnPath, succeeded
}

// fetchGeoIPGroup 为缺位的功能面按清单顺序依次下载候选，首个成功即止。
// tainted 映射中的文件是分诊异常但未被 AllowRemoval 删除的：不会重试下载
// 它的网络目标（否则会覆盖用户可见文件），只记 Skipped 并继续下一候选。
// 返回 (path, specs, failedNames, hasSucceeded)；失败候选记 Failed，其余记 Skipped。
func fetchGeoIPGroup(dir, kind string, candidates []publicGeoIPEntry, kept map[string]publicGeoIPEntry, tainted map[string]bool, opts geoIPFetchOptions) (successPath string, specs []geoIPEntrySpec, failedNames []string, hasSucceeded bool) {
	for _, c := range candidates {
		if !geoIPKindInGroup(c.Kind, kind) {
			continue
		}
		if _, exists := kept[c.Filename]; exists {
			continue // 该文件此前被接受过，理论上该面已满足；防御性跳过
		}
		if tainted[c.Filename] {
			specs = append(specs, geoIPEntrySpec{
				Filename: c.Filename, URL: c.URL, Kind: c.Kind, Status: "Skipped", Reason: "TaintedPresent",
			})
			continue
		}
		path, status := tryFetchGeoIP(dir, c, opts)
		if status == fetchStatusOK {
			return path, specs, failedNames, true
		}
		specs = append(specs, geoIPEntrySpec{
			Filename: c.Filename, URL: c.URL, Kind: c.Kind, Status: "Failed", Reason: status,
		})
		failedNames = append(failedNames, c.Filename)
	}
	// 无可试候选或全部失败。
	return "", specs, failedNames, false
}

func geoIPKindInGroup(kind, group string) bool {
	if group == kindASN {
		return kind == "asn"
	}
	return kind == "city" || kind == "country"
}

// tryFetchGeoIP 下载候选到临时文件，逐字节校验 sha256/尺寸，通过后原子改名。
// 返回 (status == fetchStatusOK 时的文件路径, 状态码或失败原因文本)。
func tryFetchGeoIP(dir string, c publicGeoIPEntry, opts geoIPFetchOptions) (filePath, status string) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = geoipMaxDownloadBytes
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 20 * time.Second}
	}
	tmp := filepath.Join(dir, "."+c.Filename+".tmp")
	req, err := http.NewRequest(http.MethodGet, c.URL, nil)
	if err != nil {
		return "", fmt.Sprintf("HTTPRequestFailed:%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := opts.Client.Do(req.WithContext(ctx))
	if err != nil {
		return "", "HTTPConnectFailed:" + err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	tf, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", "TempCreateFailed"
	}
	n, err := io.Copy(tf, io.LimitReader(resp.Body, opts.MaxBytes+1))
	if err != nil {
		_ = tf.Close()
		_ = os.Remove(tmp)
		return "", "HTTPBodyReadFailed:" + err.Error()
	}
	if n > opts.MaxBytes {
		_ = tf.Close()
		_ = os.Remove(tmp)
		return "", fmt.Sprintf("Oversize:%d", n)
	}
	if err := tf.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", "TempCloseFailed"
	}
	if c.Size > 0 && n != c.Size {
		_ = os.Remove(tmp)
		return "", fmt.Sprintf("SizeAnchor:%d", n)
	}
	if c.Sha256 != "" {
		sum, ok := fileSha256Hex(tmp)
		if !ok || !strings.EqualFold(sum, c.Sha256) {
			_ = os.Remove(tmp)
			return "", "ShaAnchorMismatch"
		}
	}
	if !geoIPFileProbe(tmp) {
		_ = os.Remove(tmp)
		return "", "OpenFailed"
	}
	if err := os.Rename(tmp, filepath.Join(dir, c.Filename)); err != nil {
		_ = os.Remove(tmp)
		return "", "RenameFailed"
	}
	return filepath.Join(dir, c.Filename), fetchStatusOK
}

const fetchStatusOK = "OK"

// geoIPFileProbe 验证文件可被 maxminddb 打开；测试可替换为 stub。
// 保持注入式的原因：最小的合法 mmdb 也必须携带与 ip_version 匹配的完整
// 搜索树（百 MB 级），无法在测试中合成小样本。
var geoIPFileProbe = func(path string) bool {
	db, err := maxminddb.Open(path)
	if err != nil {
		return false
	}
	_ = db.Close()
	return true
}
