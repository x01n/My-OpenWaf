package owasp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// owaspCorpusDir 是 blazehttp 全语料的位置（相对本包 = internal/waf/owasp）。
// 目录不存在时整组用例 Skip —— 语料是本地 gitignored 资产，CI 不带。
const owaspCorpusDir = "../../../temp/testcases"

// fpGoldenPath 是本测试口径下的误报指纹快照。
const fpGoldenPath = "testdata/blazehttp_fp_golden.txt"

type corpusRequest struct {
	path    string
	query   string
	headers map[string]string
	body    []string
}

// loadOWASPCorpus 读取语料目录下全部 .white/.black 原始 HTTP 报文。
func loadOWASPCorpus(tb testing.TB) (whites []corpusRequest, blacks []corpusRequest, parseErr int) {
	tb.Helper()
	dir := os.Getenv("OWASP_GOLDEN_CORPUS")
	if dir == "" {
		dir = owaspCorpusDir
	}
	if _, err := os.Stat(dir); err != nil {
		tb.Skipf("语料目录不存在,跳过: %s", dir)
	}
	// filepath.Walk 用 Lstat 判定根目录，符号链接根会被当作普通文件跳过；
	// 先解出真实路径，语料目录可以用符号链接挂载。
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	var files []string
	if err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".white") || strings.HasSuffix(p, ".black") {
			files = append(files, p)
		}
		return nil
	}); err != nil {
		tb.Skipf("语料目录遍历失败: %v", err)
	}
	sort.Strings(files)
	for _, f := range files {
		req, ok := parseRawHTTPForOWASP(f)
		if !ok {
			parseErr++
			continue
		}
		if strings.HasSuffix(f, ".black") {
			blacks = append(blacks, req)
		} else {
			whites = append(whites, req)
		}
	}
	return whites, blacks, parseErr
}

func parseRawHTTPForOWASP(path string) (corpusRequest, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return corpusRequest{}, false
	}
	r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return corpusRequest{}, false
	}
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
	}
	headers := make(map[string]string, len(r.Header)+1)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	if r.Host != "" {
		headers["Host"] = r.Host
	}
	out := corpusRequest{path: r.URL.Path, query: r.URL.RawQuery, headers: headers}
	if len(body) > 0 {
		out.body = []string{string(body)}
	}
	return out, true
}

// scanCorpus 以 mid 灵敏度（生产默认）扫描全语料，返回误报指纹列表与黑样本命中数。
//
// 扫描口径说明：body 直接作为单 target 传入（不模拟生产的 Content-Type 分派与
// 8192/48KiB 截断），因此本口径比生产**更严**，基线本身即有少量本口径下的误报；
// 端到端生产口径（blazehttp 全语料）由 lead 的引擎级基线保证 0 误报。
// 本用例的作用是「改动前后逐条对拍」：任何新增指纹都说明该改动引入了新误报。
func scanCorpus(tb testing.TB) (fpPrints []string, blackHits int) {
	tb.Helper()
	whites, blacks, parseErr := loadOWASPCorpus(tb)
	tb.Logf("语料: white=%d black=%d parse_errors=%d", len(whites), len(blacks), parseErr)
	thresholds := CompileThresholds("mid")
	for _, req := range whites {
		hit, ok := FirstOWASPHitWithThresholds(thresholds, req.path, req.query, req.headers, req.body)
		if !ok {
			continue
		}
		bodyLen := 0
		for _, b := range req.body {
			bodyLen += len(b)
		}
		fpPrints = append(fpPrints, fmt.Sprintf("%s|path=%q|queryLen=%d|bodyLen=%d|score=%d",
			hit.RuleID, req.path, len(req.query), bodyLen, hit.Score))
	}
	sort.Strings(fpPrints)
	for _, req := range blacks {
		if _, ok := FirstOWASPHitWithThresholds(thresholds, req.path, req.query, req.headers, req.body); ok {
			blackHits++
		}
	}
	return fpPrints, blackHits
}

func formatFPSummary(fpPrints []string, blackHits int, whites, blacks int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "white=%d\nblack=%d\nblack_hits=%d\nfp_total=%d\n", whites, blacks, blackHits, len(fpPrints))
	for _, p := range fpPrints {
		b.WriteString(p)
		b.WriteByte('\n')
	}
	return b.String()
}

// TestOWASPBlazehttpFingerprint 对拍 OWASP 在 blazehttp 全语料上的
// 「白样本误报指纹 + 黑样本检出数」。
//
// 这是 hint 剪枝修复的护栏：
//   - 新 hint 过弱 → 白样本新增误报，fp 指纹出现新行 → 失败
//   - 新 hint 过强 → 黑样本检出数下降 → 失败
//
// 用 OWASP_GOLDEN_UPDATE=1 刷新快照（仅在确认漂移可接受时使用）。
// 语料缺失时 Skip。
func TestOWASPBlazehttpFingerprint(t *testing.T) {
	whites, blacks, parseErr := loadOWASPCorpus(t)
	if len(whites) == 0 && len(blacks) == 0 {
		t.Skipf("语料无样本 (parse_errors=%d)", parseErr)
	}
	fpPrints, blackHits := scanCorpus(t)
	summary := formatFPSummary(fpPrints, blackHits, len(whites), len(blacks))

	if os.Getenv("OWASP_GOLDEN_UPDATE") == "1" {
		if err := os.MkdirAll(filepath.Dir(fpGoldenPath), 0o755); err != nil {
			t.Fatalf("创建 testdata 失败: %v", err)
		}
		if err := os.WriteFile(fpGoldenPath, []byte(summary), 0o644); err != nil {
			t.Fatalf("写 golden 失败: %v", err)
		}
		t.Logf("已刷新 golden: %s\n%s", fpGoldenPath, summary)
		return
	}
	want, err := os.ReadFile(fpGoldenPath)
	if err != nil {
		t.Fatalf("读 golden 失败（首次请用 OWASP_GOLDEN_UPDATE=1 生成）: %v", err)
	}
	if summary != string(want) {
		gotLines := strings.Split(summary, "\n")
		wantLines := strings.Split(string(want), "\n")
		added := diffLines(wantLines, gotLines)
		removed := diffLines(gotLines, wantLines)
		t.Fatalf("blazehttp 语料判定漂移。\n新增(可能误报):\n%s\n消失(可能漏报):\n%s",
			strings.Join(added, "\n"), strings.Join(removed, "\n"))
	}
}

// diffLines 返回 a 中有而 b 中没有的行。
func diffLines(a, b []string) []string {
	set := make(map[string]int, len(b))
	for _, l := range b {
		set[l]++
	}
	var out []string
	for _, l := range a {
		if set[l] > 0 {
			set[l]--
			continue
		}
		out = append(out, l)
	}
	return out
}
