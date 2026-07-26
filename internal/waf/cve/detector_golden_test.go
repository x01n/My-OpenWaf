package cve

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

// TestCVEDetectFirstGoldenCorpus 是 CVE 多模式匹配等价替换的核心安全网。
//
// 它在一大批真实 HTTP 报文样本(blazehttp 语料)上跑当前 DetectFirst,把
// 每个样本命中的 CVEID 聚合成稳定摘要(CVEID->命中次数 + 总命中数),与固化的
// golden 快照逐字节比对。任何改动 gate/自动机后重跑此测试,若 block/pass 判定或
// 命中的 CVE 规则发生变化,摘要即不一致,测试红。
//
// 语料路径由 CVE_GOLDEN_CORPUS 指定(默认 ../../../temp/testcases,相对本包)。
// 语料目录不存在时 Skip —— 语料是本地 gitignored 资产,不随仓库分发。
// 首次运行或带 -update 时用 CVE_GOLDEN_UPDATE=1 生成/刷新 golden 文件。
func TestCVEDetectFirstGoldenCorpus(t *testing.T) {
	corpus := os.Getenv("CVE_GOLDEN_CORPUS")
	if corpus == "" {
		corpus = filepath.Join("..", "..", "..", "temp", "testcases")
	}
	if _, err := os.Stat(corpus); err != nil {
		t.Skipf("语料目录不存在,跳过 golden 差分: %s", corpus)
	}

	files := collectCorpusFiles(t, corpus)
	if len(files) == 0 {
		t.Skipf("语料目录无样本文件: %s", corpus)
	}

	detector := NewCVEDetector()
	counts := make(map[string]int)
	totalHit := 0
	parseErr := 0
	for _, f := range files {
		req, ok := parseRawHTTPToCVERequest(f)
		if !ok {
			parseErr++
			continue
		}
		if m, hit := detector.DetectFirst(req); hit {
			totalHit++
			key := m.CVEID
			if key == "" {
				key = "<empty-cveid>"
			}
			counts[key]++
		}
	}

	summary := formatGoldenSummary(len(files), parseErr, totalHit, counts)

	goldenPath := filepath.Join("testdata", "detectfirst_golden.txt")
	if os.Getenv("CVE_GOLDEN_UPDATE") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("创建 testdata 目录失败: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(summary), 0o644); err != nil {
			t.Fatalf("写 golden 失败: %v", err)
		}
		t.Logf("已生成 golden: %s\n%s", goldenPath, summary)
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("读 golden 失败(首次请用 CVE_GOLDEN_UPDATE=1 生成): %v", err)
	}
	if summary != string(want) {
		t.Fatalf("DetectFirst 在真实语料上的命中摘要与 golden 不一致——等价性被破坏。\n--- got ---\n%s\n--- want ---\n%s", summary, string(want))
	}
}

// collectCorpusFiles 递归收集 .white/.black 样本文件路径,排序保证确定性。
func collectCorpusFiles(t *testing.T, root string) []string {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".white") || strings.HasSuffix(path, ".black") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历语料失败: %v", err)
	}
	sort.Strings(files)
	return files
}

// parseRawHTTPToCVERequest 把原始 HTTP 报文文件解析为 CVERequest。
// 解析失败返回 false,由调用方计入 parseErr(计入 golden,保证确定性)。
func parseRawHTTPToCVERequest(path string) (*CVERequest, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	reader := bufio.NewReader(bytes.NewReader(raw))
	httpReq, err := http.ReadRequest(reader)
	if err != nil {
		return nil, false
	}
	var body []byte
	if httpReq.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(httpReq.Body, 1<<20))
		httpReq.Body.Close()
	}
	headers := make(map[string]string, len(httpReq.Header))
	for k, v := range httpReq.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	if httpReq.Host != "" {
		headers["Host"] = httpReq.Host
	}
	contentType := httpReq.Header.Get("Content-Type")
	reqPath := httpReq.URL.Path
	rawQuery := httpReq.URL.RawQuery
	return BuildCVERequest(reqPath, rawQuery, headers, body, contentType), true
}

// formatGoldenSummary 生成确定性文本摘要:样本总数、解析失败数、命中总数,
// 后跟按 CVEID 字典序排列的命中计数,便于 diff 定位是哪条规则的判定漂移。
func formatGoldenSummary(total, parseErr, totalHit int, counts map[string]int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "samples=%d\nparse_errors=%d\ntotal_hits=%d\n", total, parseErr, totalHit)
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(&b, "distinct_cveids=%d\n", len(keys))
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%d\n", k, counts[k])
	}
	return b.String()
}
