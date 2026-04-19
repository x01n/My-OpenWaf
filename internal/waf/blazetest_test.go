package waf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestBlazeBlackSamples reads all .black files from the blazehttp testcases
// directory and runs them through the OWASP engine to identify which ones
// are missed. This helps understand detection gaps.
func TestBlazeBlackSamples(t *testing.T) {
	baseDir := `C:\Users\Administrator\Desktop\file\blazehttp-repo\testcases`
	if _, err := os.Stat(baseDir); err != nil {
		t.Skipf("blazehttp testcases not found at %s", baseDir)
	}

	var total, detected, missed int
	var missedSamples []string

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".black") {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 64*1024)

		// Parse HTTP request
		var method, reqPath, rawQuery, host, contentType string
		headers := make(map[string]string)
		var bodyLines []string
		inBody := false
		lineNum := 0

		for scanner.Scan() {
			line := scanner.Text()
			lineNum++

			if lineNum == 1 {
				// Request line: GET /path?query HTTP/1.1
				parts := strings.SplitN(line, " ", 3)
				if len(parts) < 2 {
					return nil
				}
				method = parts[0]
				fullPath := parts[1]
				if u, err := url.Parse(fullPath); err == nil {
					reqPath = u.Path
					rawQuery = u.RawQuery
				} else {
					reqPath = fullPath
				}
				continue
			}

			if inBody {
				bodyLines = append(bodyLines, line)
				continue
			}

			if line == "" || line == "\r" {
				inBody = true
				continue
			}

			// Header
			if k, v, ok := strings.Cut(line, ":"); ok {
				k = strings.TrimSpace(k)
				v = strings.TrimSpace(v)
				headers[k] = v
				lk := strings.ToLower(k)
				if lk == "host" {
					host = v
				}
				if lk == "content-type" {
					contentType = v
				}
			}
		}

		_ = method
		_ = host
		body := strings.Join(bodyLines, "\n")

		// Build body targets like the real pipeline does
		var bodyTargets []string
		if len(body) > 0 {
			ct := strings.ToLower(contentType)
			switch {
			case strings.Contains(ct, "application/x-www-form-urlencoded"):
				bodyTargets = extractFormTargets(body)
			case strings.Contains(ct, "application/json"):
				bodyTargets = extractJSONTargetsHelper([]byte(body))
			default:
				if len(body) > 0 && !isBinaryBody([]byte(body)) {
					limit := 8192
					if len(body) < limit {
						limit = len(body)
					}
					bodyTargets = []string{body[:limit]}
				}
			}
		}

		hits := CheckOWASP("high", reqPath, rawQuery, headers, bodyTargets)

		total++
		if len(hits) > 0 {
			detected++
		} else {
			missed++
			// Truncate for display
			display := reqPath
			if rawQuery != "" {
				display += "?" + rawQuery
			}
			if len(display) > 150 {
				display = display[:150] + "..."
			}
			shortPath := filepath.Base(filepath.Dir(filepath.Dir(path))) + "/" +
				filepath.Base(filepath.Dir(path)) + "/" + filepath.Base(path)
			missedSamples = append(missedSamples, fmt.Sprintf("[%s] %s %s", shortPath, method, display))
		}
		return nil
	})

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Total: %d, Detected: %d (%.1f%%), Missed: %d (%.1f%%)",
		total, detected, float64(detected)/float64(total)*100,
		missed, float64(missed)/float64(total)*100)

	// Print first 100 missed samples for analysis
	t.Logf("\n=== MISSED SAMPLES (first 100) ===")
	for i, s := range missedSamples {
		if i >= 100 {
			break
		}
		t.Logf("%d: %s", i+1, s)
	}
}

// TestBlazeWhiteFalsePositives analyses which rules cause false positives
// on legitimate (.white) samples.
func TestBlazeWhiteFalsePositives(t *testing.T) {
	baseDir := `C:\Users\Administrator\Desktop\file\blazehttp-repo\testcases`
	if _, err := os.Stat(baseDir); err != nil {
		t.Skipf("blazehttp testcases not found at %s", baseDir)
	}

	ruleCount := make(map[string]int)
	catCount := make(map[string]int)
	var total, fp int

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".white") {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 64*1024)

		var method, reqPath, rawQuery, contentType string
		headers := make(map[string]string)
		var bodyLines []string
		inBody := false
		lineNum := 0

		for scanner.Scan() {
			line := scanner.Text()
			lineNum++
			if lineNum == 1 {
				parts := strings.SplitN(line, " ", 3)
				if len(parts) < 2 {
					return nil
				}
				method = parts[0]
				_ = method
				if u, err := url.Parse(parts[1]); err == nil {
					reqPath = u.Path
					rawQuery = u.RawQuery
				} else {
					reqPath = parts[1]
				}
				continue
			}
			if inBody {
				bodyLines = append(bodyLines, line)
				continue
			}
			if line == "" || line == "\r" {
				inBody = true
				continue
			}
			if k, v, ok := strings.Cut(line, ":"); ok {
				k = strings.TrimSpace(k)
				v = strings.TrimSpace(v)
				headers[k] = v
				if strings.ToLower(k) == "content-type" {
					contentType = v
				}
			}
		}

		body := strings.Join(bodyLines, "\n")
		var bodyTargets []string
		if len(body) > 0 {
			ct := strings.ToLower(contentType)
			switch {
			case strings.Contains(ct, "application/x-www-form-urlencoded"):
				bodyTargets = extractFormTargets(body)
			case strings.Contains(ct, "application/json"):
				bodyTargets = extractJSONTargetsHelper([]byte(body))
			default:
				if !isBinaryBody([]byte(body)) {
					limit := 8192
					if len(body) < limit {
						limit = len(body)
					}
					bodyTargets = []string{body[:limit]}
				}
			}
		}

		hits := CheckOWASP("high", reqPath, rawQuery, headers, bodyTargets)

		total++
		if len(hits) > 0 {
			fp++
			for _, h := range hits {
				ruleCount[h.RuleID]++
				catCount[string(h.Category)]++
			}
			if fp <= 20 {
				display := reqPath
				if rawQuery != "" {
					display += "?" + rawQuery
				}
				if len(display) > 200 {
					display = display[:200] + "..."
				}
				t.Logf("FP#%d [%s] %s", fp, hits[0].RuleID, display)
			}
		}
		return nil
	})

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Total white samples: %d, False positives: %d (%.2f%%)", total, fp, float64(fp)/float64(total)*100)

	// Sort by count descending
	type kv struct {
		k string
		v int
	}
	var sorted []kv
	for k, v := range ruleCount {
		sorted = append(sorted, kv{k, v})
	}
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].v > sorted[i].v {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	t.Logf("\n=== FALSE POSITIVE RULES (by count) ===")
	for _, s := range sorted {
		t.Logf("  %s: %d", s.k, s.v)
	}

	t.Logf("\n=== FALSE POSITIVE CATEGORIES ===")
	var catSorted []kv
	for k, v := range catCount {
		catSorted = append(catSorted, kv{k, v})
	}
	for i := 0; i < len(catSorted); i++ {
		for j := i + 1; j < len(catSorted); j++ {
			if catSorted[j].v > catSorted[i].v {
				catSorted[i], catSorted[j] = catSorted[j], catSorted[i]
			}
		}
	}
	for _, s := range catSorted {
		t.Logf("  %s: %d", s.k, s.v)
	}
}

// Helper to extract form body values
func extractFormTargets(body string) []string {
	var vals []string
	for body != "" {
		pair := body
		if i := strings.IndexByte(pair, '&'); i >= 0 {
			pair, body = pair[:i], pair[i+1:]
		} else {
			body = ""
		}
		if pair == "" {
			continue
		}
		paramKey, value, hasEq := strings.Cut(pair, "=")
		if hasEq {
			dv, err := url.QueryUnescape(value)
			if err != nil {
				dv = value
			}
			if dv != "" {
				vals = append(vals, dv)
			}
		}
		dk, err := url.QueryUnescape(paramKey)
		if err != nil {
			dk = paramKey
		}
		if dk != "" {
			vals = append(vals, dk)
		}
	}
	return vals
}

// Helper for JSON body extraction
func extractJSONTargetsHelper(body []byte) []string {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	var vals []string
	walkJSONHelper(raw, &vals, 0)
	return vals
}

func walkJSONHelper(v any, vals *[]string, depth int) {
	if depth > 10 || len(*vals) > 100 {
		return
	}
	switch val := v.(type) {
	case string:
		if val != "" {
			*vals = append(*vals, val)
		}
	case map[string]any:
		for k, child := range val {
			if k != "" {
				*vals = append(*vals, k)
			}
			walkJSONHelper(child, vals, depth+1)
		}
	case []any:
		for _, child := range val {
			walkJSONHelper(child, vals, depth+1)
		}
	}
}

func isBinaryBody(body []byte) bool {
	sample := body
	if len(sample) > 512 {
		sample = body[:512]
	}
	if len(sample) == 0 {
		return false
	}
	printable := 0
	for _, b := range sample {
		if b >= 0x20 && b <= 0x7E || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(sample)) < 0.9
}

// TestBlazeBlackMissedAnalysis provides detailed analysis of missed (false-negative)
// black samples, printing key features of each missed request and aggregating
// pattern statistics to guide detection improvements.
func TestBlazeBlackMissedAnalysis(t *testing.T) {
	baseDir := `C:\Users\Administrator\Desktop\file\blazehttp-repo\testcases`
	if _, err := os.Stat(baseDir); err != nil {
		t.Skipf("blazehttp testcases not found at %s", baseDir)
	}

	reBase64 := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)

	var total, detected, missed int

	// Aggregate counters for pattern statistics
	var (
		countBase64Body    int
		countUnicodeQuery  int
		countScriptQuery   int
		countJavaSerBody   int
		countGlobalThisAny int
	)

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".black") {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 64*1024)

		var method, reqPath, rawQuery, contentType string
		headers := make(map[string]string)
		var bodyLines []string
		inBody := false
		lineNum := 0

		for scanner.Scan() {
			line := scanner.Text()
			lineNum++

			if lineNum == 1 {
				parts := strings.SplitN(line, " ", 3)
				if len(parts) < 2 {
					return nil
				}
				method = parts[0]
				if u, err := url.Parse(parts[1]); err == nil {
					reqPath = u.Path
					rawQuery = u.RawQuery
				} else {
					reqPath = parts[1]
				}
				continue
			}

			if inBody {
				bodyLines = append(bodyLines, line)
				continue
			}

			if line == "" || line == "\r" {
				inBody = true
				continue
			}

			if k, v, ok := strings.Cut(line, ":"); ok {
				k = strings.TrimSpace(k)
				v = strings.TrimSpace(v)
				headers[k] = v
				lk := strings.ToLower(k)
				if lk == "content-type" {
					contentType = v
				}
			}
		}

		_ = method
		body := strings.Join(bodyLines, "\n")

		var bodyTargets []string
		if len(body) > 0 {
			ct := strings.ToLower(contentType)
			switch {
			case strings.Contains(ct, "application/x-www-form-urlencoded"):
				bodyTargets = extractFormTargets(body)
			case strings.Contains(ct, "application/json"):
				bodyTargets = extractJSONTargetsHelper([]byte(body))
			default:
				if len(body) > 0 && !isBinaryBody([]byte(body)) {
					limit := 8192
					if len(body) < limit {
						limit = len(body)
					}
					bodyTargets = []string{body[:limit]}
				}
			}
		}

		hits := CheckOWASP("high", reqPath, rawQuery, headers, bodyTargets)

		total++
		if len(hits) > 0 {
			detected++
			return nil
		}
		missed++

		// --- Print key features of this missed sample ---
		shortPath := filepath.Base(filepath.Dir(filepath.Dir(path))) + "/" +
			filepath.Base(filepath.Dir(path)) + "/" + filepath.Base(path)

		truncate := func(s string, max int) string {
			if len(s) > max {
				return s[:max] + "..."
			}
			return s
		}

		t.Logf("=== MISSED #%d [%s] ===", missed, shortPath)
		t.Logf("  Path:  %s", truncate(reqPath, 50))
		t.Logf("  Query: %s", truncate(rawQuery, 50))
		t.Logf("  Body:  %s", truncate(body, 100))

		for _, hdr := range []string{"Referer", "Cookie"} {
			if v, ok := headers[hdr]; ok {
				t.Logf("  %s: %s", hdr, truncate(v, 50))
			}
		}

		// --- Aggregate pattern statistics ---
		allText := reqPath + " " + rawQuery + " " + body
		for _, hv := range headers {
			allText += " " + hv
		}

		if len(body) > 0 && reBase64.MatchString(body) {
			countBase64Body++
		}

		queryLower := strings.ToLower(rawQuery)
		if strings.Contains(rawQuery, `\u00`) {
			countUnicodeQuery++
		}
		if strings.Contains(queryLower, "<script") || strings.Contains(queryLower, "<svg") {
			countScriptQuery++
		}

		bodyLower := strings.ToLower(body)
		if strings.Contains(bodyLower, "ro0ab") || strings.Contains(bodyLower, "aced0005") {
			countJavaSerBody++
		}

		allLower := strings.ToLower(allText)
		if strings.Contains(allLower, "globalthis") || strings.Contains(allLower, "this[") || strings.Contains(allLower, "window[") {
			countGlobalThisAny++
		}

		return nil
	})

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("\n========== SUMMARY ==========")
	t.Logf("Total: %d, Detected: %d (%.1f%%), Missed: %d (%.1f%%)",
		total, detected, float64(detected)/float64(total)*100,
		missed, float64(missed)/float64(total)*100)

	t.Logf("\n=== MISSED SAMPLE PATTERN STATISTICS ===")
	t.Logf("  Body contains base64-like pattern:        %d", countBase64Body)
	t.Logf("  Query contains unicode escape (\\u00):     %d", countUnicodeQuery)
	t.Logf("  Query contains <script or <svg:           %d", countScriptQuery)
	t.Logf("  Body contains rO0AB or aced0005 (JavaSer):%d", countJavaSerBody)
	t.Logf("  Contains globalThis/this[/window[:        %d", countGlobalThisAny)
}
