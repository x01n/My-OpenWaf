package waf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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
				if len(body) > 0 {
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
