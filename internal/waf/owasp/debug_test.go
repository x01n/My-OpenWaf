package owasp

import (
	"bufio"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestDebugSample(t *testing.T) {
	samples := []string{
		`C:\Users\Administrator\Desktop\file\blazehttp-repo\testcases\cc\ba\a7fa8b6ea8c70ed1ab587148a061.black`,
		`C:\Users\Administrator\Desktop\file\blazehttp-repo\testcases\3b\30\07d1113b4e098232de687e58a292.black`,
		`C:\Users\Administrator\Desktop\file\blazehttp-repo\testcases\7a\7f\8aa6bc22414aeba1b3f492943e0b.black`,
		`C:\Users\Administrator\Desktop\file\blazehttp-repo\testcases\81\0f\7a42faed086036e72fec24ba965e.black`,
		`C:\Users\Administrator\Desktop\file\blazehttp-repo\testcases\be\32\cbb9261c728de3c91a11a7bd086d.black`,
		`C:\Users\Administrator\Desktop\file\blazehttp-repo\testcases\d8\ab\654a635915b6333180d6bbe05008.black`,
		`C:\Users\Administrator\Desktop\file\blazehttp-repo\testcases\e9\fb\0f57b1c282be9e43ab4140bb8844.black`,
	}

	for _, path := range samples {
		name := path[len(path)-45:]
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Skip(err)
			}
			defer f.Close()

			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 64*1024)
			var reqPath, rawQuery, contentType string
			headers := make(map[string]string)
			var bodyLines []string
			inBody := false
			lineNum := 0
			for scanner.Scan() {
				line := scanner.Text()
				lineNum++
				if lineNum == 1 {
					parts := strings.SplitN(line, " ", 3)
					if u, err := url.Parse(parts[1]); err == nil {
						reqPath = u.Path
						rawQuery = u.RawQuery
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
			_ = contentType

			bodyTargets := extractFormTargets(body)
			t.Logf("Body targets: %d, body len: %d", len(bodyTargets), len(body))

			for i, bt := range bodyTargets {
				if len(bt) > 200 {
					t.Logf("  target[%d] len=%d: %s...", i, len(bt), bt[:200])
				} else {
					t.Logf("  target[%d] len=%d: %s", i, len(bt), bt)
				}
				normalized := normalizeWithDecode(bt)
				// Also test with truncated input (like CheckOWASP does)
				truncBt := bt
				if len(truncBt) > 8192 {
					truncBt = truncBt[:8192]
				}
				truncNorm := normalizeWithDecode(truncBt)
				t.Logf("    full_norm_len=%d trunc_norm_len=%d", len(normalized), len(truncNorm))
				t.Logf("    hasSuspicious=%v hasELIndicator=%v", hasSuspiciousContent(normalized), hasELIndicator(normalized))
				t.Logf("    trunc: hasSuspicious=%v hasELIndicator=%v", hasSuspiciousContent(truncNorm), hasELIndicator(truncNorm))
				// Test EL detection directly
				if hasELIndicator(normalized) {
					hit, ok := checkExprLang(normalized, 3)
					t.Logf("    checkExprLang: ok=%v hit=%+v", ok, hit)
					t.Logf("    isELFalsePositive: %v", isELFalsePositive(normalized, hit.RuleID))
					for _, p := range exprLangPatterns {
						if p.re.MatchString(normalized) {
							t.Logf("    EL pattern match: %s score=%d", p.id, p.score)
						}
					}
				}
				if len(normalized) > 200 {
					t.Logf("    normalized len=%d first500: %s...", len(normalized), normalized[:500])
					t.Logf("    normalized last500: ...%s", normalized[len(normalized)-500:])
				}
			}

			hits := CheckOWASP("high", reqPath, rawQuery, headers, bodyTargets)
			t.Logf("Hits: %d", len(hits))
			for _, h := range hits {
				t.Logf("  %s %s score=%d", h.RuleID, h.Desc, h.Score)
			}
		})
	}
}
