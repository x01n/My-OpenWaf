package owasp

import (
	"testing"
)

func TestCheckOWASP_Base64SQLi_FN_Debug(t *testing.T) {
	// Decoded payload: "1 # fefflabelled... \naND\x00/* ... */1=1"
	// After normalize, the decoded content should contain "and" + "1=1"
	decoded := "1 # fefflabelledbytabindexintegrityundoprogressgraytoffeopen \naND\x00/* collectionsawait\nclosestpositionslinpusvimeominimoblazertrimtype\nrsync\rnicenameexclusivepointdirty */1=1"

	// Test directly with the decoded payload as a target
	norm := normalize(decoded)
	t.Logf("normalize(decoded) = %q", norm)

	// Check if sqli patterns match
	for _, p := range sqliPatterns {
		if p.re.MatchString(norm) {
			t.Logf("sqli pattern matched: id=%s score=%d", p.id, p.score)
			// Check if false positive suppressor kicks in
			fp := isSQLiFalsePositive(norm, p.id)
			t.Logf("  isSQLiFalsePositive => %v", fp)
		}
	}

	// Check directly with CheckOWASP using the decoded payload as body target
	hits := CheckOWASP("medium", "/", "", nil, []string{decoded})
	t.Logf("CheckOWASP with decoded body: %d hits", len(hits))
	for _, h := range hits {
		t.Logf("  hit: rule=%s score=%d category=%s", h.RuleID, h.Score, h.Category)
	}

	// Now check with normalizeWithDecode applied to the base64 token
	b64 := "MSAjIGZlZmZsYWJlbGxlZGJ5dGFiaW5kZXhpbnRlZ3JpdHl1bmRvcHJvZ3Jlc3NncmF5dG9mZmVvcGVuIAphTkQALyogY29sbGVjdGlvbnNhd2FpdApjbG9zZXN0cG9zaXRpb25zbGlucHVzdmltZW9taW5pbW9ibGF6ZXJ0cmltdHlwZQpyc3luYw1uaWNlbmFtZWV4Y2x1c2l2ZXBvaW50ZGlydHkgKi8xPTE="
	nwd := normalizeWithDecode(b64)
	t.Logf("normalizeWithDecode(b64) = %q", nwd)

	// Check sqli patterns against the normalizeWithDecode result
	for _, p := range sqliPatterns {
		if p.re.MatchString(nwd) {
			t.Logf("sqli pattern matched on nwd: id=%s score=%d", p.id, p.score)
			fp := isSQLiFalsePositive(nwd, p.id)
			t.Logf("  isSQLiFalsePositive => %v", fp)
		}
	}
}
