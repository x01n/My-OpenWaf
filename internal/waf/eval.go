package waf

import (
	"net"
	"strings"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

func Evaluate(clientIP net.IP, path string, rawQuery string, rules []snapshot.CompiledRule) action.Result {
	if res := evalACL(clientIP, rules); res.Matched {
		return res
	}
	if res := evalPathQuery(rules, path, rawQuery, []store.RulePhase{store.PhaseSignature, store.PhaseCustom}); res.Matched {
		return res
	}
	return action.Pass()
}

// EvaluateWithBot performs full WAF evaluation including bot detection.
// headers is the request headers map; headerKeys is kept for API compatibility.
func EvaluateWithBot(clientIP net.IP, method, path, rawQuery string, headers map[string]string, headerKeys []string, rules []snapshot.CompiledRule, botLevel string) (action.Result, BotVerdict) {
	// Standard WAF evaluation
	if res := evalACL(clientIP, rules); res.Matched {
		return res, BotVerdict{}
	}
	if res := evalPathQuery(rules, path, rawQuery, []store.RulePhase{store.PhaseSignature, store.PhaseCustom}); res.Matched {
		return res, BotVerdict{}
	}

	// Bot detection with fingerprint scoring
	br := NewBotRequest(method, path, headers)
	br.HeaderKeys = headerKeys
	br.ClientIP = clientIP
	verdict := CheckBotWithLevel(br, botLevel)

	// If already classified as good or definite malicious, skip deep fingerprint
	if verdict.Category != "good" && verdict.Score < 100 {
		// Deep TLS/HTTP2 fingerprint scoring (JA3/JA4/H2/header order)
		fpResult := DeepFingerprintScore(br)
		if fpResult.Score > 0 {
			verdict.Score += fpResult.Score
			fpReason := "tls_fp:" + strings.Join(fpResult.Reasons, ",")
			if verdict.Reason != "" {
				verdict.Reason += "; " + fpReason
			} else {
				verdict.Reason = fpReason
			}
			// Re-evaluate category based on combined score
			if verdict.Score >= 80 {
				verdict.IsBot = true
				verdict.Category = "malicious"
				if verdict.RuleID == "" {
					verdict.RuleID = "bot:fp:deep:001"
				}
			} else if verdict.Score >= 50 && verdict.Category != "malicious" {
				verdict.IsBot = true
				verdict.Category = "suspicious"
				if verdict.RuleID == "" {
					verdict.RuleID = "bot:fp:deep:002"
				}
			}
		}
	}

	// If bot detection triggers a block-level response
	if verdict.Category == "malicious" && verdict.Score >= 80 {
		// Bot score >= 80 uses Drop (highest severity) when available.
		actType := action.Block
		if verdict.Score >= 80 {
			actType = action.Drop
		}
		return action.Result{
			Type:      actType,
			RuleIDStr: verdict.RuleID,
			Matched:   true,
			Phase:     "bot",
			MatchDesc: verdict.Reason,
		}, verdict
	}

	return action.Pass(), verdict
}

func evalACL(clientIP net.IP, rules []snapshot.CompiledRule) action.Result {
	for _, r := range rules {
		if r.Phase != store.PhaseACL || clientIP == nil {
			continue
		}
		_, cidr, err := net.ParseCIDR(r.Arg)
		if err != nil {
			ip := net.ParseIP(r.Arg)
			if ip == nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				_, cidr, _ = net.ParseCIDR(ip.String() + "/32")
			} else {
				_, cidr, _ = net.ParseCIDR(ip.String() + "/128")
			}
		}
		if cidr == nil || !cidr.Contains(clientIP) {
			continue
		}
		act := action.Normalize(action.Type(r.Action))
		return action.Result{
			Type: act, RuleID: r.ID, Matched: true,
			Phase: string(r.Phase), MatchDesc: r.Kind + ":" + r.Arg,
		}
	}
	return action.Pass()
}

func evalPathQuery(rules []snapshot.CompiledRule, path, rawQuery string, phases []store.RulePhase) action.Result {
	phaseSet := make(map[store.RulePhase]struct{})
	for _, p := range phases {
		phaseSet[p] = struct{}{}
	}
	for _, r := range rules {
		if _, ok := phaseSet[r.Phase]; !ok {
			continue
		}
		matched := false
		switch r.Kind {
		case "block_path":
			if r.Arg != "" && len(path) >= len(r.Arg) && path[:len(r.Arg)] == r.Arg {
				matched = true
			}
		case "block_query_contains":
			if r.Arg != "" && containsStr(rawQuery, r.Arg) {
				matched = true
			}
		}
		if matched {
			act := action.Normalize(action.Type(r.Action))
			return action.Result{
				Type: act, RuleID: r.ID, Matched: true,
				Phase: string(r.Phase), MatchDesc: r.Kind + ":" + r.Arg,
			}
		}
	}
	return action.Pass()
}

func containsStr(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
