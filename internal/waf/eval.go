package waf

import (
	"net"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

// Evaluate runs phases in order (legacy entry point, delegates to core/rules logic).
func Evaluate(clientIP net.IP, path string, rawQuery string, rules []snapshot.CompiledRule) action.Result {
	if res := evalACL(clientIP, rules); res.Matched {
		return res
	}
	if res := evalPathQuery(rules, path, rawQuery, []store.RulePhase{store.PhaseSignature, store.PhaseCustom}); res.Matched {
		return res
	}
	return action.Pass()
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
