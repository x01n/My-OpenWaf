package owasp

import "testing"

// TestCheckMaliciousUserAgent 覆盖 gotestwaf community-user-agent 的 8 条自报工具 UA。
func TestCheckMaliciousUserAgent(t *testing.T) {
	positives := []string{
		"http://lmb1ikpej3yys0gqft8lxewm2d89w5qtgh840sp.burpcollaborator.net/6.17.0.RELEASE iPhone12,8 iOS/14.5.1))",
		"mercuryboard_user_agent_sql_injection.nasl'",
		"Mozilla/5.0 [en] (X11, U; OpenVAS-VT 22.4.1)",
		"Microsoft WinRM Client OpenVASVT",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 root@w63gecoroprj5um8ypnd7r6in9t0hseg3.interact.sh",
		"Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
		"Fuzz Faster U Fool v2.0.0",
		"sqlmap/1.7.4#stable (https://sqlmap.org)",
	}
	for _, ua := range positives {
		hit, ok := CheckMaliciousUserAgent(ua)
		if !ok {
			t.Fatalf("malicious UA not detected: %q", ua)
		}
		if hit.Category != CatMaliciousClient || hit.RuleID != "owasp:client:001" {
			t.Fatalf("unexpected hit for %q: %+v", ua, hit)
		}
	}

	negatives := []string{
		"",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
		"curl/8.4.0",
		"python-requests/2.31.0",
		"Go-http-client/1.1",
		"PostmanRuntime/7.36.0",
	}
	for _, ua := range negatives {
		if hit, ok := CheckMaliciousUserAgent(ua); ok {
			t.Fatalf("benign UA falsely detected: %q -> %+v", ua, hit)
		}
	}
}

// TestCheckOWASPMaliciousUserAgent 校验 UA 命中经由公共检测入口可见。
func TestCheckOWASPMaliciousUserAgent(t *testing.T) {
	hits := CheckOWASP("mid", "/", "", map[string]string{"User-Agent": "sqlmap/1.7.4#stable (https://sqlmap.org)"}, nil)
	for _, hit := range hits {
		if hit.Category == CatMaliciousClient && hit.RuleID == "owasp:client:001" {
			return
		}
	}
	t.Fatalf("CheckOWASP missed malicious user-agent; hits=%+v", hits)
}

// TestCheckOWASPMaliciousUserAgentDoesNotPreemptPayloadRules 校验既有载荷规则优先，
// 恶意 UA 只在没有其他命中时兜底，不改变归因。
func TestCheckOWASPMaliciousUserAgentDoesNotPreemptPayloadRules(t *testing.T) {
	hits := CheckOWASP("mid", "/%2e%2e/%2e%2e/etc/passwd", "", map[string]string{"user-agent": "sqlmap/1.7.4"}, nil)
	for _, hit := range hits {
		if hit.Category == CatPathTrav {
			return
		}
	}
	t.Fatalf("payload rule attribution was preempted by user-agent hit; hits=%+v", hits)
}
