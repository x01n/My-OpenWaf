package rule

import (
	"context"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/rules"
	"My-OpenWaf/internal/store"
)

type ValidateRuleRequest struct {
	Pattern string `json:"pattern"`
}

type ValidateRuleResponse struct {
	Valid   bool     `json:"valid"`
	Message string   `json:"message,omitempty"`
	Kind    string   `json:"kind,omitempty"`
	Arg     string   `json:"arg,omitempty"`
	Errors  []string `json:"errors,omitempty"`
}

type RuleTemplate struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
	Category    string `json:"category"`
	Phase       string `json:"phase"`
	Action      string `json:"action"`
}

func ValidateRule() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req ValidateRuleRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		pattern := strings.TrimSpace(req.Pattern)
		if pattern == "" {
			c.JSON(400, ValidateRuleResponse{
				Valid:   false,
				Message: "pattern cannot be empty",
			})
			return
		}

		kind, arg := rules.ParsePattern(pattern)
		if kind == "" {
			c.JSON(200, ValidateRuleResponse{
				Valid:   false,
				Message: "invalid pattern format",
				Errors:  []string{"pattern must start with a valid prefix like 'block_ip:', 'allow_ip:', 'block_path:', etc., or be a valid JSON compound condition"},
			})
			return
		}

		validationErrors := []string(nil)
		if _, _, errs := rules.ValidatePattern(pattern); len(errs) > 0 {
			validationErrors = errs
		}
		if len(validationErrors) > 0 {
			c.JSON(200, ValidateRuleResponse{
				Valid:   false,
				Message: "pattern cannot be compiled",
				Errors:  validationErrors,
			})
			return
		}

		c.JSON(200, ValidateRuleResponse{
			Valid:   true,
			Message: "pattern is valid",
			Kind:    kind,
			Arg:     arg,
		})
	}
}

func GetRuleTemplates() app.HandlerFunc {
	templates := []RuleTemplate{
		{
			Name:        "Block IP Address",
			Description: "Block requests from a specific IP address or CIDR range",
			Pattern:     "block_ip:192.168.1.100",
			Category:    "IP Filtering",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Allow IP Address",
			Description: "Allow requests from a specific IP address or CIDR range (bypasses WAF)",
			Pattern:     "allow_ip:10.0.0.0/8",
			Category:    "IP Filtering",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionAllow),
		},
		{
			Name:        "Block Path",
			Description: "Block requests to paths containing a specific string",
			Pattern:     "block_path:/admin",
			Category:    "Path Filtering",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Block Path (Regex)",
			Description: "Block requests matching a path regex pattern",
			Pattern:     "block_path_regex:(?i)\\.(git|env|bak)$",
			Category:    "Path Filtering",
			Phase:       string(store.PhaseSignature),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Block Path (Exact)",
			Description: "Block requests to an exact path",
			Pattern:     "block_path_exact:/wp-admin/install.php",
			Category:    "Path Filtering",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Block Query Parameter",
			Description: "Block requests with query strings containing specific text",
			Pattern:     "block_query_contains:union select",
			Category:    "Query Filtering",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Block Query (Regex)",
			Description: "Block requests with query strings matching a regex",
			Pattern:     "block_query_regex:(?i)(union|select|insert|update|delete)",
			Category:    "Query Filtering",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Block Header",
			Description: "Block requests with a specific header value",
			Pattern:     "block_header:X-Scanner:sqlmap",
			Category:    "Header Filtering",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Block Header (Regex)",
			Description: "Block requests with headers matching a regex",
			Pattern:     "block_header_regex:User-Agent:(?i)(bot|crawler|spider)",
			Category:    "Header Filtering",
			Phase:       string(store.PhaseSignature),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Block HTTP Method",
			Description: "Block specific HTTP methods",
			Pattern:     "block_method:TRACE",
			Category:    "Method Filtering",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Block Content-Type",
			Description: "Block requests with specific Content-Type headers",
			Pattern:     "block_content_type:application/x-www-form-urlencoded",
			Category:    "Content Filtering",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Block User-Agent",
			Description: "Block requests from specific user agents",
			Pattern:     "block_user_agent:curl",
			Category:    "User-Agent Filtering",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Block User-Agent (Regex)",
			Description: "Block user agents matching a regex pattern",
			Pattern:     "block_user_agent_regex:(?i)(nikto|nmap|masscan)",
			Category:    "User-Agent Filtering",
			Phase:       string(store.PhaseSignature),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "TLS JA3",
			Description: "Match requests by raw TLS JA3 fingerprint string",
			Pattern:     "tls_ja3:771,4865-4866-4867,0-11-10-35,29-23-24,0",
			Category:    "Fingerprint Filtering",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "TLS JA3 Hash",
			Description: "Match requests by TLS JA3 hash fingerprint",
			Pattern:     "tls_ja3_hash:27a5061c22108817120d1d3870cba0e0",
			Category:    "Fingerprint Filtering",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "TLS JA4",
			Description: "Match requests by TLS JA4 fingerprint",
			Pattern:     "tls_ja4:t13d1516h2_8daaf6152771_e5627efa2ab1",
			Category:    "Fingerprint Filtering",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "TLS Version",
			Description: "Match requests by negotiated TLS version",
			Pattern:     "tls_version:TLS13",
			Category:    "Fingerprint Filtering",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "TLS SNI",
			Description: "Match requests by TLS SNI server name",
			Pattern:     "tls_sni:login.example.com",
			Category:    "Fingerprint Filtering",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "TLS ALPN",
			Description: "Match requests by negotiated TLS ALPN protocol",
			Pattern:     "tls_alpn:h2",
			Category:    "Fingerprint Filtering",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "TLS Cipher Suites",
			Description: "Match requests by advertised TLS cipher suite list",
			Pattern:     "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
			Category:    "Fingerprint Filtering",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Header Order",
			Description: "Match abnormal HTTP header ordering",
			Pattern:     "header_order_contains:user-agent,accept",
			Category:    "Fingerprint Filtering",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Compound Rule (AND)",
			Description: "Block requests matching all conditions",
			Pattern:     `{"op":"and","children":[{"kind":"block_path","arg":"/api"},{"kind":"block_method","arg":"DELETE"}]}`,
			Category:    "Compound Rules",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Compound Rule (OR)",
			Description: "Block requests matching any condition",
			Pattern:     `{"op":"or","children":[{"kind":"block_ip","arg":"1.2.3.4"},{"kind":"block_user_agent","arg":"scanner"}]}`,
			Category:    "Compound Rules",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
	}

	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{
			"templates": templates,
			"total":     len(templates),
		})
	}
}
