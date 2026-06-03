package rule

import (
	"context"
	"strings"

	"My-OpenWaf/internal/store"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/rules"
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

		if len(rules.Compile([]store.Rule{{Pattern: pattern, Phase: store.PhaseCustom, Action: store.ActionObserve, Enabled: true}})) == 0 {
			c.JSON(200, ValidateRuleResponse{
				Valid:   false,
				Message: "pattern cannot be compiled",
				Errors:  []string{"pattern uses an unsupported matcher or invalid regular expression"},
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
		},
		{
			Name:        "Allow IP Address",
			Description: "Allow requests from a specific IP address or CIDR range (bypasses WAF)",
			Pattern:     "allow_ip:10.0.0.0/8",
			Category:    "IP Filtering",
		},
		{
			Name:        "Block Path",
			Description: "Block requests to paths containing a specific string",
			Pattern:     "block_path:/admin",
			Category:    "Path Filtering",
		},
		{
			Name:        "Block Path (Regex)",
			Description: "Block requests matching a path regex pattern",
			Pattern:     "block_path_regex:(?i)\\.(git|env|bak)$",
			Category:    "Path Filtering",
		},
		{
			Name:        "Block Path (Exact)",
			Description: "Block requests to an exact path",
			Pattern:     "block_path_exact:/wp-admin/install.php",
			Category:    "Path Filtering",
		},
		{
			Name:        "Block Query Parameter",
			Description: "Block requests with query strings containing specific text",
			Pattern:     "block_query_contains:union select",
			Category:    "Query Filtering",
		},
		{
			Name:        "Block Query (Regex)",
			Description: "Block requests with query strings matching a regex",
			Pattern:     "block_query_regex:(?i)(union|select|insert|update|delete)",
			Category:    "Query Filtering",
		},
		{
			Name:        "Block Header",
			Description: "Block requests with a specific header value",
			Pattern:     "block_header:X-Scanner:sqlmap",
			Category:    "Header Filtering",
		},
		{
			Name:        "Block Header (Regex)",
			Description: "Block requests with headers matching a regex",
			Pattern:     "block_header_regex:User-Agent:(?i)(bot|crawler|spider)",
			Category:    "Header Filtering",
		},
		{
			Name:        "Block HTTP Method",
			Description: "Block specific HTTP methods",
			Pattern:     "block_method:TRACE",
			Category:    "Method Filtering",
		},
		{
			Name:        "Block Content-Type",
			Description: "Block requests with specific Content-Type headers",
			Pattern:     "block_content_type:application/x-www-form-urlencoded",
			Category:    "Content Filtering",
		},
		{
			Name:        "Block User-Agent",
			Description: "Block requests from specific user agents",
			Pattern:     "block_user_agent:curl",
			Category:    "User-Agent Filtering",
		},
		{
			Name:        "Block User-Agent (Regex)",
			Description: "Block user agents matching a regex pattern",
			Pattern:     "block_user_agent_regex:(?i)(nikto|nmap|masscan)",
			Category:    "User-Agent Filtering",
		},
		{
			Name:        "TLS JA3 Hash",
			Description: "Match requests by TLS JA3 hash fingerprint",
			Pattern:     "tls_ja3_hash:27a5061c22108817120d1d3870cba0e0",
			Category:    "Fingerprint Filtering",
		},
		{
			Name:        "TLS JA4",
			Description: "Match requests by TLS JA4 fingerprint",
			Pattern:     "tls_ja4:t13d1516h2_8daaf6152771_e5627efa2ab1",
			Category:    "Fingerprint Filtering",
		},
		{
			Name:        "Header Order",
			Description: "Match abnormal HTTP header ordering",
			Pattern:     "header_order_contains:user-agent,accept",
			Category:    "Fingerprint Filtering",
		},
		{
			Name:        "Compound Rule (AND)",
			Description: "Block requests matching all conditions",
			Pattern:     `{"op":"and","children":[{"kind":"block_path","arg":"/api"},{"kind":"block_method","arg":"DELETE"}]}`,
			Category:    "Compound Rules",
		},
		{
			Name:        "Compound Rule (OR)",
			Description: "Block requests matching any condition",
			Pattern:     `{"op":"or","children":[{"kind":"block_ip","arg":"1.2.3.4"},{"kind":"block_user_agent","arg":"scanner"}]}`,
			Category:    "Compound Rules",
		},
	}

	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]any{
			"templates": templates,
			"total":     len(templates),
		})
	}
}
