package rule

import (
	"context"
	"encoding/json"
	"strings"

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

		// Additional validation for compound JSON rules
		if kind == "compound" {
			var compoundRule map[string]interface{}
			if err := json.Unmarshal([]byte(arg), &compoundRule); err != nil {
				c.JSON(200, ValidateRuleResponse{
					Valid:   false,
					Message: "invalid JSON compound rule",
					Errors:  []string{err.Error()},
				})
				return
			}

			// Validate compound rule structure
			if op, ok := compoundRule["op"].(string); !ok || (op != "and" && op != "or" && op != "not") {
				c.JSON(200, ValidateRuleResponse{
					Valid:   false,
					Message: "invalid compound rule operator",
					Errors:  []string{"op must be 'and', 'or', or 'not'"},
				})
				return
			}

			if _, ok := compoundRule["children"]; !ok {
				c.JSON(200, ValidateRuleResponse{
					Valid:   false,
					Message: "invalid compound rule structure",
					Errors:  []string{"compound rule must have 'children' array"},
				})
				return
			}
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
			Name:        "Compound Rule (AND)",
			Description: "Block requests matching all conditions",
			Pattern:     `{"op":"and","children":[{"pattern":"block_path:/api"},{"pattern":"block_method:DELETE"}]}`,
			Category:    "Compound Rules",
		},
		{
			Name:        "Compound Rule (OR)",
			Description: "Block requests matching any condition",
			Pattern:     `{"op":"or","children":[{"pattern":"block_ip:1.2.3.4"},{"pattern":"block_user_agent:scanner"}]}`,
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
