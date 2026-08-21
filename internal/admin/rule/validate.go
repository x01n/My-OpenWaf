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
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}

		pattern := strings.TrimSpace(req.Pattern)
		if pattern == "" {
			c.JSON(400, ValidateRuleResponse{
				Valid:   false,
				Message: "规则表达式不能为空",
			})
			return
		}

		kind, arg := rules.ParsePattern(pattern)
		if kind == "" {
			c.JSON(200, ValidateRuleResponse{
				Valid:   false,
				Message: "规则表达式格式无效",
				Errors:  []string{"规则表达式必须以合法的匹配器前缀开头，或使用合法的复合条件 JSON"},
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
				Message: "规则表达式无法编译",
				Errors:  validationErrors,
			})
			return
		}

		c.JSON(200, ValidateRuleResponse{
			Valid:   true,
			Message: "规则表达式有效",
			Kind:    kind,
			Arg:     arg,
		})
	}
}

func GetRuleTemplates() app.HandlerFunc {
	templates := []RuleTemplate{
		{
			Name:        "拦截 IP 地址",
			Description: "拦截来自特定 IP 或 CIDR 段的请求",
			Pattern:     "block_ip:192.168.1.100",
			Category:    "IP 过滤",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "放行 IP 地址",
			Description: "放行来自特定 IP 或 CIDR 段的请求（绕过 WAF）",
			Pattern:     "allow_ip:10.0.0.0/8",
			Category:    "IP 过滤",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionAllow),
		},
		{
			Name:        "拦截路径",
			Description: "拦截路径中包含特定字符串的请求",
			Pattern:     "block_path:/admin",
			Category:    "路径过滤",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "拦截路径（正则）",
			Description: "拦截路径符合正则模式的请求",
			Pattern:     "block_path_regex:(?i)\\.(git|env|bak)$",
			Category:    "路径过滤",
			Phase:       string(store.PhaseSignature),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "拦截路径（精确）",
			Description: "拦截精确路径的请求",
			Pattern:     "block_path_exact:/wp-admin/install.php",
			Category:    "路径过滤",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "拦截查询参数",
			Description: "拦截查询字符串包含特定文本的请求",
			Pattern:     "block_query_contains:union select",
			Category:    "查询过滤",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "拦截查询（正则）",
			Description: "拦截查询字符串符合正则的请求",
			Pattern:     "block_query_regex:(?i)(union|select|insert|update|delete)",
			Category:    "查询过滤",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "拦截 Header",
			Description: "拦截包含特定 header 值的请求",
			Pattern:     "block_header:X-Scanner:sqlmap",
			Category:    "Header 过滤",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "拦截 Header（正则）",
			Description: "拦截 header 符合正则的请求",
			Pattern:     "block_header_regex:User-Agent:(?i)(bot|crawler|spider)",
			Category:    "Header 过滤",
			Phase:       string(store.PhaseSignature),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "拦截 HTTP 方法",
			Description: "拦截特定 HTTP 方法",
			Pattern:     "block_method:TRACE",
			Category:    "方法过滤",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "拦截 Content-Type",
			Description: "拦截包含特定 Content-Type 头的请求",
			Pattern:     "block_content_type:application/x-www-form-urlencoded",
			Category:    "内容过滤",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "拦截 User-Agent",
			Description: "拦截来自特定 User-Agent 的请求",
			Pattern:     "block_user_agent:curl",
			Category:    "User-Agent 过滤",
			Phase:       string(store.PhaseACL),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "拦截 User-Agent（正则）",
			Description: "拦截符合正则模式的 User-Agent",
			Pattern:     "block_user_agent_regex:(?i)(nikto|nmap|masscan)",
			Category:    "User-Agent 过滤",
			Phase:       string(store.PhaseSignature),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "TLS JA3",
			Description: "按原始 TLS JA3 指纹字符串匹配请求",
			Pattern:     "tls_ja3:771,4865-4866-4867,0-11-10-35,29-23-24,0",
			Category:    "指纹过滤",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "TLS JA3 哈希",
			Description: "按 TLS JA3 哈希指纹匹配请求",
			Pattern:     "tls_ja3_hash:27a5061c22108817120d1d3870cba0e0",
			Category:    "指纹过滤",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "TLS JA4",
			Description: "按 TLS JA4 指纹匹配请求",
			Pattern:     "tls_ja4:t13d1516h2_8daaf6152771_e5627efa2ab1",
			Category:    "指纹过滤",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "TLS 版本",
			Description: "按协商的 TLS 版本匹配请求",
			Pattern:     "tls_version:TLS13",
			Category:    "指纹过滤",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "TLS SNI",
			Description: "按 TLS SNI 服务器名匹配请求",
			Pattern:     "tls_sni:login.example.com",
			Category:    "指纹过滤",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "TLS ALPN",
			Description: "按协商的 TLS ALPN 协议匹配请求",
			Pattern:     "tls_alpn:h2",
			Category:    "指纹过滤",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "TLS 密码套件",
			Description: "按 TLS 密码套件列表匹配请求",
			Pattern:     "tls_cipher_suites:TLS_AES_128_GCM_SHA256",
			Category:    "指纹过滤",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "Header 顺序",
			Description: "匹配异常的 HTTP Header 顺序",
			Pattern:     "header_order_contains:user-agent,accept",
			Category:    "指纹过滤",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "复合规则（与）",
			Description: "拦截所有条件都满足的请求",
			Pattern:     `{"op":"and","children":[{"kind":"block_path","arg":"/api"},{"kind":"block_method","arg":"DELETE"}]}`,
			Category:    "复合规则",
			Phase:       string(store.PhaseCustom),
			Action:      string(store.ActionIntercept),
		},
		{
			Name:        "复合规则（或）",
			Description: "拦截任一条件满足的请求",
			Pattern:     `{"op":"or","children":[{"kind":"block_ip","arg":"1.2.3.4"},{"kind":"block_user_agent","arg":"scanner"}]}`,
			Category:    "复合规则",
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
