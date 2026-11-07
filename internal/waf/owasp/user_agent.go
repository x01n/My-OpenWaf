package owasp

import "strings"

/**
 * maliciousClientUASignature 描述一个确定性攻击工具 User-Agent 特征。
 *
 * @property needle 小写匹配子串。
 * @property name 工具可读名称，用于命中说明。
 */
type maliciousClientUASignature struct {
	needle string
	name   string
}

// maliciousClientUASignatures 只收录攻击工具自报标识。curl、python-requests、
// go-http-client 等通用 HTTP 客户端不在此列，避免把正常自动化流量判成攻击。
var maliciousClientUASignatures = []maliciousClientUASignature{
	{"sqlmap", "sqlmap"},
	{"nikto", "nikto"},
	{"nmap", "nmap"},
	{"masscan", "masscan"},
	{"zmap", "zmap"},
	{"openvas", "openvas"},
	{"nessus", "nessus"},
	{"qualys", "qualys"},
	{"acunetix", "acunetix"},
	{"netsparker", "netsparker"},
	{"burpcollaborator", "burp collaborator"},
	{"burpsuite", "burp suite"},
	{"burp suite", "burp suite"},
	{"dirbuster", "dirbuster"},
	{"gobuster", "gobuster"},
	{"wfuzz", "wfuzz"},
	{"ffuf", "ffuf"},
	{"faster u fool", "ffuf"},
	{"feroxbuster", "feroxbuster"},
	{"nuclei", "nuclei"},
	{"zgrab", "zgrab"},
	{"xspider", "xspider"},
	{"crawler4j", "crawler4j"},
	{"commix", "commix"},
	{"xsser", "xsser"},
	{"w3af", "w3af"},
	{"skipfish", "skipfish"},
	{"arachni", "arachni"},
	{"joomscan", "joomscan"},
	{"wpscan", "wpscan"},
	{"droopescan", "droopescan"},
	{"shodan", "shodan"},
	{"censys", "censys"},
	{"zoomeye", "zoomeye"},
	{"havij", "havij"},
	{"pangolin", "pangolin"},
	{"metasploit", "metasploit"},
	{"thc-hydra", "hydra"},
	{"patator", "patator"},
	{"mercuryboard_user_agent_sql_injection", "mercuryboard sqli scanner"},
	{"interact.sh", "interactsh oast"},
	{"oast.", "oast callback"},
}

/**
 * headerUserAgent 从已标准化的请求头表中取 User-Agent 原始值。
 *
 * @param headers 请求头映射，键大小写不保证统一。
 * @returns User-Agent 值；不存在时返回空串。
 */
func headerUserAgent(headers map[string]string) string {
	if value, ok := headers["user-agent"]; ok {
		return value
	}
	for key, value := range headers {
		if strings.EqualFold(key, "user-agent") {
			return value
		}
	}
	return ""
}

/**
 * CheckMaliciousUserAgent 用确定性签名识别攻击/扫描工具的 User-Agent。
 *
 * @param userAgent 原始 User-Agent 值。
 * @returns 命中结果；未命中时 ok 为 false。
 */
func CheckMaliciousUserAgent(userAgent string) (OWASPHit, bool) {
	userAgent = strings.TrimSpace(userAgent)
	if userAgent == "" {
		return OWASPHit{}, false
	}
	lower := toLowerASCII(userAgent)
	for _, signature := range maliciousClientUASignatures {
		if !strings.Contains(lower, signature.needle) {
			continue
		}
		return OWASPHit{
			Category: CatMaliciousClient,
			RuleID:   "owasp:client:001",
			Score:    8,
			Snippet:  userAgentSnippet(userAgent),
			Desc:     "恶意攻击工具 User-Agent：" + signature.name,
		}, true
	}
	return OWASPHit{}, false
}

// userAgentSnippet 限制命中片段长度，避免把超长 UA 原样带入日志。
func userAgentSnippet(userAgent string) string {
	const maxSnippet = 160
	if len(userAgent) <= maxSnippet {
		return userAgent
	}
	return userAgent[:maxSnippet] + "..."
}
