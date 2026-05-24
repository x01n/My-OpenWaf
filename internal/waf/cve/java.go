package cve

import (
	"regexp"
)

func init() {
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-log4j-obfuscated",
		Name:     "Log4Shell Obfuscated JNDI Lookup",
		CVE:      "CVE-2021-44228",
		Severity: "critical",
		Category: "cve_java",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			// Check all inputs for obfuscated log4j patterns
			for _, s := range []string{uri, body, ua} {
				if reLog4j1.MatchString(s) || reLog4j2.MatchString(s) || reLog4j3.MatchString(s) ||
					reLog4j4.MatchString(s) || reLog4j5.MatchString(s) || reLog4j6.MatchString(s) || reLog4j7.MatchString(s) {
					return &CVEMatch{
						CVEID:       "CVE-2021-44228",
						Category:    "cve_java",
						Severity:    "critical",
						Description: "Log4Shell JNDI injection via obfuscated lookup",
						MatchedPart: "all",
						Pattern:     "log4j-obfuscated",
						Action:      "drop",
					}
				}
			}
			// Also check header values
			for _, v := range headers {
				if reLog4j1.MatchString(v) || reLog4j5.MatchString(v) {
					return &CVEMatch{
						CVEID:       "CVE-2021-44228",
						Category:    "cve_java",
						Severity:    "critical",
						Description: "Log4Shell JNDI injection via HTTP header",
						MatchedPart: "header",
						Pattern:     "log4j-header",
						Action:      "drop",
					}
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-tomcat-session-deser",
		Name:     "Apache Tomcat Session Deserialization",
		CVE:      "CVE-2025-24813",
		Severity: "critical",
		Category: "cve_java",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reTomcat1.MatchString(uri) {
				return &CVEMatch{
					CVEID:       "CVE-2025-24813",
					Category:    "cve_java",
					Severity:    "critical",
					Description: "Apache Tomcat session deserialization via .ser file path",
					MatchedPart: "url",
					Pattern:     "tomcat-session-deser",
					Action:      "drop",
				}
			}
			return nil
		},
	})
}

// JavaCVEDetector detects Java-specific CVE exploitation attempts.
type JavaCVEDetector struct {
	rules []javaCVERule
}

type javaCVERule struct {
	cveID       string
	severity    string
	description string
	patterns    []*regexp.Regexp
	target      string
}

// Compiled Java CVE patterns (init-time).
var (
	reLog4j1        = regexp.MustCompile(`(?i)\$\{jndi:(ldap|rmi|dns|iiop|corba|nds|http)://`)
	reLog4j2        = regexp.MustCompile(`(?i)\$\{\$\{[a-z:]*\}ndi:`)
	reLog4j3        = regexp.MustCompile(`(?i)\$\{j\$\{[:\-a-z]*\}n?di:`)
	reLog4j4        = regexp.MustCompile(`(?i)\$\{(lower|upper|env|sys|java|:)+[:\-}]*j`)
	reLog4j5        = regexp.MustCompile(`(?i)%24%7Bjndi:`)
	reLog4j6        = regexp.MustCompile(`(?i)\$\{j\$\{::-n\}di:`)
	reLog4j7        = regexp.MustCompile(`(?i)\$\{jn\$\{::-d\}i:`)
	reSpring4Shell1 = regexp.MustCompile(`(?i)class\.module\.classLoader`)
	reSpring4Shell2 = regexp.MustCompile(`(?i)spring\.datasource`)
	reSpring4Shell3 = regexp.MustCompile(`(?i)class\.classLoader\.resources`)
	reSpring4Shell4 = regexp.MustCompile(`(?i)class\.module\.classLoader\.defaultAssertionStatus`)
	reSpringCloud1  = regexp.MustCompile(`(?i)spring\.cloud\.function\.routing-expression`)
	reSpringCloud2  = regexp.MustCompile(`(?i)T\(java\.lang\.Runtime\)`)
	reFastjson1     = regexp.MustCompile(`(?i)"@type"\s*:\s*"(com\.sun\.|java\.|javax\.|org\.apache\.)`)
	reFastjson2     = regexp.MustCompile(`(?i)com\.sun\.rowset\.JdbcRowSetImpl`)
	reFastjson3     = regexp.MustCompile(`(?i)java\.lang\.Runtime`)
	reFastjson4     = regexp.MustCompile(`(?i)java\.net\.(URL|InetAddress)`)
	reFastjson5     = regexp.MustCompile(`(?i)org\.apache\.xbean`)
	reFastjson6     = regexp.MustCompile(`(?i)com\.mchange\.v2\.c3p0`)
	reFastjson7     = regexp.MustCompile(`(?i)javax\.naming\.InitialContext`)
	reStruts1       = regexp.MustCompile(`(?i)%\{[^}]*\}`)
	reStruts2       = regexp.MustCompile(`(?i)#_memberAccess`)
	reStruts3       = regexp.MustCompile(`(?i)#rt\s*=\s*@java\.lang\.Runtime`)
	reStruts4       = regexp.MustCompile(`(?i)ognl\.OgnlContext`)
	reStruts5       = regexp.MustCompile(`(?i)multipart/form-data.*%\{`)
	reStruts6       = regexp.MustCompile(`(?i)\$\{[^}]*\}`)
	reShiro1        = regexp.MustCompile(`(?i)rememberMe=[A-Za-z0-9+/=]{100,}`)
	reJackson1      = regexp.MustCompile(`(?i)\["org\.apache\.commons\.`)
	reJackson2      = regexp.MustCompile(`(?i)com\.sun\.org\.apache\.xalan`)

	// Apache OFBiz Auth Bypass + RCE (CVE-2023-49070, CVE-2023-51467)
	reOFBiz1 = regexp.MustCompile(`(?i)/webtools/control/(xmlrpc|main|ViewHandlerExt)`)
	reOFBiz2 = regexp.MustCompile(`(?i)/accounting/control/.*requirePasswordChange=Y`)

	// Apache Tomcat deserialization (CVE-2025-24813)
	reTomcat1 = regexp.MustCompile(`(?i)\.session\.\d+\.ser`)

	// Apache ActiveMQ RCE (CVE-2023-46604)
	reActiveMQ = regexp.MustCompile(`(?i)ExceptionResponse.*ClassPathXmlApplicationContext|ClassInfo.*org\.springframework`)

	// Confluence OGNL injection (CVE-2022-26134)
	reConfluence1 = regexp.MustCompile(`(?i)/\$\{[^}]*\}/?$`)
	reConfluence2 = regexp.MustCompile(`(?i)#a=@java\.lang\.Runtime@getRuntime`)
)

func NewJavaCVEDetector() *JavaCVEDetector {
	d := &JavaCVEDetector{}
	d.rules = []javaCVERule{
		{
			cveID: "CVE-2021-44228", severity: "critical",
			description: "Log4Shell JNDI injection via Log4j2 lookup",
			patterns:    []*regexp.Regexp{reLog4j1, reLog4j2, reLog4j3, reLog4j4, reLog4j5, reLog4j6, reLog4j7},
			target:      "all",
		},
		{
			cveID: "CVE-2022-22965", severity: "critical",
			description: "Spring4Shell class loader manipulation RCE",
			patterns:    []*regexp.Regexp{reSpring4Shell1, reSpring4Shell2, reSpring4Shell3, reSpring4Shell4},
			target:      "all",
		},
		{
			cveID: "CVE-2022-22963", severity: "critical",
			description: "Spring Cloud Function SpEL injection RCE",
			patterns:    []*regexp.Regexp{reSpringCloud1, reSpringCloud2},
			target:      "all",
		},
		{
			cveID: "CVE-2017-18349", severity: "critical",
			description: "Fastjson deserialization via @type gadget chain",
			patterns:    []*regexp.Regexp{reFastjson1, reFastjson2, reFastjson3, reFastjson4, reFastjson5, reFastjson6, reFastjson7},
			target:      "body",
		},
		{
			cveID: "CVE-2017-5638", severity: "critical",
			description: "Struts2 OGNL injection via Content-Type or parameter names",
			patterns:    []*regexp.Regexp{reStruts1, reStruts2, reStruts3, reStruts4, reStruts5},
			target:      "all",
		},
		{
			cveID: "CVE-2016-4437", severity: "high",
			description: "Apache Shiro rememberMe deserialization",
			patterns:    []*regexp.Regexp{reShiro1},
			target:      "cookie",
		},
		{
			cveID: "CVE-2017-7525", severity: "high",
			description: "Jackson deserialization via polymorphic type handling",
			patterns:    []*regexp.Regexp{reJackson1, reJackson2},
			target:      "body",
		},
		{
			cveID: "CVE-2023-49070", severity: "critical",
			description: "Apache OFBiz auth bypass and RCE via webtools endpoint",
			patterns:    []*regexp.Regexp{reOFBiz1, reOFBiz2},
			target:      "url",
		},
		{
			cveID: "CVE-2023-46604", severity: "critical",
			description: "Apache ActiveMQ RCE via ClassPathXml deserialization",
			patterns:    []*regexp.Regexp{reActiveMQ},
			target:      "body",
		},
		{
			cveID: "CVE-2022-26134", severity: "critical",
			description: "Confluence OGNL injection via URL path expression",
			patterns:    []*regexp.Regexp{reConfluence1, reConfluence2},
			target:      "all",
		},
	}
	return d
}

func (d *JavaCVEDetector) Detect(req *CVERequest) []CVEMatch {
	var matches []CVEMatch
	for _, rule := range d.rules {
		targets := resolveTargets(req, rule.target)
		for _, t := range targets {
			for _, pat := range rule.patterns {
				if pat.MatchString(t) {
					part := rule.target
					if part == "all" {
						part = guessMatchedPart(req, t)
					}
					matches = append(matches, CVEMatch{
						CVEID:       rule.cveID,
						Category:    "java",
						Severity:    rule.severity,
						Description: rule.description,
						MatchedPart: part,
						Pattern:     pat.String(),
						Action:      "drop",
					})
					goto nextRule
				}
			}
		}
	nextRule:
	}
	return matches
}
