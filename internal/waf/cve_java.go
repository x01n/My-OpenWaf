package waf

import (
	"regexp"
)

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
	reFastjson1     = regexp.MustCompile(`(?i)"@type"\s*:\s*"`)
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
	reShiro1        = regexp.MustCompile(`(?i)rememberMe=`)
	reJackson1      = regexp.MustCompile(`(?i)\["org\.apache\.commons\.`)
	reJackson2      = regexp.MustCompile(`(?i)com\.sun\.org\.apache\.xalan`)
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
