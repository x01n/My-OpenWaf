package cve

import (
	"regexp"
	"strings"
)

func init() {
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-graphql-introspection",
		Name:     "GraphQL Introspection Probe",
		CVE:      "CVE-2023-GRAPHQL",
		Severity: "medium",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			combined := strings.ToLower(uri + body)
			if strings.Contains(combined, "__schema") || strings.Contains(combined, "__type") ||
				strings.Contains(combined, "introspectionquery") {
				return &CVEMatch{
					CVEID:       "CVE-2023-GRAPHQL",
					Category:    "cve_general",
					Severity:    "medium",
					Description: "GraphQL introspection query probe detected",
					MatchedPart: "body",
					Pattern:     "graphql-introspection",
					Action:      "log",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-shellshock-ua",
		Name:     "ShellShock via User-Agent",
		CVE:      "CVE-2014-6271",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reShellShock.MatchString(ua) {
				return &CVEMatch{
					CVEID:       "CVE-2014-6271",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "ShellShock Bash injection via User-Agent header",
					MatchedPart: "header",
					Pattern:     "shellshock-ua",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-vite-fs-raw-bypass",
		Name:     "Vite @fs Raw Query File Read Bypass",
		CVE:      "CVE-2025-30208",
		Severity: "high",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reViteFSAccess.MatchString(uri) && reViteRawBypass.MatchString(uri) {
				return &CVEMatch{
					CVEID:       "CVE-2025-30208",
					Category:    "cve_general",
					Severity:    "high",
					Description: "Vite dev server @fs arbitrary file read via ?raw?? or ?import&raw??",
					MatchedPart: "url",
					Pattern:     "vite-fs-raw-bypass",
					Action:      "drop",
				}
			}
			if reViteFSAccess.MatchString(uri) && reViteHTMLBypass.MatchString(uri) {
				return &CVEMatch{
					CVEID:       "CVE-2025-31125",
					Category:    "cve_general",
					Severity:    "high",
					Description: "Vite dev server @fs arbitrary file read via html proxy or inline asset query bypass",
					MatchedPart: "url",
					Pattern:     "vite-fs-html-bypass",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-langflow-validate-code-rce",
		Name:     "Langflow Validate Code Unauthenticated RCE",
		CVE:      "CVE-2025-3248",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reLangflowValidateCode.MatchString(uri) && reLangflowCodeExec.MatchString(body) {
				return &CVEMatch{
					CVEID:       "CVE-2025-3248",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "Langflow validate/code request carrying Python execution primitives",
					MatchedPart: "body",
					Pattern:     "langflow-validate-code-rce",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-xwiki-solrsearch-groovy-rce",
		Name:     "XWiki SolrSearch Groovy Macro RCE",
		CVE:      "CVE-2025-24893",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reXWikiSolrSearch.MatchString(uri) && reXWikiMediaRSS.MatchString(uri) && reXWikiGroovyMacro.MatchString(uri+body) {
				return &CVEMatch{
					CVEID:       "CVE-2025-24893",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "XWiki SolrSearch RSS request carrying async/groovy macro payload",
					MatchedPart: "url",
					Pattern:     "xwiki-solrsearch-groovy-rce",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-sharepoint-toolshell-toolpane",
		Name:     "SharePoint ToolShell ToolPane Exploit",
		CVE:      "CVE-2025-53770",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			referer := headers["Referer"]
			if referer == "" {
				referer = headers["referer"]
			}
			if reSharePointToolPane.MatchString(uri) && reSharePointEditMode.MatchString(uri) && reSharePointSignOut.MatchString(referer) && reSharePointDWP.MatchString(body) {
				return &CVEMatch{
					CVEID:       "CVE-2025-53770",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "SharePoint ToolPane exploit with SignOut referer and ViewState/WebPart payload",
					MatchedPart: "all",
					Pattern:     "sharepoint-toolshell-toolpane",
					Action:      "drop",
				}
			}
			if reSharePointWebShell.MatchString(uri) {
				return &CVEMatch{
					CVEID:       "CVE-2025-53770",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "SharePoint ToolShell web shell access indicator",
					MatchedPart: "url",
					Pattern:     "sharepoint-toolshell-webshell",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-commvault-deploywebpackage-rce",
		Name:     "Commvault deployWebpackage Pre-Auth RCE",
		CVE:      "CVE-2025-34028",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reCommvaultDeploy.MatchString(uri) && reCommvaultDeployParams.MatchString(body) && reCommvaultPayload.MatchString(body) {
				return &CVEMatch{
					CVEID:       "CVE-2025-34028",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "Commvault deployWebpackage SSRF/path traversal pre-auth RCE payload",
					MatchedPart: "all",
					Pattern:     "commvault-deploywebpackage-rce",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-wingftp-null-lua-rce",
		Name:     "Wing FTP NULL Byte Lua RCE",
		CVE:      "CVE-2025-47812",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reWingFTPLoginOK.MatchString(uri) && reWingFTPNullLua.MatchString(body) {
				return &CVEMatch{
					CVEID:       "CVE-2025-47812",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "Wing FTP loginok.html username NULL byte Lua injection payload",
					MatchedPart: "body",
					Pattern:     "wingftp-null-lua-rce",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-magicinfo-swupdate-file-write",
		Name:     "Samsung MagicINFO SWUpdateFileUploader File Write",
		CVE:      "CVE-2025-4632",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reMagicINFOUploader.MatchString(uri) && reMagicINFOFileName.MatchString(uri+body) {
				return &CVEMatch{
					CVEID:       "CVE-2025-4632",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "Samsung MagicINFO SWUpdateFileUploader traversal filename for arbitrary file write",
					MatchedPart: "all",
					Pattern:     "magicinfo-swupdate-file-write",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-fortiweb-fwbcgi-cgiinfo-auth-bypass",
		Name:     "FortiWeb fwbcgi CGIINFO Auth Bypass",
		CVE:      "CVE-2025-64446",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			cgiInfo := headers["CGIINFO"]
			if cgiInfo == "" {
				cgiInfo = headers["cgiinfo"]
			}
			if reFortiWebFWBCGI.MatchString(uri) && reFortiWebCGIInfo.MatchString("CGIINFO: "+cgiInfo) {
				return &CVEMatch{
					CVEID:       "CVE-2025-64446",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "FortiWeb API traversal to fwbcgi with client-supplied CGIINFO identity",
					MatchedPart: "all",
					Pattern:     "fortiweb-fwbcgi-cgiinfo-auth-bypass",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-goanywhere-license-activate-bypass",
		Name:     "GoAnywhere License Activation Auth Bypass",
		CVE:      "CVE-2025-10035",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reGoAnywhereLicense.MatchString(uri) && reGoAnywhereActivate.MatchString(uri) && reGoAnywhereViewState.MatchString(uri) {
				return &CVEMatch{
					CVEID:       "CVE-2025-10035",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "GoAnywhere Unlicensed.xhtml activation request abusing ViewState error flow",
					MatchedPart: "url",
					Pattern:     "goanywhere-license-activate-bypass",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-spring-gateway-actuator-spel",
		Name:     "Spring Cloud Gateway Actuator SpEL Injection",
		CVE:      "CVE-2025-41243",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reSpringGatewayActuator.MatchString(uri) && reSpringGatewaySpEL.MatchString(body+uri) {
				return &CVEMatch{
					CVEID:       "CVE-2025-41243",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "Spring Cloud Gateway actuator route update carrying SpEL-capable filter expression",
					MatchedPart: "all",
					Pattern:     "spring-gateway-actuator-spel",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-invision-customcss-expression-rce",
		Name:     "Invision customCss Template Expression RCE",
		CVE:      "CVE-2025-47916",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reInvisionThemeEditor.MatchString(uri+body) && reInvisionExpression.MatchString(uri+body) {
				return &CVEMatch{
					CVEID:       "CVE-2025-47916",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "Invision themeeditor customCss request carrying executable template expression",
					MatchedPart: "all",
					Pattern:     "invision-customcss-expression-rce",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-crushftp-s3-auth-bypass",
		Name:     "CrushFTP S3 Authorization Auth Bypass",
		CVE:      "CVE-2025-31161",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			authorization := headers["Authorization"]
			if authorization == "" {
				authorization = headers["authorization"]
			}
			if reCrushFTPAdminEndpoint.MatchString(uri) && reCrushFTPS3Auth.MatchString(authorization) {
				return &CVEMatch{
					CVEID:       "CVE-2025-31161",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "CrushFTP administrative function request with mangled AWS4-HMAC Credential",
					MatchedPart: "all",
					Pattern:     "crushftp-s3-auth-bypass",
					Action:      "drop",
				}
			}
			return nil
		},
	})
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-fortinet-authhash-hostcheck-rce",
		Name:     "Fortinet AuthHash hostcheck_validate RCE",
		CVE:      "CVE-2025-32756",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			cookie := headers["Cookie"]
			if cookie == "" {
				cookie = headers["cookie"]
			}
			if reFortinetHostcheck.MatchString(uri) && reFortinetAuthHash.MatchString(cookie) {
				return &CVEMatch{
					CVEID:       "CVE-2025-32756",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "Fortinet hostcheck_validate request carrying oversized AuthHash enc cookie",
					MatchedPart: "cookie",
					Pattern:     "fortinet-authhash-hostcheck-rce",
					Action:      "drop",
				}
			}
			return nil
		},
	})

	// --- 12 new rules ---

	// 1. Spring Data REST RCE (CVE-2017-8046)
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-spring-data-rest-rce",
		Name:     "Spring Data REST JSON Patch SpEL RCE",
		CVE:      "CVE-2017-8046",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			ct := headers["Content-Type"]
			if ct == "" {
				ct = headers["content-type"]
			}
			if reSpringDataRestPatch.MatchString(ct) && reSpringDataRestSpEL.MatchString(body) {
				return &CVEMatch{
					CVEID:       "CVE-2017-8046",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "Spring Data REST PATCH request with SpEL expression in JSON Patch body",
					MatchedPart: "body",
					Pattern:     "spring-data-rest-rce",
					Action:      "drop",
				}
			}
			return nil
		},
	})

	// 2. Jeecg-boot SQL injection (CVE-2023-1454)
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-jeecg-boot-sqli",
		Name:     "Jeecg-boot API SQL Injection",
		CVE:      "CVE-2023-1454",
		Severity: "high",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reJeecgEndpoint.MatchString(uri) {
				combined := uri + body
				if reJeecgSQLi.MatchString(combined) {
					return &CVEMatch{
						CVEID:       "CVE-2023-1454",
						Category:    "cve_general",
						Severity:    "high",
						Description: "Jeecg-boot API endpoint with SQL injection payload",
						MatchedPart: "all",
						Pattern:     "jeecg-boot-sqli",
						Action:      "drop",
					}
				}
			}
			return nil
		},
	})

	// 3. XStream Deserialization RCE (CVE-2021-21351 / CVE-2021-29505)
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-xstream-deser-rce",
		Name:     "XStream Deserialization RCE",
		CVE:      "CVE-2021-21351",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reXStreamXML.MatchString(body) && reXStreamPayload.MatchString(body) {
				return &CVEMatch{
					CVEID:       "CVE-2021-21351",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "XStream XML deserialization payload with dangerous gadget class",
					MatchedPart: "body",
					Pattern:     "xstream-deser-rce",
					Action:      "drop",
				}
			}
			return nil
		},
	})

	// 4. Router OS Command Injection (CVE-2019-3929)
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-router-cmd-inject",
		Name:     "Router CGI OS Command Injection",
		CVE:      "CVE-2019-3929",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reRouterCGIPath.MatchString(uri) {
				combined := uri + "\n" + body
				if reRouterShellMeta.MatchString(combined) {
					part := "body"
					if reRouterShellMeta.MatchString(uri) {
						part = "url"
					}
					return &CVEMatch{
						CVEID:       "CVE-2019-3929",
						Category:    "cve_general",
						Severity:    "critical",
						Description: "Router CGI endpoint with shell metacharacter injection",
						MatchedPart: part,
						Pattern:     "router-cmd-inject",
						Action:      "drop",
					}
				}
			}
			return nil
		},
	})

	// 5. Java Code Injection
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-java-code-inject",
		Name:     "Java Code Injection / OGNL / SpEL",
		CVE:      "CVE-2024-JAVAINJ",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			combined := uri + "\n" + body
			for k, v := range headers {
				lk := strings.ToLower(k)
				if lk == "content-type" || lk == "referer" || lk == "x-forwarded-for" || lk == "cookie" {
					combined += "\n" + v
				}
			}
			if reJavaCodeInject.MatchString(combined) || reJavaOGNLSpEL.MatchString(combined) {
				part := "body"
				if reJavaCodeInject.MatchString(uri) || reJavaOGNLSpEL.MatchString(uri) {
					part = "url"
				}
				return &CVEMatch{
					CVEID:       "CVE-2024-JAVAINJ",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "Java code injection or OGNL/SpEL expression detected",
					MatchedPart: part,
					Pattern:     "java-code-inject",
					Action:      "drop",
				}
			}
			return nil
		},
	})

	// 6. Suspicious Remote Call Protocol / JDBC
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-remote-protocol-jndi",
		Name:     "Suspicious Remote Call Protocol / JDBC",
		CVE:      "CVE-2024-REMOTECALL",
		Severity: "high",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			combined := uri + "\n" + body + "\n" + ua
			for _, v := range headers {
				combined += "\n" + v
			}
			if reRemoteProtocol.MatchString(combined) {
				part := "body"
				if reRemoteProtocol.MatchString(uri) {
					part = "url"
				} else if reRemoteProtocol.MatchString(ua) {
					part = "header"
				} else {
					for _, v := range headers {
						if reRemoteProtocol.MatchString(v) {
							part = "header"
							break
						}
					}
				}
				return &CVEMatch{
					CVEID:       "CVE-2024-REMOTECALL",
					Category:    "cve_general",
					Severity:    "high",
					Description: "Suspicious remote call protocol (rmi/ldap/jndi/jdbc) detected",
					MatchedPart: part,
					Pattern:     "remote-protocol-jndi",
					Action:      "drop",
				}
			}
			return nil
		},
	})

	// 7. Deep Path Traversal
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-deep-path-traversal",
		Name:     "Deep / Encoded Path Traversal",
		CVE:      "CVE-2024-DEEPPATH",
		Severity: "high",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			combined := uri + "\n" + body
			if reDeepPathTraversal.MatchString(combined) {
				part := "url"
				if reDeepPathTraversal.MatchString(body) && !reDeepPathTraversal.MatchString(uri) {
					part = "body"
				}
				return &CVEMatch{
					CVEID:       "CVE-2024-DEEPPATH",
					Category:    "cve_general",
					Severity:    "high",
					Description: "Deep or multiply-encoded path traversal attempt detected",
					MatchedPart: part,
					Pattern:     "deep-path-traversal",
					Action:      "drop",
				}
			}
			return nil
		},
	})

	// 8. XML Entity Injection UTF-7 (XXE)
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-xxe-utf7",
		Name:     "XXE via UTF-7 Encoding",
		CVE:      "CVE-2024-XXEUTF7",
		Severity: "high",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reXXEUTF7Prefix.MatchString(body) && reXXEUTF7Entity.MatchString(body) {
				return &CVEMatch{
					CVEID:       "CVE-2024-XXEUTF7",
					Category:    "cve_general",
					Severity:    "high",
					Description: "UTF-7 encoded XXE payload detected in request body",
					MatchedPart: "body",
					Pattern:     "xxe-utf7",
					Action:      "drop",
				}
			}
			return nil
		},
	})

	// 9. LDAP Injection
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-ldap-injection",
		Name:     "LDAP Injection",
		CVE:      "CVE-2024-LDAPI",
		Severity: "high",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			combined := uri + "\n" + body
			if reLDAPInject.MatchString(combined) {
				part := "url"
				if reLDAPInject.MatchString(body) && !reLDAPInject.MatchString(uri) {
					part = "body"
				}
				return &CVEMatch{
					CVEID:       "CVE-2024-LDAPI",
					Category:    "cve_general",
					Severity:    "high",
					Description: "LDAP injection pattern detected in request parameters",
					MatchedPart: part,
					Pattern:     "ldap-injection",
					Action:      "drop",
				}
			}
			return nil
		},
	})

	// 10. MongoDB NoSQL Injection
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-nosql-injection",
		Name:     "MongoDB NoSQL Injection",
		CVE:      "CVE-2024-NOSQLI",
		Severity: "high",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			combined := uri + "\n" + body
			if reNoSQLInject.MatchString(combined) {
				part := "body"
				if reNoSQLInject.MatchString(uri) {
					part = "url"
				}
				return &CVEMatch{
					CVEID:       "CVE-2024-NOSQLI",
					Category:    "cve_general",
					Severity:    "high",
					Description: "MongoDB NoSQL injection operator detected",
					MatchedPart: part,
					Pattern:     "nosql-injection",
					Action:      "drop",
				}
			}
			return nil
		},
	})

	// 11. Sensitive File Access
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-sensitive-file-access",
		Name:     "Sensitive File Access",
		CVE:      "CVE-2024-SENSFILE",
		Severity: "medium",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if reSensitiveFile.MatchString(uri) {
				return &CVEMatch{
					CVEID:       "CVE-2024-SENSFILE",
					Category:    "cve_general",
					Severity:    "medium",
					Description: "Access attempt to sensitive configuration or system file",
					MatchedPart: "url",
					Pattern:     "sensitive-file-access",
					Action:      "block",
				}
			}
			return nil
		},
	})

	// 12. Low-severity Command Execution
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-low-cmd-exec",
		Name:     "Low-severity OS Command in URL Parameters",
		CVE:      "CVE-2024-LOWCMD",
		Severity: "low",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			combined := uri + "\n" + body
			if reLowSeverityCmd.MatchString(combined) {
				part := "url"
				if reLowSeverityCmd.MatchString(body) && !reLowSeverityCmd.MatchString(uri) {
					part = "body"
				}
				return &CVEMatch{
					CVEID:       "CVE-2024-LOWCMD",
					Category:    "cve_general",
					Severity:    "low",
					Description: "Low-severity OS command detected in request",
					MatchedPart: part,
					Pattern:     "low-cmd-exec",
					Action:      "log",
				}
			}
			return nil
		},
	})
}

// GeneralCVEDetector detects technology-agnostic CVE exploitation patterns.
type GeneralCVEDetector struct {
	rules []generalCVERule
}

type generalCVERule struct {
	cveID       string
	severity    string
	description string
	patterns    []*regexp.Regexp
	target      string
	matchAll    bool // if true, ALL patterns must match (conjunction)
}

var (
	reSSRF_10          = regexp.MustCompile(`(?i)(?:^|[/=?&])https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	reSSRF_172         = regexp.MustCompile(`(?i)(?:^|[/=?&])https?://172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}`)
	reSSRF_192         = regexp.MustCompile(`(?i)(?:^|[/=?&])https?://192\.168\.\d{1,3}\.\d{1,3}`)
	reSSRF_127         = regexp.MustCompile(`(?i)(?:^|[/=?&])https?://127\.0\.0\.\d{1,3}`)
	reSSRF_local       = regexp.MustCompile(`(?i)(?:^|[/=?&])https?://localhost`)
	reSSRF_meta        = regexp.MustCompile(`(?i)169\.254\.169\.254`)
	reSSRF_gcloud      = regexp.MustCompile(`(?i)metadata\.google\.internal`)
	reSSRF_file        = regexp.MustCompile(`(?i)file://`)
	reSSRF_ipv6        = regexp.MustCompile(`(?i)(?:^|[/=?&])https?://\[?::1\]?[:/]`)
	reSSRF_0000        = regexp.MustCompile(`(?i)(?:^|[/=?&])https?://0\.0\.0\.0`)
	reXXE_doctype      = regexp.MustCompile(`(?i)<!DOCTYPE\s`)
	reXXE_entity       = regexp.MustCompile(`(?i)<!ENTITY\s`)
	reXXE_system       = regexp.MustCompile(`(?i)SYSTEM\s+["'](?:file|http|ftp|gopher)://`)
	reXXE_public       = regexp.MustCompile(`(?i)PUBLIC\s+["']-//`)
	rePathTrav_double  = regexp.MustCompile(`(?i)%252[eE]%252[eE]%252[fF]`)
	rePathTrav_utf8    = regexp.MustCompile(`(?i)\.\.%[cC]0%[aA][fF]`)
	rePathTrav_double2 = regexp.MustCompile(`(?i)\.\.\.\./`)
	rePathTrav_win     = regexp.MustCompile(`(?i)\.\.\\`)
	rePathTrav_win5c   = regexp.MustCompile(`(?i)\.\.%5[cC]`)
	rePathTrav_null    = regexp.MustCompile(`(?i)\.\./%00`)
	reCRLF_encoded     = regexp.MustCompile(`(?i)%0[dD]%0[aA]`)
	reCRLF_raw         = regexp.MustCompile(`\r\n`)
	reCRLF_header      = regexp.MustCompile(`(?i)%0[dD]%0[aA](Set-Cookie|Location|Content-Type):`)
	reSmuggle_clte     = regexp.MustCompile(`(?i)transfer-encoding\s*:\s*chunked`)
	reSmuggle_te       = regexp.MustCompile(`(?i)transfer-encoding\s*:\s*[\s,]*(chunked|identity)`)
	reShellShock       = regexp.MustCompile(`(?i)\(\)\s*\{[^}]*\}\s*;`)
	reHeartbleed       = regexp.MustCompile(`(?i)heartbleed`)

	// HTTP header injection
	reHeaderInject = regexp.MustCompile(`(?i)%0[dD]%0[aA]\s*(HTTP/|Content-|Location:|Set-Cookie)`)

	// SAP NetWeaver Visual Composer (CVE-2025-31324)
	reSAPMetadataUploader = regexp.MustCompile(`(?i)/developmentserver/metadatauploader`)
	reSAPIRJServlet       = regexp.MustCompile(`(?i)/irj/servlet`)

	// PHP-CGI argument injection (CVE-2024-4577)
	rePHPCGISoftHyphen  = regexp.MustCompile(`(?i)[%\x00-\xff]ad.*-[dD]\s*(allow_url_include|auto_prepend_file)`)
	rePHPCGIArgInject   = regexp.MustCompile(`(?i)php://input.*allow_url_include|auto_prepend_file.*php://input`)
	rePHPCGISoftHyphen2 = regexp.MustCompile(`%[aA][dD]`)

	// PAN-OS GlobalProtect (CVE-2024-3400)
	rePANOSCookieTraversal = regexp.MustCompile(`(?i)SESSID=.*\.\.`)
	rePANOSGlobalProtect   = regexp.MustCompile(`(?i)/ssl-vpn/hipreport\.esp`)

	// Confluence RCE (CVE-2023-22527)
	reConfluenceOGNL = regexp.MustCompile(`(?i)/template/aui/text-inline\.vm`)

	// Citrix Bleed (CVE-2023-4966)
	reCitrixBleed = regexp.MustCompile(`(?i)/vpn/\.\./vpns/|/vpn/index\.html`)

	// Apache Struts path traversal (CVE-2024-53677)
	reStrutsUpload = regexp.MustCompile(`(?i)top\["[^"]*"\]\s*=`)

	// Ivanti Connect Secure (CVE-2024-21887, CVE-2025-0282)
	reIvantiCSAPI           = regexp.MustCompile(`(?i)/api/v1/totp/user-backup-code/\.\.;/`)
	reIvantiCSWeb           = regexp.MustCompile(`(?i)/dana-na/auth/url_default/welcome\.cgi`)
	reViteFSAccess          = regexp.MustCompile(`(?i)(^|/)@fs/`)
	reViteRawBypass         = regexp.MustCompile(`(?i)(^|[&?])(?:import&)?raw\?\?`)
	reViteHTMLBypass        = regexp.MustCompile(`(?i)(^|[&?])(?:html-proxy|htmlproxy|inline|url)(?:=|&|$)|\.html(?:[?#]|$)`)
	reLangflowValidateCode  = regexp.MustCompile(`(?i)/api/v1/validate/code`)
	reLangflowCodeExec      = regexp.MustCompile(`(?i)(__import__|\b(?:os|subprocess)\s*\.|\b(?:exec|eval|open)\s*\(|import\s+(?:os|subprocess)|child_process)`)
	reXWikiSolrSearch       = regexp.MustCompile(`(?i)/xwiki/bin/get/Main/SolrSearch`)
	reXWikiMediaRSS         = regexp.MustCompile(`(?i)(^|[&?])media=rss(?:&|$)`)
	reXWikiGroovyMacro      = regexp.MustCompile(`(?i)(\{\{\s*(?:async|groovy)\b|%7b%7b\s*(?:async|groovy)\b)`)
	reSharePointToolPane    = regexp.MustCompile(`(?i)/_?layouts/15/ToolPane\.aspx`)
	reSharePointEditMode    = regexp.MustCompile(`(?i)(^|[&?])DisplayMode=Edit(?:&|$|.*a=/_?ToolPane\.aspx)`)
	reSharePointSignOut     = regexp.MustCompile(`(?i)/_?layouts/SignOut\.aspx`)
	reSharePointDWP         = regexp.MustCompile(`(?i)(MSOTlPn_DWP|CompressedDataTable|__VIEWSTATE)`)
	reSharePointWebShell    = regexp.MustCompile(`(?i)/_?layouts/15/(?:spinstall0|info3)\.aspx`)
	reCommvaultDeploy       = regexp.MustCompile(`(?i)/commandcenter/deployWebpackage\.do`)
	reCommvaultDeployParams = regexp.MustCompile(`(?i)(commcellName=.*servicePack=.*version=|servicePack=.*version=.*commcellName=)`)
	reCommvaultPayload      = regexp.MustCompile(`(?i)(\.\./|%2e%2e|https?://|/commandcenter/webpackage\.do|\.zip\b)`)
	reMultipartFormData     = regexp.MustCompile(`(?i)multipart/form-data`)
	reDangerousCharset      = regexp.MustCompile(`(?i)charset\s*=\s*["']?(?:utf-7|utf-16|utf-32|shift[_-]?jis|euc-jp|gb2312|gbk|iso-2022-jp|x-imap4-modified-utf7)`)
	reWingFTPLoginOK        = regexp.MustCompile(`(?i)/loginok\.html`)
	reWingFTPNullLua        = regexp.MustCompile(`(?i)(%00|\x00).*(?:io\.popen|os\.execute|loadstring|dofile|local\s+\w+\s*=|%5d%5d|\]\])`)
	reMagicINFOUploader     = regexp.MustCompile(`(?i)/MagicInfo/servlet/SWUpdateFileUploader`)
	reMagicINFOFileName     = regexp.MustCompile(`(?i)fileName\s*=.*(?:\.\./|%2e%2e|\.\.\\|%5c).*(?:\.jsp|\.jspx|\.war|\.html?)`)
	reFortiWebFWBCGI        = regexp.MustCompile(`(?i)/api/v2\.0/(?:cmdb|cmd)/.*(?:%3f|\?).*(?:\.\./|%2e%2e).*/cgi-bin/fwbcgi`)
	reFortiWebCGIInfo       = regexp.MustCompile(`(?i)CGIINFO\s*[:=]\s*[A-Za-z0-9+/=]{20,}`)
	reGoAnywhereLicense     = regexp.MustCompile(`(?i)/(?:goanywhere/)?license/Unlicensed\.xhtml/[^?\s]*`)
	reGoAnywhereActivate    = regexp.MustCompile(`(?i)(?:^|[&?])GARequestAction=activate(?:&|$)`)
	reGoAnywhereViewState   = regexp.MustCompile(`(?i)(?:^|[&?])javax\.faces\.ViewState=`)
	reSpringGatewayActuator = regexp.MustCompile(`(?i)/actuator/gateway/(?:routes|refresh)`)
	reSpringGatewaySpEL     = regexp.MustCompile(`(?i)(#\{|%23%7b|T\s*\(|AddResponseHeader|SetResponseHeader|RewritePath|RequestRateLimiter)`)
	reInvisionThemeEditor   = regexp.MustCompile(`(?i)(?:^|[&?\s/])app=core(?:&|$).*module=system.*controller=themeeditor.*do=customCss`)
	reInvisionExpression    = regexp.MustCompile(`(?i)(?:content=)?(?:%7b|\{)expression(?:\s*=|%3d).*?(?:system|exec|shell_exec|passthru|base64_decode|eval|die)`)
	reCrushFTPS3Auth        = regexp.MustCompile(`(?i)AWS4-HMAC-SHA256\s+Credential=[^,\s]+/`)
	reCrushFTPAdminEndpoint = regexp.MustCompile(`(?i)/WebInterface/function/.*command=(?:getUserList|setUserItem|zip|login)`)
	reFortinetHostcheck     = regexp.MustCompile(`(?i)/remote/hostcheck_validate`)
	reFortinetAuthHash      = regexp.MustCompile(`(?i)AuthHash=[^;]*(?:enc=|%65%6e%63%3d)?[A-Za-z0-9+/=%]{80,}`)

	// --- New rules ---

	// Spring Data REST RCE (CVE-2017-8046): JSON Patch with SpEL
	reSpringDataRestPatch = regexp.MustCompile(`(?i)application/json-patch\+json|application/merge-patch\+json`)
	reSpringDataRestSpEL  = regexp.MustCompile(`(?i)(?:new\s+java\.lang\.ProcessBuilder|T\s*\(\s*java\.lang\.Runtime\s*\)|\.getRuntime\s*\(\s*\)\.exec|spring\.cloud\.bootstrap|org\.springframework|\.getClass\s*\(\s*\)\.forName|#this\.getClass|java\.lang\.(?:Thread|ClassLoader)|beanFactory|applicationContext|getEnvironment)`)

	// Jeecg-boot SQLi (CVE-2023-1454)
	reJeecgEndpoint = regexp.MustCompile(`(?i)/(?:sys/(?:dict/load(?:TreeData|Dict)|duplicate/check|user/query(?:SysUser|UserByDepId)|permission/getPermCode|category/loadAllData)|jmreport/(?:queryFieldBySql|testConnection|dictTableWhite))`)
	reJeecgSQLi     = regexp.MustCompile(`(?i)(?:(?:union\s+(?:all\s+)?select|select\s+.*\bfrom\b|insert\s+into|update\s+.*\bset\b|delete\s+from|drop\s+(?:table|database)|sleep\s*\(|benchmark\s*\(|waitfor\s+delay|extractvalue\s*\(|updatexml\s*\(|load_file\s*\(|into\s+(?:outfile|dumpfile))|\b(?:and|or)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|'\s*(?:or|and)\s+['"]?\d|--\s*$|#\s*$)`)

	// XStream Deserialization RCE (CVE-2021-21351 / CVE-2021-29505)
	reXStreamPayload = regexp.MustCompile(`(?i)(?:<sorted-set>|<java\.util\.PriorityQueue|<dynamic-proxy>|<javax\.naming\.ldap\.Rdn\$RdnEntry|ProcessBuilder.*</|<java\.lang\.Runtime|<sun\.reflect\.annotation|<java\.beans\.EventHandler|<com\.sun\.rowset\.JdbcRowSetImpl|<org\.apache\.xalan|<org\.apache\.commons\.(?:beanutils|collections)|<javassist\.tools\.web\.Viewer|<java\.security\.SignedObject)`)
	reXStreamXML     = regexp.MustCompile(`(?i)(?:<\?xml\s|<(?:map|list|set|object-stream|linked-hash-set|tree-set|sorted-set|java\.util|javax\.)\b)`)

	// Router OS Command Injection (CVE-2019-3929)
	reRouterCGIPath   = regexp.MustCompile(`(?i)/(?:cgi-bin/|ping\.cgi|syscmd\.cgi|diagnostic\.cgi|test-cgi|shell\.cgi|command\.cgi|webcm|goform/|apply\.cgi|tmUnblock\.cgi|admin/config\.cgi|debug\.cgi|boardData\w*\.php|formLogin)`)
	reRouterShellMeta = regexp.MustCompile("(?:[;|&]|\\$\\(|`|\\n|%0[aAdD]|%7[cC]|%3[bB])")

	// Java Code Injection
	reJavaCodeInject = regexp.MustCompile(`(?i)(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|new\s+ProcessBuilder|Class\s*\.\s*forName\s*\(|java\.lang\.reflect\.Method\s*\.\s*invoke|javax\.script\.ScriptEngine|\.getMethod\s*\(\s*["'](?:exec|invoke|forName|getRuntime)|java\.lang\.ProcessBuilder|ScriptEngineManager|\.newInstance\s*\(\s*\)|Unsafe\.getUnsafe|sun\.misc\.Unsafe)`)
	reJavaOGNLSpEL   = regexp.MustCompile(`(?i)(?:#\{\s*T\s*\(|%23%7[bB]|ognlUtil|_memberAccess|valueStack|#context\[|ActionContext|#_memberAccess|#attr\[|#application\[|#session\[|#request\[|#parameters\[|#root\b|\.getClass\(\)\.forName|%24%7[bB]|java\.lang\.\w+\)\.|\$\{.*T\(java\.)`)

	// Suspicious Remote Call Protocol / JDBC
	reRemoteProtocol = regexp.MustCompile(`(?i)(?:rmi://|ldaps?://|jndi:|jdbc:(?:mysql|postgresql|oracle|sqlserver|h2|derby|mariadb|sqlite)|iiop://|corba://|t3://|t3s://|dns://[^/]*\.\w+/|(?:^|[&?=])(?:rmi|ldap|jndi|jdbc|dns)://)`)

	// Deep Path Traversal
	reDeepPathTraversal = regexp.MustCompile(`(?i)(?:\.\.\.\.//|\\\.\\\.\\\.\\\.\\\\|%252[eE]%252[eE]/|\.\.%[cC]0%[aA][fF]|\.\.%[eE][fF]%[bB][cC]%8[fF]|(?:\.\./){4,}|(?:\.\.\\){4,}|(?:%2[eE]%2[eE](?:%2[fF]|%5[cC])){4,}|\.\.%25%35%63|\.\.%c1%1c|\.\.%c1%9c|\.\.%c0%9v|\.\.%uff0e%uff0e|%c0%ae%c0%ae/|\.\.;/|/\.%2e/\.%2e/)`)

	// XXE UTF-7
	reXXEUTF7Prefix = regexp.MustCompile(`\+ADw-`)
	reXXEUTF7Entity = regexp.MustCompile(`(?i)(?:\+ADw-\s*!DOCTYPE|\+ADw-\s*!ENTITY|SYSTEM|PUBLIC)`)

	// LDAP Injection
	reLDAPInject = regexp.MustCompile(`(?i)(?:\)\s*\(\s*\|\s*\(|\*\)\s*\(\s*(?:objectclass|objectCategory|cn|uid|sAMAccountName|mail|memberOf)\s*=\s*\*|\\00|%00.*\(|\)\s*\(\s*[&|!]\s*\(|(?:^|[&?=])\(\s*[&|]\s*\(|\x00|\)\(cn=\*\))`)

	// MongoDB NoSQL Injection
	reNoSQLInject = regexp.MustCompile(`(?i)(?:\{\s*["']?\$(?:gt|ne|regex|where|or|and|not|exists|elemMatch|nin|lt|gte|lte|in|type|size|all|mod)\b|\$(?:gt|ne|regex|where|or|and|not|exists|nin|lt|gte|lte|in)\s*[:\[{]|\[\s*\$(?:gt|ne|regex|where|or|and)\b|"\$(?:gt|ne|regex|where|or|and|not)"|\$where\s*:\s*["']?\s*(?:function|this\.)|\$regex\s*:\s*["']|(?:^|[&?])[\w.]*\[\$(?:gt|ne|regex|where)\])`)

	// Sensitive File Access
	reSensitiveFile = regexp.MustCompile(`(?i)(?:/\.env(?:\b|\.\w+|$)|/\.git/(?:config|HEAD|index|refs|objects|logs)|/\.gitignore|/\.htaccess|/\.htpasswd|/wp-config\.php(?:\.bak|\.old|\.swp|~)?|/web\.config|/database\.yml|/settings\.py|/application\.(?:properties|yml|yaml)|/etc/(?:passwd|shadow|hosts|my\.cnf|redis\.conf)|/\.DS_Store|/\.svn/entries|/\.svn/wc\.db|/\.idea/workspace\.xml|/\.vscode/settings\.json|/composer\.(?:json|lock)|/package\.json|/Gemfile(?:\.lock)?|/requirements\.txt|/Dockerfile|/docker-compose\.ya?ml|/\.aws/credentials|/\.ssh/(?:id_rsa|authorized_keys)|/\.bash_history|/\.mysql_history|/phpinfo\.php|/adminer\.php|/info\.php|/server-status|/server-info|/\.well-known/security\.txt|/backup\.(?:sql|zip|tar\.gz|bak)|/dump\.sql|/WEB-INF/web\.xml|/META-INF/MANIFEST\.MF)`)

	// Low-severity Command Execution in URL
	reLowSeverityCmd = regexp.MustCompile(`(?i)(?:^|[&?=|;\x60\s])(?:whoami|(?:^|\b)id(?:\b|$)|uname(?:\s+-[a-z])?|hostname|ifconfig|ipconfig|systeminfo|net\s+user|cat\s+/etc/(?:passwd|shadow|hosts)|ls\s+-la|pwd|w(?:ho)?(?:\s|$)|env(?:\s|$)|set(?:\s|$)|printenv|curl\s+|wget\s+|nslookup\s+|dig\s+|traceroute\s+|ping\s+-[nc])\s*(?:[&;|)\x60]|%[0-9a-f]{2}|$)`)
)

// NewGeneralCVEDetector creates a general CVE detector with built-in rules.
func NewGeneralCVEDetector() *GeneralCVEDetector {
	d := &GeneralCVEDetector{}
	d.rules = []generalCVERule{
		{
			cveID: "CVE-2019-SSRF", severity: "high",
			description: "SSRF attempt targeting internal network, cloud metadata, or local files",
			patterns: []*regexp.Regexp{
				reSSRF_10, reSSRF_172, reSSRF_192, reSSRF_127, reSSRF_local,
				reSSRF_meta, reSSRF_gcloud, reSSRF_file, reSSRF_ipv6, reSSRF_0000,
			},
			target: "all",
		},
		{
			cveID: "CVE-2018-XXE", severity: "high",
			description: "XML External Entity (XXE) injection via DOCTYPE/ENTITY declaration",
			patterns:    []*regexp.Regexp{reXXE_doctype, reXXE_entity, reXXE_system, reXXE_public},
			target:      "body",
		},
		{
			cveID: "CVE-2019-PATHTRA", severity: "medium",
			description: "Enhanced path traversal via double encoding, UTF-8, or Windows-style backslash",
			patterns:    []*regexp.Regexp{rePathTrav_double, rePathTrav_utf8, rePathTrav_double2, rePathTrav_win, rePathTrav_win5c, rePathTrav_null},
			target:      "url",
		},
		{
			cveID: "CVE-2019-CRLF", severity: "medium",
			description: "CRLF injection in URL parameters or header values",
			patterns:    []*regexp.Regexp{reCRLF_encoded, reCRLF_raw, reCRLF_header},
			target:      "all",
		},
		{
			cveID: "CVE-2023-SMUGGLE", severity: "high",
			description: "HTTP request smuggling via CL-TE or TE-CL mismatch",
			patterns:    []*regexp.Regexp{reSmuggle_clte},
			target:      "header",
		},
		{
			cveID: "CVE-2014-6271", severity: "critical",
			description: "ShellShock Bash function definition injection",
			patterns:    []*regexp.Regexp{reShellShock},
			target:      "all",
		},
		{
			cveID: "CVE-2019-HEADER-INJECT", severity: "medium",
			description: "HTTP header injection via CRLF in parameter values",
			patterns:    []*regexp.Regexp{reHeaderInject},
			target:      "all",
		},
		// 2024-2025 Critical CVEs
		{
			cveID: "CVE-2025-31324", severity: "critical",
			description: "SAP NetWeaver Visual Composer unauthenticated file upload RCE",
			patterns:    []*regexp.Regexp{reSAPMetadataUploader},
			target:      "url",
		},
		{
			cveID: "CVE-2024-4577", severity: "critical",
			description: "PHP-CGI argument injection via soft-hyphen (Best-Fit mapping bypass)",
			patterns:    []*regexp.Regexp{rePHPCGISoftHyphen, rePHPCGIArgInject},
			target:      "all",
		},
		{
			cveID: "CVE-2024-3400", severity: "critical",
			description: "PAN-OS GlobalProtect command injection via SESSID cookie traversal",
			patterns:    []*regexp.Regexp{rePANOSCookieTraversal, rePANOSGlobalProtect},
			target:      "all",
		},
		{
			cveID: "CVE-2023-22527", severity: "critical",
			description: "Confluence Server OGNL injection via template endpoint",
			patterns:    []*regexp.Regexp{reConfluenceOGNL},
			target:      "url",
		},
		{
			cveID: "CVE-2023-4966", severity: "critical",
			description: "Citrix Bleed information disclosure via path traversal",
			patterns:    []*regexp.Regexp{reCitrixBleed},
			target:      "url",
		},
		{
			cveID: "CVE-2024-53677", severity: "critical",
			description: "Apache Struts file upload path traversal RCE",
			patterns:    []*regexp.Regexp{reStrutsUpload},
			target:      "all",
		},
		{
			cveID: "CVE-2024-21887", severity: "critical",
			description: "Ivanti Connect Secure path traversal and command injection",
			patterns:    []*regexp.Regexp{reIvantiCSAPI, reIvantiCSWeb},
			target:      "url",
		},
		{
			cveID: "CVE-2025-30208", severity: "high",
			description: "Vite dev server arbitrary file read via @fs raw query bypass",
			patterns:    []*regexp.Regexp{reViteFSAccess, reViteRawBypass},
			target:      "url",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-3248", severity: "critical",
			description: "Langflow unauthenticated code execution via validate/code endpoint",
			patterns:    []*regexp.Regexp{reLangflowValidateCode, reLangflowCodeExec},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-24893", severity: "critical",
			description: "XWiki SolrSearch unauthenticated Groovy macro RCE",
			patterns:    []*regexp.Regexp{reXWikiSolrSearch, reXWikiMediaRSS, reXWikiGroovyMacro},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-53770", severity: "critical",
			description: "Microsoft SharePoint ToolShell ToolPane exploit with SignOut referer and ViewState/WebPart payload",
			patterns:    []*regexp.Regexp{reSharePointToolPane, reSharePointEditMode, reSharePointSignOut, reSharePointDWP},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-53770", severity: "critical",
			description: "Microsoft SharePoint ToolShell web shell access indicator",
			patterns:    []*regexp.Regexp{reSharePointWebShell},
			target:      "url",
		},
		{
			cveID: "CVE-2025-34028", severity: "critical",
			description: "Commvault Command Center pre-auth deployWebpackage SSRF/path traversal RCE",
			patterns:    []*regexp.Regexp{reCommvaultDeploy, reCommvaultDeployParams, reCommvaultPayload},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2026-21876", severity: "critical",
			description: "OWASP CRS multipart charset bypass using dangerous non-final part charset",
			patterns:    []*regexp.Regexp{reMultipartFormData, reDangerousCharset},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-47812", severity: "critical",
			description: "Wing FTP Server NULL byte Lua session code injection via loginok.html",
			patterns:    []*regexp.Regexp{reWingFTPLoginOK, reWingFTPNullLua},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-4632", severity: "critical",
			description: "Samsung MagicINFO SWUpdateFileUploader path traversal arbitrary file write",
			patterns:    []*regexp.Regexp{reMagicINFOUploader, reMagicINFOFileName},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-64446", severity: "critical",
			description: "Fortinet FortiWeb API path traversal to fwbcgi with forged CGIINFO identity",
			patterns:    []*regexp.Regexp{reFortiWebFWBCGI, reFortiWebCGIInfo},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-10035", severity: "critical",
			description: "Fortra GoAnywhere MFT license activation authentication bypass precondition",
			patterns:    []*regexp.Regexp{reGoAnywhereLicense, reGoAnywhereActivate, reGoAnywhereViewState},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-41243", severity: "critical",
			description: "Spring Cloud Gateway WebFlux actuator SpEL route property modification",
			patterns:    []*regexp.Regexp{reSpringGatewayActuator, reSpringGatewaySpEL},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-47916", severity: "critical",
			description: "Invision Community themeeditor customCss template expression RCE",
			patterns:    []*regexp.Regexp{reInvisionThemeEditor, reInvisionExpression},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-31161", severity: "critical",
			description: "CrushFTP S3 AWS4-HMAC authentication bypass against administrative function endpoint",
			patterns:    []*regexp.Regexp{reCrushFTPAdminEndpoint, reCrushFTPS3Auth},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-32756", severity: "critical",
			description: "Fortinet AuthHash enc cookie overflow via hostcheck_validate",
			patterns:    []*regexp.Regexp{reFortinetHostcheck, reFortinetAuthHash},
			target:      "all",
			matchAll:    true,
		},
	}
	return d
}

// Detect scans the request for general CVE exploitation attempts.
func (d *GeneralCVEDetector) Detect(req *CVERequest) []CVEMatch {
	var matches []CVEMatch

	// Special handling: HTTP request smuggling checks both CL and TE headers.
	if checkHTTPSmuggling(req) {
		matches = append(matches, CVEMatch{
			CVEID:       "CVE-2023-SMUGGLE",
			Category:    "general",
			Severity:    "high",
			Description: "HTTP request smuggling: Content-Length and Transfer-Encoding both present",
			MatchedPart: "header",
			Pattern:     "CL+TE simultaneous",
			Action:      "drop",
		})
	}

	for _, rule := range d.rules {
		if rule.cveID == "CVE-2023-SMUGGLE" {
			continue // handled above
		}
		if rule.matchAll {
			if matchAllPatterns(req, rule) {
				matches = append(matches, CVEMatch{
					CVEID:       rule.cveID,
					Category:    "general",
					Severity:    rule.severity,
					Description: rule.description,
					MatchedPart: rule.target,
					Pattern:     "conjunction match",
					Action:      "drop",
				})
			}
			continue
		}
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
						Category:    "general",
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

// checkHTTPSmuggling detects when both Content-Length and Transfer-Encoding headers
// are present simultaneously, or TE contains malformed values.
func checkHTTPSmuggling(req *CVERequest) bool {
	hasCL := false
	hasTE := false
	for k, v := range req.Headers {
		kl := strings.ToLower(k)
		if kl == "content-length" {
			hasCL = true
		}
		if kl == "transfer-encoding" {
			hasTE = true
			// Check for obfuscated chunked value.
			vl := strings.ToLower(v)
			if strings.Contains(vl, " chunked") || strings.Contains(vl, "\tchunked") ||
				strings.Contains(vl, "chunked ") || strings.Contains(vl, ",chunked") {
				return true // obfuscated TE
			}
		}
	}
	return hasCL && hasTE
}

// matchAllPatterns returns true only if ALL patterns in the rule match.
func matchAllPatterns(req *CVERequest, rule generalCVERule) bool {
	targets := resolveTargets(req, rule.target)
	combined := strings.Join(targets, "\n")
	for _, pat := range rule.patterns {
		if !pat.MatchString(combined) {
			return false
		}
	}
	return true
}
