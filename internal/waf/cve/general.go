package cve

import (
	"regexp"
	"strings"
)

func init() {
	globalCVERuleRegistry.Register(&CVERule{
		ID:       "cve-graphql-introspection",
		Name:     "GraphQL 内省探测",
		CVE:      "CVE-2023-GRAPHQL",
		Severity: "medium",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			combined := strings.ToLower(uri + body)
			if hasGraphQLIntrospectionSignalLower(combined) {
				return &CVEMatch{
					CVEID:       "CVE-2023-GRAPHQL",
					Category:    "cve_general",
					Severity:    "medium",
					Description: "检测到 GraphQL 内省查询探测",
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
		Name:     "ShellShock User-Agent 攻击",
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
					Description: "通过 User-Agent 请求头进行 ShellShock Bash 注入",
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
		Name:     "Vite @fs 原始查询文件读取绕过",
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
					Description: "Vite 开发服务器 @fs 通过 ?raw?? 或 ?import&raw?? 进行任意文件读取",
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
					Description: "Vite 开发服务器 @fs 通过 html 代理或内联资源查询绕过进行任意文件读取",
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
		Name:     "Langflow 未认证 Validate Code RCE",
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
					Description: "Langflow validate/code 请求携带 Python 执行原语",
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
		Name:     "XWiki SolrSearch Groovy 宏 RCE",
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
					Description: "XWiki SolrSearch RSS 请求携带 async/groovy 宏载荷",
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
		Name:     "SharePoint ToolShell ToolPane 漏洞利用",
		CVE:      "CVE-2025-53770",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			referer := cveHeaderValue(headers, "Referer")
			if reSharePointToolPane.MatchString(uri) && reSharePointEditMode.MatchString(uri) && reSharePointSignOut.MatchString(referer) && reSharePointDWP.MatchString(body) {
				return &CVEMatch{
					CVEID:       "CVE-2025-53770",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "SharePoint ToolPane 漏洞利用，包含 SignOut referer 和 ViewState/WebPart 载荷",
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
					Description: "SharePoint ToolShell Web Shell 访问迹象",
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
		Name:     "Commvault deployWebpackage 预认证 RCE",
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
					Description: "Commvault deployWebpackage SSRF/路径遍历预认证 RCE 载荷",
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
		Name:     "Wing FTP NULL 字节 Lua RCE",
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
					Description: "Wing FTP loginok.html 用户名 NULL 字节 Lua 注入载荷",
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
		Name:     "Samsung MagicINFO SWUpdateFileUploader 文件写入",
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
					Description: "Samsung MagicINFO SWUpdateFileUploader 遍历文件名进行任意文件写入",
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
		Name:     "FortiWeb fwbcgi CGIINFO 认证绕过",
		CVE:      "CVE-2025-64446",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			cgiInfo := cveHeaderValue(headers, "CGIINFO")
			if reFortiWebFWBCGI.MatchString(uri) && reFortiWebCGIInfo.MatchString("CGIINFO: "+cgiInfo) {
				return &CVEMatch{
					CVEID:       "CVE-2025-64446",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "FortiWeb API 遍历至 fwbcgi，并携带客户端提供的 CGIINFO 身份",
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
		Name:     "GoAnywhere 许可证激活认证绕过",
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
					Description: "GoAnywhere Unlicensed.xhtml 激活请求滥用 ViewState 错误流程",
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
		Name:     "Spring Cloud Gateway Actuator SpEL 注入",
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
					Description: "Spring Cloud Gateway actuator 路由更新携带支持 SpEL 的过滤器表达式",
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
		Name:     "Invision customCss 模板表达式 RCE",
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
					Description: "Invision themeeditor customCss 请求携带可执行模板表达式",
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
		Name:     "CrushFTP S3 Authorization 认证绕过",
		CVE:      "CVE-2025-31161",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			authorization := cveHeaderValue(headers, "Authorization")
			if reCrushFTPAdminEndpoint.MatchString(uri) && reCrushFTPS3Auth.MatchString(authorization) {
				return &CVEMatch{
					CVEID:       "CVE-2025-31161",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "CrushFTP 管理功能请求包含篡改的 AWS4-HMAC 凭据",
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
		Name:     "Fortinet AuthHash hostcheck_validate 远程代码执行（RCE）",
		CVE:      "CVE-2025-32756",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			cookie := cveHeaderValue(headers, "Cookie")
			if reFortinetHostcheck.MatchString(uri) && reFortinetAuthHash.MatchString(cookie) {
				return &CVEMatch{
					CVEID:       "CVE-2025-32756",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "Fortinet hostcheck_validate 请求携带超长 AuthHash enc Cookie",
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
		Name:     "Spring Data REST JSON Patch SpEL 远程代码执行（RCE）",
		CVE:      "CVE-2017-8046",
		Severity: "critical",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			ct := cveHeaderValue(headers, "Content-Type")
			if reSpringDataRestPatch.MatchString(ct) && reSpringDataRestSpEL.MatchString(body) {
				return &CVEMatch{
					CVEID:       "CVE-2017-8046",
					Category:    "cve_general",
					Severity:    "critical",
					Description: "Spring Data REST PATCH 请求的 JSON Patch 请求体包含 SpEL 表达式",
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
		Name:     "Jeecg-boot API SQL 注入",
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
						Description: "Jeecg-boot API 端点包含 SQL 注入载荷",
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
		Name:     "XStream 反序列化 RCE",
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
					Description: "XStream XML 反序列化载荷包含危险 gadget 类",
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
		Name:     "Router CGI OS 命令注入",
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
						Description: "Router CGI 端点包含 Shell 元字符注入",
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
		Name:     "Java 代码注入 / OGNL / SpEL",
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
					Description: "检测到 Java 代码注入或 OGNL/SpEL 表达式",
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
		Name:     "可疑远程调用协议 / JDBC",
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
					Description: "检测到可疑远程调用协议（rmi/ldap/jndi/jdbc）",
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
		Name:     "深度 / 编码路径遍历",
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
					Description: "检测到深度或多重编码的路径遍历尝试",
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
		Name:     "通过 UTF-7 的 XXE",
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
					Description: "请求体中检测到 UTF-7 编码的 XXE 载荷",
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
		Name:     "LDAP 注入",
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
					Description: "请求参数中检测到 LDAP 注入模式",
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
		Name:     "MongoDB NoSQL 注入",
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
					Description: "检测到 MongoDB NoSQL 注入操作符",
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
		Name:     "敏感文件访问",
		CVE:      "CVE-2024-SENSFILE",
		Severity: "medium",
		Category: "cve_general",
		Enabled:  true,
		CheckFunc: func(uri, body, ua string, headers map[string]string) *CVEMatch {
			if isPackageManifestRequest(uri, headers) {
				return nil
			}
			if reSensitiveFile.MatchString(uri) {
				return &CVEMatch{
					CVEID:       "CVE-2024-SENSFILE",
					Category:    "cve_general",
					Severity:    "medium",
					Description: "尝试访问敏感配置文件或系统文件",
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
		Name:     "URL 参数中的低严重性 OS 命令",
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
					Description: "请求中检测到低严重性 OS 命令",
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
	reShellShock       = regexp.MustCompile(`(?i)\(\)\s*\{[^}]*\}\s*;`)

	// HTTP header injection
	reHeaderInject = regexp.MustCompile(`(?i)%0[dD]%0[aA]\s*(HTTP/|Content-|Location:|Set-Cookie)`)

	// SAP NetWeaver Visual Composer (CVE-2025-31324)
	reSAPMetadataUploader = regexp.MustCompile(`(?i)/developmentserver/metadatauploader`)

	// PHP-CGI argument injection (CVE-2024-4577)
	rePHPCGISoftHyphen = regexp.MustCompile(`(?i)[%\x00-\xff]ad.*-[dD]\s*(allow_url_include|auto_prepend_file)`)
	rePHPCGIArgInject  = regexp.MustCompile(`(?i)php://input.*allow_url_include|auto_prepend_file.*php://input`)

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
			description: "针对内部网络、云元数据或本地文件的 SSRF 尝试",
			patterns: []*regexp.Regexp{
				reSSRF_10, reSSRF_172, reSSRF_192, reSSRF_127, reSSRF_local,
				reSSRF_meta, reSSRF_gcloud, reSSRF_file, reSSRF_ipv6, reSSRF_0000,
			},
			target: "url_body",
		},
		{
			cveID: "CVE-2018-XXE", severity: "high",
			description: "通过 DOCTYPE/ENTITY 声明进行 XML 外部实体（XXE）注入",
			patterns:    []*regexp.Regexp{reXXE_doctype, reXXE_entity, reXXE_system, reXXE_public},
			target:      "body",
		},
		{
			cveID: "CVE-2019-PATHTRA", severity: "medium",
			description: "通过双重编码、UTF-8 或 Windows 风格反斜杠进行增强型路径遍历",
			patterns:    []*regexp.Regexp{rePathTrav_double, rePathTrav_utf8, rePathTrav_double2, rePathTrav_win, rePathTrav_win5c, rePathTrav_null},
			target:      "url",
		},
		{
			cveID: "CVE-2019-CRLF", severity: "medium",
			description: "URL 参数或请求头中的 CRLF 注入",
			patterns:    []*regexp.Regexp{reCRLF_encoded, reCRLF_raw, reCRLF_header},
			target:      "all",
		},
		{
			cveID: "CVE-2023-SMUGGLE", severity: "high",
			description: "通过 CL-TE 或 TE-CL 不匹配进行 HTTP 请求走私",
			patterns:    []*regexp.Regexp{reSmuggle_clte},
			target:      "header",
		},
		{
			cveID: "CVE-2014-6271", severity: "critical",
			description: "ShellShock Bash 函数定义注入",
			patterns:    []*regexp.Regexp{reShellShock},
			target:      "all",
		},
		{
			cveID: "CVE-2019-HEADER-INJECT", severity: "medium",
			description: "参数值中的 CRLF HTTP 请求头注入",
			patterns:    []*regexp.Regexp{reHeaderInject},
			target:      "all",
		},
		// 2024-2025 Critical CVEs
		{
			cveID: "CVE-2025-31324", severity: "critical",
			description: "SAP NetWeaver Visual Composer 未认证文件上传 RCE",
			patterns:    []*regexp.Regexp{reSAPMetadataUploader},
			target:      "url",
		},
		{
			cveID: "CVE-2024-4577", severity: "critical",
			description: "通过软连字符（Best-Fit 映射绕过）进行 PHP-CGI 参数注入",
			patterns:    []*regexp.Regexp{rePHPCGISoftHyphen, rePHPCGIArgInject},
			target:      "all",
		},
		{
			cveID: "CVE-2024-3400", severity: "critical",
			description: "通过 SESSID Cookie 路径遍历进行 PAN-OS GlobalProtect 命令注入",
			patterns:    []*regexp.Regexp{rePANOSCookieTraversal, rePANOSGlobalProtect},
			target:      "all",
		},
		{
			cveID: "CVE-2023-22527", severity: "critical",
			description: "通过模板端点进行 Confluence Server OGNL 注入",
			patterns:    []*regexp.Regexp{reConfluenceOGNL},
			target:      "url",
		},
		{
			cveID: "CVE-2023-4966", severity: "critical",
			description: "通过路径遍历进行 Citrix Bleed 信息泄露",
			patterns:    []*regexp.Regexp{reCitrixBleed},
			target:      "url",
		},
		{
			cveID: "CVE-2024-53677", severity: "critical",
			description: "Apache Struts 文件上传路径遍历 RCE",
			patterns:    []*regexp.Regexp{reStrutsUpload},
			target:      "all",
		},
		{
			cveID: "CVE-2024-21887", severity: "critical",
			description: "Ivanti Connect Secure 路径遍历和命令注入",
			patterns:    []*regexp.Regexp{reIvantiCSAPI, reIvantiCSWeb},
			target:      "url",
		},
		{
			cveID: "CVE-2025-30208", severity: "high",
			description: "Vite 开发服务器通过 @fs 原始查询绕过进行任意文件读取",
			patterns:    []*regexp.Regexp{reViteFSAccess, reViteRawBypass},
			target:      "url",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-3248", severity: "critical",
			description: "通过 validate/code 端点进行 Langflow 未认证代码执行",
			patterns:    []*regexp.Regexp{reLangflowValidateCode, reLangflowCodeExec},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-24893", severity: "critical",
			description: "XWiki SolrSearch 未认证 Groovy 宏 RCE",
			patterns:    []*regexp.Regexp{reXWikiSolrSearch, reXWikiMediaRSS, reXWikiGroovyMacro},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-53770", severity: "critical",
			description: "Microsoft SharePoint ToolShell ToolPane 漏洞利用，包含 SignOut referer 和 ViewState/WebPart 载荷",
			patterns:    []*regexp.Regexp{reSharePointToolPane, reSharePointEditMode, reSharePointSignOut, reSharePointDWP},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-53770", severity: "critical",
			description: "Microsoft SharePoint ToolShell Web Shell 访问迹象",
			patterns:    []*regexp.Regexp{reSharePointWebShell},
			target:      "url",
		},
		{
			cveID: "CVE-2025-34028", severity: "critical",
			description: "Commvault Command Center 预认证 deployWebpackage SSRF/路径遍历 RCE",
			patterns:    []*regexp.Regexp{reCommvaultDeploy, reCommvaultDeployParams, reCommvaultPayload},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2026-21876", severity: "critical",
			description: "OWASP CRS 利用危险的非最终 part charset 绕过 multipart charset 检查",
			patterns:    []*regexp.Regexp{reMultipartFormData, reDangerousCharset},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-47812", severity: "critical",
			description: "Wing FTP Server 通过 loginok.html 进行 NULL 字节 Lua 会话代码注入",
			patterns:    []*regexp.Regexp{reWingFTPLoginOK, reWingFTPNullLua},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-4632", severity: "critical",
			description: "Samsung MagicINFO SWUpdateFileUploader 路径遍历任意文件写入",
			patterns:    []*regexp.Regexp{reMagicINFOUploader, reMagicINFOFileName},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-64446", severity: "critical",
			description: "Fortinet FortiWeb API 路径遍历至 fwbcgi 并伪造 CGIINFO 身份",
			patterns:    []*regexp.Regexp{reFortiWebFWBCGI, reFortiWebCGIInfo},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-10035", severity: "critical",
			description: "Fortra GoAnywhere MFT 许可证激活认证绕过前置条件",
			patterns:    []*regexp.Regexp{reGoAnywhereLicense, reGoAnywhereActivate, reGoAnywhereViewState},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-41243", severity: "critical",
			description: "Spring Cloud Gateway WebFlux actuator SpEL 路由属性修改",
			patterns:    []*regexp.Regexp{reSpringGatewayActuator, reSpringGatewaySpEL},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-47916", severity: "critical",
			description: "Invision Community themeeditor customCss 模板表达式 RCE",
			patterns:    []*regexp.Regexp{reInvisionThemeEditor, reInvisionExpression},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-31161", severity: "critical",
			description: "CrushFTP S3 AWS4-HMAC 针对管理功能端点的认证绕过",
			patterns:    []*regexp.Regexp{reCrushFTPAdminEndpoint, reCrushFTPS3Auth},
			target:      "all",
			matchAll:    true,
		},
		{
			cveID: "CVE-2025-32756", severity: "critical",
			description: "Fortinet AuthHash enc Cookie 通过 hostcheck_validate 溢出",
			patterns:    []*regexp.Regexp{reFortinetHostcheck, reFortinetAuthHash},
			target:      "all",
			matchAll:    true,
		},
	}
	return d
}

func shouldScanGeneralRule(req *CVERequest, rule generalCVERule, hits *subDetectorHits) bool {
	switch rule.cveID {
	case "CVE-2019-SSRF":
		return requestTargetContainsSSRF(req, rule.target)
	case "CVE-2019-CRLF":
		return requestTargetContainsCRLF(req, rule.target)
	case "CVE-2019-HEADER-INJECT":
		return requestTargetContainsHeaderInject(req, rule.target)
	case "CVE-2024-4577":
		return requestTargetContainsPHPCGIArgInject(req, rule.target)
	case "CVE-2024-3400":
		return requestTargetContainsPANOSGlobalProtect(req, rule.target)
	case "CVE-2025-34028":
		return requestHasCommvaultDeploySignal(req)
	case "CVE-2024-JAVAINJ":
		return lowerTargetsHaveJavaInjectSignal(req.AllTargetsLower)
	case "CVE-2024-DEEPPATH":
		return lowerTargetsHaveDeepPathTraversalSignal(req.AllTargetsLower)
	case "CVE-2024-NOSQLI":
		return lowerTargetsHaveNoSQLInjectSignal(req.AllTargetsLower)
	case "CVE-2018-XXE", "CVE-2019-PATHTRA", "CVE-2014-6271", "CVE-2025-31324",
		"CVE-2023-22527", "CVE-2023-4966", "CVE-2024-53677", "CVE-2024-21887",
		"CVE-2025-30208", "CVE-2025-3248", "CVE-2025-24893", "CVE-2025-53770",
		"CVE-2026-21876", "CVE-2025-47812", "CVE-2025-4632", "CVE-2025-64446",
		"CVE-2025-10035", "CVE-2025-41243", "CVE-2025-47916", "CVE-2025-31161",
		"CVE-2025-32756", "CVE-2024-SENSFILE", "CVE-2017-8046", "CVE-2023-1454",
		"CVE-2021-21351", "CVE-2019-3929", "CVE-2024-REMOTECALL", "CVE-2024-XXEUTF7",
		"CVE-2024-LDAPI", "CVE-2024-LOWCMD":
		return subDetectorACGate(rule.cveID, rule.target, hits)
	default:
		return true
	}
}

func requestTargetContainsSSRF(req *CVERequest, target string) bool {
	return requestTargetContainsAny(req, target,
		"://10.", "://172.16.", "://172.17.", "://172.18.", "://172.19.", "://172.2", "://172.30.", "://172.31.",
		"://192.168.", "://127.0.0.", "://localhost", "169.254.169.254", "metadata.google.internal",
		"file://", "://0.0.0.0", "://[::1", "://::1")
}

func requestTargetContainsCRLF(req *CVERequest, target string) bool {
	return requestTargetContainsAny(req, target, "%0d%0a", "\r\n")
}

func requestTargetContainsHeaderInject(req *CVERequest, target string) bool {
	return requestTargetContainsAny(req, target, "%0d%0a") &&
		requestTargetContainsAny(req, target, "http/", "content-", "location:", "set-cookie")
}

func requestTargetContainsPHPCGIArgInject(req *CVERequest, target string) bool {
	return requestTargetContainsAny(req, target, "allow_url_include", "auto_prepend_file") &&
		requestTargetContainsAny(req, target, "%ad", "ad", "php://input")
}

func requestTargetContainsPANOSGlobalProtect(req *CVERequest, target string) bool {
	return requestTargetContainsAny(req, target, "/ssl-vpn/hipreport.esp") ||
		(requestTargetContainsAny(req, target, "sessid=") && requestTargetContainsAny(req, target, ".."))
}

func (d *GeneralCVEDetector) Detect(req *CVERequest, hits *subDetectorHits) []CVEMatch {
	var matches []CVEMatch

	// Special handling: HTTP request smuggling checks both CL and TE headers.
	if checkHTTPSmuggling(req) {
		matches = append(matches, CVEMatch{
			CVEID:       "CVE-2023-SMUGGLE",
			Category:    "general",
			Severity:    "high",
			Description: "HTTP 请求走私：同时存在 Content-Length 和 Transfer-Encoding",
			MatchedPart: "header",
			Pattern:     "CL+TE simultaneous",
			Action:      "drop",
		})
	}

	allTargets := req.AllTargets
	urlTargets := req.URLTargets
	bodyTargets := req.BodyTargets
	urlBodyTargets := req.URLBodyTargets
	headerTargets := req.HeaderTargets

	for _, rule := range d.rules {
		if rule.cveID == "CVE-2024-SENSFILE" && isPackageManifestRequest(req.Path, req.Headers) {
			continue
		}
		if rule.cveID == "CVE-2023-SMUGGLE" {
			continue // handled above
		}
		if !shouldScanGeneralRule(req, rule, hits) {
			continue
		}

		var targets []string
		switch rule.target {
		case "url":
			targets = urlTargets
		case "body":
			targets = bodyTargets
		case "url_body":
			targets = urlBodyTargets
		case "header":
			targets = headerTargets
		default:
			targets = allTargets
		}
		if len(targets) == 0 {
			continue
		}

		if rule.matchAll {
			matchedAll := true
			for _, pat := range rule.patterns {
				matched := false
				for _, target := range targets {
					if pat.MatchString(target) {
						matched = true
						break
					}
				}
				if !matched {
					matchedAll = false
					break
				}
			}
			if matchedAll {
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

func (d *GeneralCVEDetector) DetectFirst(req *CVERequest, hits *subDetectorHits) (CVEMatch, bool) {
	if checkHTTPSmuggling(req) {
		return CVEMatch{
			CVEID:       "CVE-2023-SMUGGLE",
			Category:    "general",
			Severity:    "high",
			Description: "HTTP 请求走私：同时存在 Content-Length 和 Transfer-Encoding",
			MatchedPart: "header",
			Pattern:     "CL+TE simultaneous",
			Action:      "drop",
		}, true
	}

	allTargets := req.AllTargets
	urlTargets := req.URLTargets
	bodyTargets := req.BodyTargets
	urlBodyTargets := req.URLBodyTargets
	headerTargets := req.HeaderTargets

	for _, rule := range d.rules {
		if rule.cveID == "CVE-2024-SENSFILE" && isPackageManifestRequest(req.Path, req.Headers) {
			continue
		}
		if rule.cveID == "CVE-2023-SMUGGLE" {
			continue
		}
		if !shouldScanGeneralRule(req, rule, hits) {
			continue
		}

		var targets []string
		switch rule.target {
		case "url":
			targets = urlTargets
		case "body":
			targets = bodyTargets
		case "url_body":
			targets = urlBodyTargets
		case "header":
			targets = headerTargets
		default:
			targets = allTargets
		}
		if len(targets) == 0 {
			continue
		}

		if rule.matchAll {
			matchedAll := true
			for _, pat := range rule.patterns {
				matched := false
				for _, target := range targets {
					if pat.MatchString(target) {
						matched = true
						break
					}
				}
				if !matched {
					matchedAll = false
					break
				}
			}
			if matchedAll {
				return CVEMatch{
					CVEID:       rule.cveID,
					Category:    "general",
					Severity:    rule.severity,
					Description: rule.description,
					MatchedPart: rule.target,
					Pattern:     "conjunction match",
					Action:      "drop",
				}, true
			}
			continue
		}

		for _, t := range targets {
			for _, pat := range rule.patterns {
				if pat.MatchString(t) {
					part := rule.target
					if part == "all" {
						part = guessMatchedPart(req, t)
					}
					return CVEMatch{
						CVEID:       rule.cveID,
						Category:    "general",
						Severity:    rule.severity,
						Description: rule.description,
						MatchedPart: part,
						Pattern:     pat.String(),
						Action:      "drop",
					}, true
				}
			}
		}
	}
	return CVEMatch{}, false
}

// checkHTTPSmuggling detects when both Content-Length and Transfer-Encoding headers
// are present simultaneously, or TE contains malformed values.
func checkHTTPSmuggling(req *CVERequest) bool {
	hasCL := false
	hasTE := false
	for k, v := range req.Headers {
		switch {
		case strings.EqualFold(k, "content-length"):
			hasCL = true
		case strings.EqualFold(k, "transfer-encoding"):
			hasTE = true
			vl := strings.ToLower(v)
			if strings.Contains(vl, " chunked") || strings.Contains(vl, "\tchunked") ||
				strings.Contains(vl, "chunked ") || strings.Contains(vl, ",chunked") {
				return true
			}
		}
	}
	return hasCL && hasTE
}

func isPackageManifestRequest(uri string, headers map[string]string) bool {
	pathOnly := uri
	if i := strings.IndexByte(pathOnly, '?'); i >= 0 {
		pathOnly = pathOnly[:i]
	}
	if !strings.HasSuffix(strings.ToLower(pathOnly), "/package.json") {
		return false
	}
	host := strings.ToLower(cveHeaderValue(headers, "Host"))
	if host == "cdn.jsdelivr.net" || host == "codesandbox.io" || host == "raw.githubusercontent.com" {
		return true
	}
	referer := strings.ToLower(cveHeaderValue(headers, "Referer"))
	origin := strings.ToLower(cveHeaderValue(headers, "Origin"))
	return strings.HasPrefix(pathOnly, "/npm/") ||
		(strings.HasPrefix(pathOnly, "/public/vscode-extensions/") && strings.Contains(referer, "codesandbox.io/")) ||
		(strings.HasPrefix(pathOnly, "/SchemaStore/") && (strings.Contains(referer, "codesandbox.io/") || strings.Contains(origin, "codesandbox.io")))
}
