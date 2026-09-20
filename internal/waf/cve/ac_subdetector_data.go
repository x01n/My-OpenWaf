package cve

// subDetectorNeedleEntries 四子检测器(node/php/java/general)纯 OR gate 的
// needle 字面量数据。按 cveID+target 分组编入 AC 自动机,运行时一遍扫描
// 替代逐规则多针 strings.Contains。
//
// 复合 helper(含 AND 逻辑/特殊判定)不在此列,保留原始调用路径:
//
//	CVE-2019-SSRF, CVE-2019-CRLF, CVE-2019-HEADER-INJECT, CVE-2024-4577(general),
//	CVE-2024-3400, CVE-2025-34028, CVE-2024-JAVAINJ, CVE-2024-DEEPPATH, CVE-2024-NOSQLI.
var subDetectorNeedleEntries = []subDetectorNeedleEntry{
	// ══════════════════════════════════════════════════════════════════
	// Node.js sub-detector
	// ══════════════════════════════════════════════════════════════════
	{"CVE-2019-10744", "all", []string{"__proto__", "constructor.prototype", "prototype["}},
	{"CVE-2020-REACT-SSR", "all", []string{"dangerouslysetinnerhtml", "__next_data__", "react"}},
	{"CVE-2019-NODE-CMD", "all", []string{"child_process", "exec(", "spawn(", "process.env", "require(", "whoami", "uname", "wget", "curl", "|", "`"}},
	{"CVE-2017-14849", "url", []string{"../", "%2e", "%5c", "..\\"}},
	{"CVE-2022-29078", "all", []string{"ejs", "<%", "template"}},
	{"CVE-2023-32314", "all", []string{"vm2", "constructor", "globalthis"}},
	{"CVE-2024-34351", "header", []string{"x-middleware", "middleware-subrequest"}},
	{"CVE-2025-29927", "header", []string{"x-middleware", "middleware-subrequest"}},
	{"CVE-2025-55182", "body", []string{"react.server", "rsc", "$@", "$1:", "__proto__", "child_process", "constructor", "function(", "new blob", "new response", "dynamic import"}},
	{"CVE-2025-55184", "url", []string{"server-action", "server action", "next-action", "/_next/data/", "__nextdatareq"}},

	// ══════════════════════════════════════════════════════════════════
	// PHP sub-detector
	// ══════════════════════════════════════════════════════════════════
	{"CVE-2015-6835", "all", []string{"unserialize", "o:", "a:"}},
	{"CVE-2018-14884", "all", []string{"php://", "data://", "expect://", "phar://"}},
	{"CVE-2018-20062", "all", []string{"invokefunction", "thinkphp", "think\\app", "filter[]=", "filter%5b%5d=", "call_user_func", "_method=__construct", "c=runtime", "a=getcontent"}},
	{"CVE-2021-3129", "all", []string{"_ignition/execute-solution", "_ignition/health-check", "laravel", "facade/ignition", "illuminate\\"}},
	{"CVE-2016-WEBSHELL", "body", []string{"<?php", "eval(", "system(", "exec(", "passthru(", "shell_exec"}},
	{"CVE-2016-WEBSHELL-EXT", "all", []string{".php", ".phtml", ".phar", "filename="}},
	{"CVE-2018-7600", "all", []string{"drupal", "form_id=", "#post_render", "#markup", "#type"}},
	{"CVE-2017-9841", "url", []string{"eval-stdin", "phpunit"}},
	{"CVE-2024-4577", "all", []string{"%ad", "auto_prepend_file", "allow_url_include", "cgi.force_redirect"}},
	{"CVE-2023-41892", "url", []string{"conditions/render", "actions/conditions", "configobject", "craftcms", "craft cms"}},

	// ══════════════════════════════════════════════════════════════════
	// Java sub-detector
	// ══════════════════════════════════════════════════════════════════
	{"CVE-2021-44228", "all", []string{"${", "jndi:", "ldap://", "rmi://", "ldaps://"}},
	{"CVE-2022-22965", "all", []string{"class.module", "classloader", "class.classloader", "spring"}},
	{"CVE-2022-22963", "all", []string{"functionrouter", "spring.cloud.function", "spel", "#{"}},
	{"CVE-2017-18349", "body", []string{"@type", "autotype", "fastjson", "com.sun.", "java.lang.runtime", "java.net.", "javax.naming", "org.apache.xbean", "com.mchange.v2.c3p0"}},
	{"CVE-2017-5638", "all", []string{"ognl", "#_member", "valuestack", "actioncontext", "struts"}},
	{"CVE-2016-4437", "cookie", []string{"rememberme="}},
	{"CVE-2017-7525", "body", []string{"jackson", "@class", "polymorphic", "objectmapper", `["org.apache.commons.`, "com.sun.org.apache.xalan"}},
	{"CVE-2023-49070", "url", []string{"webtools/control", "ofbiz", "programexport"}},
	{"CVE-2023-46604", "body", []string{"activemq", "exceptionresponse", "classpathxml", "classpathxmlapplicationcontext", "classinfo", "org.springframework", "spring-beans"}},
	{"CVE-2022-26134", "all", []string{"confluence", "ognl", "${"}},

	// ══════════════════════════════════════════════════════════════════
	// General sub-detector (pure OR cases only)
	// ══════════════════════════════════════════════════════════════════
	{"CVE-2018-XXE", "body", []string{"<!doctype", "<!entity", " system ", " public "}},
	{"CVE-2019-PATHTRA", "url", []string{"../", "..\\", "%2e", "%5c", "%00", "....//"}},
	{"CVE-2014-6271", "all", []string{"() {", "};"}},
	{"CVE-2025-31324", "url", []string{"metadatauploader", "irj/servlet"}},
	{"CVE-2023-22527", "url", []string{"confluence", "ognl", "template"}},
	{"CVE-2023-4966", "url", []string{"vpn/index", "citrix", "../"}},
	{"CVE-2024-53677", "all", []string{`top["`}},
	{"CVE-2024-21887", "url", []string{"api/v1/totp", "dana", "../", "ivanti"}},
	{"CVE-2025-30208", "url", []string{"@fs/", "raw??"}},
	{"CVE-2025-3248", "all", []string{"validate/code", "__import__", "exec(", "system("}},
	{"CVE-2025-24893", "all", []string{"solrsearch", "groovy", "media=rss"}},
	{"CVE-2025-53770", "all", []string{"toolpane.aspx", "signout.aspx", "spinstall0.aspx", "msotlpn_dwp", "__viewstate"}},
	{"CVE-2026-21876", "all", []string{"multipart/form-data", "charset=utf-7", "charset=utf-16", "charset=utf-32", "shift-jis", "iso-2022-jp"}},
	{"CVE-2025-47812", "all", []string{"loginok.html", "%00", "io.popen", "lua"}},
	{"CVE-2025-4632", "all", []string{"swupdatefileuploader", "filename=", "magicinfo"}},
	{"CVE-2025-64446", "all", []string{"cgi-bin/fwbcgi", "cgiinfo", "fwbcgi"}},
	{"CVE-2025-10035", "all", []string{"unlicensed.xhtml", "garequestaction=activate", "javax.faces.viewstate"}},
	{"CVE-2025-41243", "all", []string{"actuator/gateway", "addresponseheader", "#{", "spel"}},
	{"CVE-2025-47916", "all", []string{"themeeditor", "customcss", "expression="}},
	{"CVE-2025-31161", "all", []string{"webinterface/function", "aws4-hmac-sha256", "crushftp"}},
	{"CVE-2025-32756", "all", []string{"hostcheck_validate", "authhash"}},
	{"CVE-2024-SENSFILE", "url", []string{"/.env", "/.git/config", "/.htaccess", "/wp-config.php", "/web.config", "/etc/passwd"}},
	{"CVE-2017-8046", "all", []string{"json-patch", "application/patch+json", "spel", "#{", "t("}},
	{"CVE-2023-1454", "all", []string{"jeecg", "sys/", "select", "union", "updatexml", "extractvalue", "sleep("}},
	{"CVE-2021-21351", "all", []string{"<java", "<sorted-set", "<dynamic-proxy", "xstream", "processbuilder", "runtime"}},
	{"CVE-2019-3929", "all", []string{"/cgi-bin/", "cgi", ";", "|", "`", "$(", "wget", "curl", "busybox"}},
	{"CVE-2024-REMOTECALL", "all", []string{"jndi:", "ldap://", "rmi://", "iiop://", "jdbc:", "dns://"}},
	{"CVE-2024-XXEUTF7", "all", []string{"utf-7", "+adw-", "+adi-", "+afw-"}},
	{"CVE-2024-LDAPI", "all", []string{"objectclass=", ")(|", ")(uid=", "*)(", "ldap"}},
	{"CVE-2024-LOWCMD", "all", []string{";", "|", "`", "$(", "whoami", "uname", "ifconfig", "ipconfig"}},
}
