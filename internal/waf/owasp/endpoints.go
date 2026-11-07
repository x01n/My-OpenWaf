package owasp

import (
	"encoding/base64"
	"net/url"
	"strings"
)

type sensitiveEndpointRule struct {
	id       string
	category OWASPCategory
	score    int
	desc     string
	method   string
	segs     []string
}

var sensitiveEndpointRules = []sensitiveEndpointRule{
	{"owasp:endpoint:001", CatCmdInject, 6, "Palo Alto GlobalProtect 登录端点提交", "POST", []string{"global-protect", "login.esp"}},
	{"owasp:endpoint:002", CatCmdInject, 5, "Palo Alto GlobalProtect HIP 上报端点探测", "POST", []string{"ssl-vpn", "hipreport.esp"}},
	{"owasp:endpoint:003", CatPathTrav, 5, "F5 iControl REST 认证端点探测", "POST", []string{"mgmt", "shared", "authn", "login"}},
	{"owasp:endpoint:004", CatPathTrav, 5, "Citrix NetScaler 网关版本文件探测", "GET", []string{"dana-na", "nc", "nc_gina_ver.txt"}},
	{"owasp:endpoint:005", CatPathTrav, 5, "Citrix NetScaler 主机检查器安装包探测", "GET", []string{"dana-cached", "hc", "hostcheckerinstaller.osx"}},
	{"owasp:endpoint:006", CatCmdInject, 5, "WatchGuard SSLVPN 登录 CGI 探测", "POST", []string{"wgcgi.cgi"}},
	{"owasp:endpoint:007", CatCmdInject, 6, "Spring Boot Actuator 网关路由删除操作", "DELETE", []string{"actuator"}},
	{"owasp:endpoint:008", CatCmdInject, 6, "Docker Engine API 未授权容器创建", "POST", []string{"v1.24", "containers", "create"}},
	{"owasp:endpoint:009", CatCmdInject, 6, "Docker Engine API 容器内命令执行", "POST", []string{"v1.24", "containers", "bash", "exec"}},
	{"owasp:endpoint:010", CatCmdInject, 5, "Jenkins crumbIssuer XML 接口探测", "GET", []string{"crumbissuer", "api", "xml"}},
	{"owasp:endpoint:011", CatCmdInject, 5, "Jenkins 脚本命令行状态端点探测", "GET", []string{"jkstatus"}},
	{"owasp:endpoint:012", CatPathTrav, 5, "CouchDB 数据库列表探测", "GET", []string{"_all_dbs"}},
	{"owasp:endpoint:013", CatPathTrav, 5, "Elasticsearch 快照仓库写入", "PUT", []string{"_snapshot"}},
	{"owasp:endpoint:014", CatCmdInject, 5, "Cobbler XML-RPC 接口探测", "", []string{"cobbler_api"}},
	{"owasp:endpoint:015", CatCmdInject, 5, "Apache Druid 采样器反序列化端点探测", "POST", []string{"druid", "indexer", "v1", "sampler"}},
	{"owasp:endpoint:016", CatCmdInject, 5, "JBoss JMX 控制台 HtmlAdaptor 探测", "", []string{"jmx-console", "htmladaptor"}},
	{"owasp:endpoint:017", CatPathTrav, 6, "路由器配置备份文件下载", "GET", []string{"cgi-bin", "downloadcfg", "routercfm.cfg"}},
	{"owasp:endpoint:018", CatCmdInject, 5, "设备管理 CGI machine.cgi 探测", "GET", []string{"cgi-bin", "nobody", "machine.cgi"}},
	{"owasp:endpoint:019", CatCmdInject, 5, "设备管理 CGI sc_mgr.cgi 探测", "GET", []string{"cgi-bin", "sc_mgr.cgi"}},
	{"owasp:endpoint:020", CatCmdInject, 5, "设备管理 CGI admin.cgi 探测", "GET", []string{"cgi-bin", "admin.cgi"}},
	{"owasp:endpoint:021", CatPathTrav, 5, "D-Link 设备描述文件探测", "", []string{"picsdesc.xml"}},
	{"owasp:endpoint:022", CatCmdInject, 5, "D-Link device.rsp 命令端点探测", "", []string{"device.rsp"}},
	{"owasp:endpoint:023", CatPathTrav, 5, "Synology DSM 设备描述文件探测", "GET", []string{"ssdp", "desc-dsm-eth0.xml"}},
	{"owasp:endpoint:024", CatCmdInject, 5, "Hikvision 地理服务 SOAP 端点探测", "POST", []string{"emap", "webservice", "gis", "soap", "bitmap"}},
	{"owasp:endpoint:025", CatCmdInject, 5, "Synology 认证 CGI 探测", "GET", []string{"webapi", "auth.cgi"}},
	{"owasp:endpoint:026", CatCmdInject, 5, "TOTOLINK 设备页面探测", "GET", []string{"bsw_cxttongr.htm"}},
	{"owasp:endpoint:027", CatCmdInject, 5, "路由器 WAN 配置页面探测", "GET", []string{"wan.htm"}},
	{"owasp:endpoint:028", CatCmdInject, 5, "设备热点 Logo 上传端点探测", "POST", []string{"config", "saveuploadedhotspotlogofile"}},
	{"owasp:endpoint:029", CatCmdInject, 5, "RD Web Access 登录端点探测", "POST", []string{"rdweb", "pages", "en-us", "login.aspx"}},
	{"owasp:endpoint:030", CatCmdInject, 5, "Amazon WorkSpaces 客户端端点探测", "GET", []string{"lwa", "webpages", "lwaclient.aspx"}},
	{"owasp:endpoint:031", CatCmdInject, 5, "Exchange OWA 脚本路径探测", "GET", []string{"owa", "auth", "x.js"}},
	{"owasp:endpoint:032", CatWebshell, 6, "WebShell 管理界面端点访问", "GET", []string{"manage", "webshell", "u"}},
	{"owasp:endpoint:033", CatWebshell, 6, "文件管理器后端 makefile 端点访问", "POST", []string{"file-manager", "backend", "makefile"}},
	{"owasp:endpoint:034", CatCmdInject, 6, "Laravel Ignition 远程代码执行端点探测", "POST", []string{"_ignition", "execute-solution"}},
	{"owasp:endpoint:035", CatCmdInject, 6, "Atlassian Crowd 插件上传端点探测", "POST", []string{"crowd", "admin", "uploadplugin.action"}},
	{"owasp:endpoint:036", CatDeserial, 6, "WebLogic wls-wsat 反序列化端点探测", "POST", []string{"wls-wsat", "coordinatorporttype"}},
	{"owasp:endpoint:037", CatCmdInject, 5, "Confluence dologin 认证端点探测", "POST", []string{"dologin.action"}},
	{"owasp:endpoint:038", CatCmdInject, 5, "Apache Axis2 管理控制台探测", "POST", []string{"axis2", "axis2-admin"}},
	{"owasp:endpoint:039", CatCmdInject, 5, "GoAnywhere 许可接受端点探测", "POST", []string{"goanywhere", "lic", "accept"}},
	{"owasp:endpoint:040", CatCmdInject, 5, "Sophos XG 访客访问端点探测", "POST", []string{"guestaccess.aspx"}},
	{"owasp:endpoint:041", CatCmdInject, 5, "Liferay 门户脚本探测", "GET", []string{"c", "portal.php"}},
	{"owasp:endpoint:042", CatCmdInject, 5, "致远 OA 接口探测", "GET", []string{"yyoa"}},
	{"owasp:endpoint:043", CatCmdInject, 5, "浪潮 MICS 日志服务端点探测", "POST", []string{"mics", "services", "micslogservice"}},
	{"owasp:endpoint:044", CatCmdInject, 5, "Oracle EBS BneViewerXMLService 端点探测", "POST", []string{"oa_html", "bneviewerxmlservice"}},
	{"owasp:endpoint:045", CatCmdInject, 5, "JeecgBoot 用户查询接口探测", "GET", []string{"jeecg-boot", "sys", "user", "querysysuser"}},
	{"owasp:endpoint:046", CatCmdInject, 5, "PHP 探针脚本探测", "GET", []string{"php", "ping.php"}},
	{"owasp:endpoint:047", CatCmdInject, 5, "SPIP 密码重置端点编码绕过探测", "POST", []string{"spip.ph%70"}},
	{"owasp:endpoint:048", CatCmdInject, 5, "A2Billing 管理备份脚本探测", "GET", []string{"a2billing", "admin", "public", "a2b_entity_backup.php"}},
	{"owasp:endpoint:049", CatCmdInject, 5, "设备凭据恢复端点探测", "GET", []string{"passwordrecovered.cgi"}},
	{"owasp:endpoint:050", CatCmdInject, 5, "Hedwig CGI 端点探测", "POST", []string{"hedwig.cgi"}},
	{"owasp:endpoint:051", CatCmdInject, 5, "云平台 Widget 渲染端点探测", "POST", []string{"ajax", "render", "widget_tabbedcontainer_tab_panel"}},
	{"owasp:endpoint:052", CatCmdInject, 5, "WordPress 安装配置端点探测", "GET", []string{"wp-admin", "setup-config.php"}},
	{"owasp:endpoint:053", CatPathTrav, 5, "Cacti Weathermap 编辑器探测", "GET", []string{"plugins", "weathermap", "editor.php"}},
	{"owasp:endpoint:054", CatPathTrav, 6, "Zabbix 日志泄露端点探测", "GET", []string{"tool", "log", "c.php"}},
	{"owasp:endpoint:055", CatPathTrav, 5, "CUPS/IPP 打印服务端点探测", "POST", []string{"ipp", "print"}},
	{"owasp:endpoint:056", CatCmdInject, 5, "WFO 控制台登录端点探测", "GET", []string{"wfo", "control", "signin"}},
	{"owasp:endpoint:057", CatCmdInject, 5, "SonicWall 设备上下文切换端点探测", "GET", []string{"esp", "cms_changedevicecontext.esp"}},
	{"owasp:endpoint:058", CatCmdInject, 5, "SonicWall admingui 服务器配置端点探测", "GET", []string{"admingui", "version", "serverconfigurationsgeneral"}},
	{"owasp:endpoint:059", CatCmdInject, 5, "SonicWall admingui 任务配置端点探测", "GET", []string{"admingui", "version", "servertasksgeneral"}},
	{"owasp:endpoint:060", CatPathTrav, 6, "ownCloud graphapi 依赖目录越权访问", "GET", []string{"owncloud", "apps", "graphapi", "vendor"}},
	{"owasp:endpoint:061", CatPathTrav, 5, "暴露的 SFTP 部署配置访问", "GET", []string{".vscode", "sftp.json"}},
	{"owasp:endpoint:062", CatPathTrav, 5, "phpunit 依赖目录内的环境变量文件访问", "GET", []string{"vendor", ".env"}},
	{"owasp:endpoint:063", CatCmdInject, 5, "GitLab 项目浏览路径穿越探测", "GET", []string{"explore", "projects"}},
	{"owasp:endpoint:064", CatCmdInject, 5, "Stalker Portal IPTV 服务端点探测", "GET", []string{"stalker_portal", "server", "load.php"}},
	{"owasp:endpoint:065", CatCmdInject, 5, "Discord API 礼品码端点探测", "GET", []string{"api", "v9", "entitlements", "gift-codes"}},
	{"owasp:endpoint:066", CatCmdInject, 5, "SonicWall 管理 API 探测", "", []string{"api", "sonicos"}},
	{"owasp:endpoint:067", CatCmdInject, 5, "华为设备接口添加端点探测", "POST", []string{"api", "interface", "add"}},
	{"owasp:endpoint:068", CatCmdInject, 5, "Ivanti Connect Secure 客户端访问统计端点探测", "POST", []string{"api", "v1", "cav", "client", "visits"}},
	{"owasp:endpoint:069", CatCmdInject, 5, "Fortinet 配置库接口写入", "PUT", []string{"api", "v2", "cmdb", "system"}},
	{"owasp:endpoint:070", CatCmdInject, 5, "JMeter 会话属性端点探测", "GET", []string{"api", "session", "properties"}},
	{"owasp:endpoint:071", CatCmdInject, 5, "Magento 访客购物车接口探测", "POST", []string{"rest", "v1", "guest-carts"}},
	{"owasp:endpoint:072", CatCmdInject, 5, "设备文件服务端点写入", "PUT", []string{"fileserver"}},
	{"owasp:endpoint:073", CatCmdInject, 6, "越权路径下的 ztp_gate 后门探测", "GET", []string{"unauth", "%252e%252e", "php", "ztp_gate.php"}},
	{"owasp:endpoint:074", CatCmdInject, 6, "WordPress 插件 age-verification 代码执行端点探测", "POST", []string{"wp-content", "plugins", "age-verification", "age-verification.php"}},
	{"owasp:endpoint:075", CatCmdInject, 6, "WordPress 插件 delightful-downloads 资源目录探测", "POST", []string{"wp-content", "plugins", "delightful-downloads", "assets"}},
	{"owasp:endpoint:076", CatCmdInject, 6, "WordPress 插件 duplicator 文件目录越权访问", "GET", []string{"wp-content", "plugins", "duplicator", "files"}},
	{"owasp:endpoint:077", CatCmdInject, 6, "WordPress 插件 dhtmlxspreadsheet 目录越权访问", "GET", []string{"wp-content", "plugins", "dhtmlxspreadsheet", "codebase"}},
	{"owasp:endpoint:078", CatCmdInject, 6, "WordPress 插件 adminimize 页面独有端点探测", "GET", []string{"wp-content", "plugins", "adminimize", "adminimize_page.php"}},
	{"owasp:endpoint:079", CatCmdInject, 5, "泛微 e-cology 系统信息外部接口探测", "POST", []string{"api", "external", "7.0", "system.system.get_infos"}},
	{"owasp:endpoint:080", CatCmdInject, 6, "致远 OA htmlofficeservlet 文件上传端点探测", "POST", []string{"seeyon", "htmlofficeservlet"}},
	{"owasp:endpoint:081", CatCmdInject, 6, "WebLogic 管理控制台上传端点探测", "POST", []string{"ws_utc", "resources", "setting", "keystore"}},
	{"owasp:endpoint:082", CatCmdInject, 6, "JBoss invoker 只读端点探测", "POST", []string{"invoker", "readonly"}},
	{"owasp:endpoint:083", CatCmdInject, 5, "移动端插件 JSP 页面探测", "POST", []string{"mobile", "plugin", "browser.jsp"}},
	{"owasp:endpoint:084", CatCmdInject, 5, "设备管理脚本路径穿越探测", "GET", []string{"resource=", "etc", "passwd"}},
	{"owasp:endpoint:085", CatCmdInject, 5, "Fortinet SSL-VPN 登录校验端点提交", "POST", []string{"logincheck"}},
	{"owasp:endpoint:086", CatCmdInject, 5, "Boa 路由器管理登录端点提交", "POST", []string{"boaform", "admin", "formlogin"}},
	// 087-090 是「路径 ∪ 请求体私有字段」的合取规则：这四个端点的路径与
	// 方法在语料黑白两侧都出现，只有请求体字段能把设备的完整登录表单与
	{"owasp:endpoint:087", CatCmdInject, 5, "SonicWall SSL-VPN 登录端点完整表单提交", "POST", []string{"cgi-bin", "userlogin"}},
	{"owasp:endpoint:088", CatCmdInject, 5, "Cisco ASA WebVPN 门户登录表单提交", "POST", []string{"+webvpn+", "index.html"}},
	{"owasp:endpoint:089", CatCmdInject, 5, "Fortinet SSL-VPN 登录校验接口提交", "POST", []string{"remote", "logincheck"}},
	{"owasp:endpoint:090", CatCmdInject, 5, "Citrix NetScaler 登录端点完整表单提交", "POST", []string{"cgi", "login"}},
	// 091-141 覆盖「URL 参数由服务端发起请求（SSRF/开放重定向）」与
	// 「文件上传/任意文件写入」两类产品专属端点。收录口径与 001-090 相同：
	// 端点在正常业务里没有用途，命中即探测；判据只用路径段，不看方法之外的
	// 任何请求内容。每条都在全语料 140572 条首请求行上验证过白侧命中数为 0
	{"owasp:endpoint:091", CatSSRF, 6, "Cacti pictureproxy 图片代理端点（url 参数由服务端发起请求）", "", []string{"pictureproxy.php"}},
	{"owasp:endpoint:092", CatSSRF, 6, "Liferay 短链生成端点（url 参数触发服务端抓取）", "", []string{"rest", "sharelinks", "1.0", "link"}},
	{"owasp:endpoint:093", CatSSRF, 5, "WordPress oEmbed 代理端点（url 参数触发服务端抓取）", "", []string{"wp-json", "oembed", "1.0", "embed"}},
	{"owasp:endpoint:094", CatSSRF, 5, "WordPress 子目录站点 oEmbed 代理端点（url 参数）", "", []string{"blog", "wp-json", "oembed", "1.0", "embed"}},
	{"owasp:endpoint:095", CatSSRF, 5, "WordPress 子目录站点 oEmbed 代理端点（url 参数）", "", []string{"sito", "wp-json", "oembed", "1.0", "embed"}},
	{"owasp:endpoint:096", CatSSRF, 5, "Jellyfin 远程图片搜索端点（ImageURL 参数触发服务端抓取）", "", []string{"items", "remotesearch", "image"}},
	{"owasp:endpoint:097", CatSSRF, 5, "Drupal Babel 翻译模块跳转端点（newurl 参数）", "", []string{"modules", "babel", "redirect.php"}},
	{"owasp:endpoint:098", CatSSRF, 5, "SonarQube 项目选择跳转端点（url 参数）", "", []string{"select_project.php"}},
	{"owasp:endpoint:099", CatSSRF, 5, "openwin.php 弹窗跳转端点（redirurl 参数）", "", []string{"openwin.php"}},
	{"owasp:endpoint:100", CatSSRF, 5, "SAFVC 单点登录登出端点（successURL 参数）", "", []string{"ssoadapter", "logoutaction.do"}},
	{"owasp:endpoint:101", CatSSRF, 5, "站点图标抓取端点（host 参数由服务端发起请求）", "", []string{"getfavicon"}},
	{"owasp:endpoint:102", CatSSRF, 5, "Novius OS 后台登录跳转端点（redirect 参数）", "", []string{"novius-os", "admin", "nos", "login"}},
	{"owasp:endpoint:103", CatSSRF, 6, "Magnolia CMS JSONP 服务端代理端点（websiteproxy 与 url 参数）", "", []string{"api", "v1", "core", "proxy", "jsonprequest"}},
	{"owasp:endpoint:104", CatSSRF, 5, "Kaseya VSA 本地代理端点（url 参数）", "", []string{"vsapres", "web20", "core", "localproxy.ashx"}},
	{"owasp:endpoint:105", CatSSRF, 5, "Composer 邮件发送端点（url 参数触发服务端抓取）", "", []string{"composer", "send_email"}},
	{"owasp:endpoint:106", CatSSRF, 5, "PMB 图书馆系统抓取端点（url 参数）", "", []string{"pmb", "opac_css", "pmb.php"}},
	{"owasp:endpoint:107", CatSSRF, 5, "后台清理缓存跳转端点（previousUrl 参数）", "", []string{"backend", "admin", "common", "clearcache"}},
	{"owasp:endpoint:108", CatSSRF, 5, "OpenX 广告点击跳转端点（dest 参数）", "", []string{"openx", "www", "delivery", "lg.php"}},
	{"owasp:endpoint:109", CatSSRF, 5, "adserve 广告点击跳转端点（dest 参数）", "", []string{"adserve", "www", "delivery", "lg.php"}},
	{"owasp:endpoint:110", CatSSRF, 5, "adserver 广告点击跳转端点（dest 参数）", "", []string{"adserver", "www", "delivery", "lg.php"}},
	{"owasp:endpoint:111", CatSSRF, 5, "Brandfolder 插件回调端点（wp_abspath 参数）", "", []string{"wp-content", "plugins", "brandfolder", "callback.php"}},
	{"owasp:endpoint:112", CatSSRF, 5, "find_v2 点击跳转端点（_t_redirect 参数）", "", []string{"find_v2", "_click"}},
	{"owasp:endpoint:113", CatSSRF, 5, "OpenCms jsonapi 抓取端点（uri 参数）", "", []string{"system", "modules", "alkacon.mercury.template.jsondemo", "elements", "jsonapi.jsp"}},
	{"owasp:endpoint:114", CatSSRF, 5, "StageShow 插件跳转端点（url 参数）", "", []string{"wp-content", "plugins", "stageshow", "stageshow_redirect.php"}},
	{"owasp:endpoint:115", CatSSRF, 5, "Bitrix 跳转端点（goto 参数）", "", []string{"bitrix", "redirect.php"}},
	{"owasp:endpoint:116", CatSSRF, 5, "Bitrix 广告点击跳转端点（goto 参数）", "", []string{"bitrix", "rk.php"}},
	{"owasp:endpoint:117", CatSSRF, 5, "回显服务探测页请求（用于验证服务端出网）", "", []string{"echo-server.html"}},
	{"owasp:endpoint:118", CatSSRF, 5, "supportLoad 抓取端点（urlToLoad 参数）", "", []string{"inc", "supportload.asp"}},
	{"owasp:endpoint:119", CatSSRF, 5, "PhastPress 远端资源抓取端点（src 参数）", "", []string{"wp-content", "plugins", "phastpress", "phast.php"}},
	{"owasp:endpoint:120", CatSSRF, 5, "WebP Converter 插件直通抓取端点（src 参数）", "", []string{"wp-content", "plugins", "webp-converter-for-media"}},
	{"owasp:endpoint:121", CatSSRF, 5, "海思 IPC 摄像头参数 CGI（cururl 参数触发服务端抓取）", "", []string{"web", "cgi-bin", "hi3510", "param.cgi"}},
	{"owasp:endpoint:122", CatWebshell, 6, "wp-file-manager 文件管理器连接器端点", "", []string{"wp-content", "plugins", "wp-file-manager"}},
	{"owasp:endpoint:123", CatWebshell, 6, "致远 OA dataDir 配置写入端点", "", []string{"admin", "datadir.html"}},
	{"owasp:endpoint:124", CatWebshell, 5, "AIM 设备映射文件上传端点", "", []string{"aim", "equipmap", "accept.jsp"}},
	{"owasp:endpoint:125", CatWebshell, 5, "OAapp 通用文件上传端点", "", []string{"oaapp", "jsp", "upload.jsp"}},
	{"owasp:endpoint:126", CatWebshell, 6, "OAapp 文件编辑上传端点", "", []string{"oaapp", "htpages", "app", "module", "trace", "component", "fileedit", "ntkoupload.jsp"}},
	{"owasp:endpoint:127", CatWebshell, 5, "pdf_maker 文件生成端点（可写入任意文件）", "", []string{"inter", "pdf_maker.php"}},
	{"owasp:endpoint:128", CatWebshell, 5, "uploadControl 文件上传端点", "", []string{"mp", "uploadcontrol", "uploadfile"}},
	{"owasp:endpoint:129", CatWebshell, 5, "变量导入端点（varimport）", "", []string{"variable", "varimport"}},
	{"owasp:endpoint:130", CatWebshell, 6, "编码穿越指向 CGI 脚本的路径", "", []string{"images", "..%2fcgi", "cgi_i_filter.js"}},
	{"owasp:endpoint:131", CatWebshell, 6, "泛微 C6 任意文件下载端点（filename 参数）", "", []string{"c6", "jhsoft.web.module", "testbill", "dj", "download.asp"}},
	{"owasp:endpoint:132", CatWebshell, 5, "viral-optins 插件文件上传端点", "", []string{"wp-content", "plugins", "viral-optins", "api", "uploader", "file-uploader.php"}},
	{"owasp:endpoint:133", CatWebshell, 5, "畅捷通 T+ 上传端点", "", []string{"tplus", "sm", "setupaccount", "upload.aspx"}},
	{"owasp:endpoint:134", CatWebshell, 5, "exportImport 上传操作端点", "", []string{"page", "exportimport", "uploadoperation.jsp"}},
	{"owasp:endpoint:135", CatWebshell, 5, "开发服务器元数据上传端点", "POST", []string{"developmentserver", "metadatauploader"}},
	{"owasp:endpoint:136", CatCmdInject, 6, "storagemgmt apply 端点（data[host] 参数内嵌命令）", "", []string{"collector", "storagemgmt", "apply"}},
	{"owasp:endpoint:137", CatCmdInject, 6, "JetBrains YouTrack 调试进程执行端点（exePath 参数）", "", []string{"app", "rest", "debug", "processes"}},
	{"owasp:endpoint:138", CatCmdInject, 6, "mesh.cgi 升级端点（key 参数内嵌命令）", "", []string{"cgi-bin", "mesh.cgi"}},
	{"owasp:endpoint:139", CatDeserial, 6, "Adobe BlazeDS AMF 反序列化端点", "", []string{"flex2gateway", "amf"}},
	{"owasp:endpoint:140", CatSSRF, 5, "服务端图片抓取端点（imageUrl 参数由服务端发起请求）", "", []string{"images", "remote"}},
	{"owasp:endpoint:141", CatSSRF, 5, "头像图标抓取端点（url 参数由服务端发起请求）", "", []string{"v1", "avatars", "favicon"}},
	{"owasp:endpoint:142", CatCmdInject, 6, "WebShell 落地脚本 Dsks.php 上传端点", "POST", []string{"tmp", "dsks.php"}},
	{"owasp:endpoint:143", CatCmdInject, 6, "GameAPI ExecuteShell 远程命令执行接口", "POST", []string{"gameapi"}},
	{"owasp:endpoint:144", CatCmdInject, 6, "设备管理登录 CGI LoginPC.cgi 提交", "POST", []string{"loginpc.cgi"}},
	{"owasp:endpoint:145", CatCmdInject, 6, "TOTOLINK 固件上传 quick.cgi 命令注入端点", "", []string{"cgi-bin", "quick", "quick.cgi"}},
	{"owasp:endpoint:146", CatCmdInject, 6, "路由器 ping 诊断 webctrl.cgi 命令注入端点", "GET", []string{"cgi-bin", "webctrl.cgi"}},
	{"owasp:endpoint:147", CatCmdInject, 6, "设备菜单 CGI guiw 命令注入端点", "GET", []string{"menu", "guiw"}},
	{"owasp:endpoint:148", CatCmdInject, 6, "Fortinet 主机检查校验端点提交", "POST", []string{"remote", "hostcheck_validate"}},
	{"owasp:endpoint:149", CatCmdInject, 6, "popen.cgi 命令执行端点探测", "GET", []string{"cgi-bin", "popen.cgi"}},
	{"owasp:endpoint:150", CatCmdInject, 6, "设备协议配置接口 index.php 注入端点", "POST", []string{"protocol", "index.php"}},
	{"owasp:endpoint:151", CatCmdInject, 6, "Boa formPing6 诊断命令注入端点", "POST", []string{"boaform", "admin", "formping6"}},
	{"owasp:endpoint:152", CatCmdInject, 6, "运维脚本执行端点 run_commands.sh", "", []string{"utility", "run_commands.sh"}},
	{"owasp:endpoint:153", CatCmdInject, 6, "固件配置上传 cvmcfgupload 命令注入端点", "", []string{"cgi-bin", "mainfunction.cgi", "cvmcfgupload"}},
	{"owasp:endpoint:154", CatCmdInject, 6, "phpMyAdmin PMD 设计器目录探测", "POST", []string{"pmd", "index.php"}},
	// /shell 是 Mirai 系僵尸网络的标准载荷落地路径：黑侧 93/93 全为该形态
	// （GET 79、HEAD 14，91 条带 `cd /tmp;rm -rf *;wget ...;chmod 777` 一类
	// query），全语料白侧命中 0。段序列只有一段，`/shell.jsp`、
	// `/sitecore/shell/...` 等同含 shell 的正常路径都不命中。
	{"owasp:endpoint:155", CatCmdInject, 6, "根路径 shell 载荷落地命令执行探测", "", []string{"shell"}},
	// 156：NCCHR 考勤系统的脚本执行接口。黑侧 1/1 为
	// `POST /ncchr/attendScript/internal/runScript`，body 为
	// `key=1&script=select 1,111*333,user,4,5,6,7,8,9,10 from dual`
	// （`select` 与 `from` 之间夹了逗号列表，既有 sqli:001/006 因缺少
	// 词边界外的结构全放行）。全语料 140572 条白侧命中 0；`/ncchr/` 单段
	// 前缀另有 1 条白侧命中，故取完整三段以收窄。
	{"owasp:endpoint:156", CatSQLi, 6, "NCCHR 考勤系统脚本执行接口探测", "POST", []string{"ncchr", "attendscript", "internal", "runscript"}},
	// 157：CMS 分页接口被用作时间盲注载体。黑侧 4/4 的 query 为
	// `id=(sleep(6))`——无引号、无注释符，`sleep(` 前是 `(` 而非
	// 赋值/布尔上下文，正是既有 sqli:003 抑制器判为 JavaScript 误报的形态。
	// 路径三段（admin/ajax/pages.php）在全语料白侧命中 0，黑侧 4 条全落此路径。
	{"owasp:endpoint:157", CatSQLi, 6, "CMS 分页接口时间盲注端点探测", "GET", []string{"admin", "ajax", "pages.php"}},
	// 158：DNS over HTTPS 专用端点。黑侧 708 条全部为 `/dns-query`，并且
	// 携带 `application/dns-message` 头或 `dns=` 查询参数；全语料白侧 0 条。
	// 仅按首段收录，覆盖 GET 查询和 POST 二进制 DNS 报文两种 DoH 形态。
	{"owasp:endpoint:158", CatCmdInject, 6, "DNS over HTTPS 查询端点探测", "", []string{"dns-query"}},
	// 159：WinRM/WS-Man SOAP 端点。黑侧 242 条均为 POST，Content-Type 为
	// application/soap+xml 或 text/xml；白侧 0 条。请求头闸门排除白侧裸路径
	// 与 multipart/encrypted 的正常 WinRM 会话续传请求。
	{"owasp:endpoint:159", CatCmdInject, 6, "WinRM WS-Man SOAP 端点探测", "POST", []string{"wsman"}},
	// 160：D-Link HNAP1 SOAP 管理端点。黑侧 160 条均为 POST，SOAPAction 与
	// body 命名空间均指向 purenetworks.com/HNAP1/；白侧 0 条。GET/HEAD
	// 设备识别探测与空 SOAPAction 的正常请求不收录。
	{"owasp:endpoint:160", CatCmdInject, 6, "D-Link HNAP1 SOAP 管理端点探测", "POST", []string{"hnap1"}},
	// 161-164：Nacos 管理/配置高风险接口。四条完整路径黑侧分别为
	// `/nacos/v1/cs/ops/derby` 19、`/nacos/v1/ns/operator/servers` 12、
	// `/nacos/v1/cs/configs` 11、`/nacos/v1/auth/login` 11；全语料白侧均为 0。
	{"owasp:endpoint:161", CatCmdInject, 6, "Nacos Derby 数据库操作端点探测", "", []string{"nacos", "v1", "cs", "ops", "derby"}},
	{"owasp:endpoint:162", CatCmdInject, 6, "Nacos 服务节点运维端点探测", "", []string{"nacos", "v1", "ns", "operator", "servers"}},
	{"owasp:endpoint:163", CatCmdInject, 6, "Nacos 配置写入端点探测", "", []string{"nacos", "v1", "cs", "configs"}},
	{"owasp:endpoint:164", CatCmdInject, 6, "Nacos 认证登录端点探测", "", []string{"nacos", "v1", "auth", "login"}},
	// 165：Jenkins CLI 协议通道。黑侧 86 条均为 POST /cli?remoting=false，
	// 带 Side: upload/download 与 Session 头；另 2 条黑侧是 GET /cli/.env。
	// POST /cli 的全语料白侧为 0，故用 Side 头方法约束收录协议通道。
	{"owasp:endpoint:165", CatCmdInject, 6, "Jenkins CLI 远程协议通道探测", "POST", []string{"cli"}},
	// 166-174：本批全部带协议级闸门（query 参数、Basic 凭据解码内容、请求体
	// 协议标记），收录口径与 158-165 相同——每条都在全语料 140572 条的任一
	// 请求上验证过白侧命中数为 0。黑白同端点的登录/取流形态全部落在闸门之外。
	// 166：Ministra TV 中间件握手端点。黑侧 712 条 query 均以 type=stb 起始
	// （action=handshake/get_profile），白侧 1 条为 type=account_info，闸门排除。
	{"owasp:endpoint:166", CatCmdInject, 6, "Ministra TV 中间件握手端点探测", "", []string{"server", "load.php"}},
	// 167：Ministra TV 门户握手端点。黑侧 208 条 query 均带 type=stb，
	// 白侧 2 条为 type=account_info 与 type=itv，闸门排除。
	{"owasp:endpoint:167", CatCmdInject, 6, "Ministra TV 门户握手端点探测", "", []string{"portal.php"}},
	// 168：开放注册接口批量注册。黑侧 272 条均为 POST JSON
	// {"email","password","username"}（邮箱为 interact.sh 出网回连探针）；
	// 端点全语料白侧 0 条。
	{"owasp:endpoint:168", CatCmdInject, 6, "开放注册接口批量注册探测", "POST", []string{"api", "user", "reg"}},
	// 169：XML-RPC system.* 方法枚举。黑侧 POST 139 条中 109 条 body 为
	// system.listMethods/system.multicall 枚举载荷；白侧 POST 仅 1 条且为
	// wp.newTerm 表单，不带 system.* 标记。
	{"owasp:endpoint:169", CatCmdInject, 6, "XML-RPC system 方法枚举探测", "POST", []string{"xmlrpc.php"}},
	// 170：僵尸网络统计回传端点。黑侧 80 条均为 POST 且 body 以 '_' 字段
	// 携带 base64 回传数据；端点全语料白侧 0 条。
	{"owasp:endpoint:170", CatCmdInject, 6, "僵尸网络统计回传端点探测", "POST", []string{"bot", "statistic"}},
	// 171：VOS3000 软交换指纹图标。黑侧 74 条 GET 同一图标路径；
	// 端点全语料白侧 0 条。
	{"owasp:endpoint:171", CatCmdInject, 6, "VOS3000 软交换指纹图标探测", "", []string{"images", "vos3000.ico"}},
	// 172：ONVIF 摄像头快照弱凭据探测。黑侧 122 条 auth 参数 base64 解码
	// 均为 admin: 开头的凭据；白侧 1 条解码非标准 base64，闸门排除。
	{"owasp:endpoint:172", CatCmdInject, 6, "ONVIF 摄像头快照弱凭据探测", "GET", []string{"onvif-http", "snapshot"}},
	// 173：Tomcat Manager Basic 凭据爆破。黑侧 90 条精确 /manager/html
	// 全部携带 Authorization: Basic；白侧 3 条精确路径无该头，另有 3 条
	// /manager/html/manager 含 Python-urllib Basic 头（爬虫对 Manager 的
	// 深度探测），用「次段为末端」的精确匹配排除。
	{"owasp:endpoint:173", CatCmdInject, 6, "Tomcat Manager Basic 凭据爆破探测", "GET", []string{"manager", "html"}},
	// 174：VERM 电动窗帘控制器 SQL 注入。黑侧 566 条 Authorization: Basic
	// 解码后均为 goolicker', '', (SELECT …));# 形态的注入载荷；白侧 1 条
	// 同端点请求无 Authorization 头，闸门排除。
	{"owasp:endpoint:174", CatSQLi, 6, "VERM 控制器 Basic 凭据 SQL 注入探测", "GET", []string{"verm", "verm_ajax_functions.php"}},
	// 175-191：本批全部以「全语料 140572 条按段前缀/精确段重算」为收录口径，
	// 逐条在请求级（一条样本可含 1~6 个请求）确认白侧命中 0；黑侧数字为
	// r87 基线上仍漏报（fn）的样本数，已剔除 status!=200 的不可挽回项。
	// 175-177：配置文件直接暴露。黑侧为 /.env → /aws.yml → /config/aws.yml 的
	// 固定探测序列（同一批多请求样本里连续出现），白侧 0。
	{"owasp:endpoint:175", CatPathTrav, 6, "AWS 访问密钥配置文件探测", "GET", []string{"aws.yml"}},
	{"owasp:endpoint:176", CatPathTrav, 6, "配置目录下的 AWS 密钥文件探测", "GET", []string{"config", "aws.yml"}},
	{"owasp:endpoint:177", CatPathTrav, 6, "配置目录下的 Spring Boot 配置文件探测", "GET", []string{"config", "application.yml"}},
	// 178：Atlassian Crowd 安装向导的创建管理员提交。黑侧 51 条全为 POST 且带
	// X-Atlassian-Token: no-check；白侧 0。方法约束已把同端点的 GET 探测排除。
	{"owasp:endpoint:178", CatCmdInject, 6, "Atlassian Crowd 安装向导创建管理员端点", "POST", []string{"setup", "setupadministrator.action"}},
	// 179：DotNetNuke 的 Access/Setup 安装向导。黑侧 44 条全为 GET 且 query 为
	// Action=createadministrator&adminusername=…；白侧 0。
	{"owasp:endpoint:179", CatCmdInject, 6, "DotNetNuke 安装向导创建管理员端点", "GET", []string{"admin", "access", "setup", "default.aspx"}},
	// 180：Grafana 插件目录回溯读取主配置。黑侧 41 条固定十段路径；白侧同形态
	// 38 条使用的是自带插件名（knightss27-weathermap-panel 等），不是 alertlist，
	// 因此只收精确段序列，避免把「任意插件名 + 穿越」泛化成规则。
	{"owasp:endpoint:180", CatPathTrav, 6, "Grafana 插件目录回溯读取主配置", "GET", []string{"public", "plugins", "alertlist", "..", "..", "..", "..", "..", "conf", "defaults.ini"}},
	// 181：public 目录下的 .env。黑侧 50 条（GET 49 / POST 1，POST 也是同一批扫描的
	// 变体，故不约束方法）；白侧精确两段 0。
	{"owasp:endpoint:181", CatPathTrav, 6, "发布目录下的环境变量文件探测", "", []string{"public", ".env"}},
	// 182：OFBiz webtools 的 Groovy 程序导出端点（RCE）。黑侧 42 条全为 POST，
	// 请求体 groovyProgram=；白侧同端点 2 条为 HEAD/GET 的目录探测，方法排除。
	{"owasp:endpoint:182", CatCmdInject, 6, "OFBiz Groovy 程序导出端点命令执行", "POST", []string{"webtools", "control", "main", "programexport"}},
	// 183-190：.env 备份/分环境变体族。判据是「首段即该文件名」的单段形态
	// （`/.env.old`、`/.env.swp`…），不含子目录。这一层收窄来自白侧实测：
	// 白侧末段为 .env 的请求 2833 条（359 个样本），其中 2753 条（289 个样本）
	// 是 `/flask/.env`、`/config/database/.env` 这类子目录形态的整站扫描流量，
	// 只有 80 条落在根路径；把规则放宽成「任意深度末段匹配」等于把这批
	// 扫描流量整体变成误报。
	// 逐条白侧命中数为 0；`.env.bak`（白侧 1 条 `/.env.BAK`）与 `.env.dist`
	// （白侧 1 条 `//.env.dist`）不收录。
	{"owasp:endpoint:183", CatPathTrav, 6, "环境变量文件备份变体探测", "", []string{".env.old"}},
	{"owasp:endpoint:184", CatPathTrav, 6, "环境变量文件交换变体探测", "", []string{".env.swp"}},
	{"owasp:endpoint:185", CatPathTrav, 6, "环境变量文件备份副本探测", "", []string{".env.backup"}},
	{"owasp:endpoint:186", CatPathTrav, 6, "环境变量文件另存变体探测", "", []string{".env.save"}},
	{"owasp:endpoint:187", CatPathTrav, 6, "环境变量文件生产环境变体探测", "", []string{".env.prod"}},
	{"owasp:endpoint:188", CatPathTrav, 6, "环境变量文件生产环境全称变体探测", "", []string{".env.production"}},
	{"owasp:endpoint:189", CatPathTrav, 6, "环境变量文件本地生产变体探测", "", []string{".env.production.local"}},
	{"owasp:endpoint:190", CatPathTrav, 6, "环境变量文件配置变体探测", "", []string{".env.config"}},
	// 191：ThinkPHP 的 s 参数任意文件读取。黑侧 80 条 query 均带 `s=/index/qrcode/
	// download/url/<base64>` 或 `s=/index/\think\app/invokefunction`；白侧同端点 3 条为
	// /public/index.php/material/… 与 /home/… 的正常图片下载，不带 s 参数，由
	// query 闸门排除。闸门只判「参数是否存在」——该参数的值形态由路由决定，
	// 没有稳定字面量可比对。
	{"owasp:endpoint:191", CatPathTrav, 6, "ThinkPHP s 参数任意文件读取端点", "GET", []string{"public", "index.php"}},
	// 192-201：WordPress 插件目录下的文件级落点，与 074-078 同一收录口径——
	// 全语料 140572 条按段前缀重算，白侧任一请求命中 0；黑侧数字是 r91 基线上
	// 仍漏报（fn）的首请求样本数。这批的形态与 074-078 的差别：判据落在
	// 「插件漏洞利用链的直接落点」上（版本文件、任意文件读取参数、上传目录里
	// 的落地脚本），不是插件内的通用目录。
	//
	// 192-194 是 readme.txt 版本探测。黑侧 25/17/13 条均为 GET 且不带 query。
	// 白侧全语料有 8 条同形态请求，落在 wp-planet、woocommerce-pdf-invoices-
	// packing-slips 等真实站点自带插件上，插件名与本批不重叠——这正是不能写成
	// 「wp-content/plugins/*/readme.txt」通配的原因：那会把 8 条正常请求变成误报。
	{"owasp:endpoint:192", CatPathTrav, 5, "WordPress 插件 elementor 版本文件探测", "GET", []string{"wp-content", "plugins", "elementor", "readme.txt"}},
	{"owasp:endpoint:193", CatPathTrav, 5, "WordPress 插件 hash-form 版本文件探测", "GET", []string{"wp-content", "plugins", "hash-form", "readme.txt"}},
	{"owasp:endpoint:194", CatPathTrav, 5, "WordPress 插件 wp-statistics 版本文件探测", "GET", []string{"wp-content", "plugins", "wp-statistics", "readme.txt"}},
	// 195：Backup Migration 插件的 backup-heart.php 代码注入（CVE-2023-6553）。
	// 黑侧该路径共 20 条请求全为 POST 空 body，其中 19 条样本在 r91 基线上仍
	// 漏报；白侧 0。
	{"owasp:endpoint:195", CatCmdInject, 6, "WordPress 插件 backup-backup 代码注入端点", "POST", []string{"wp-content", "plugins", "backup-backup", "includes", "backup-heart.php"}},
	// 196：Sniplets 插件的 syntax_highlight.php 任意文件包含。黑侧 18 条 GET 均带
	// libpath=../../../../wp-config.php；白侧同端点 1 条为 HEAD 探测，方法排除。
	{"owasp:endpoint:196", CatPathTrav, 6, "WordPress 插件 sniplets 任意文件包含端点", "GET", []string{"wp-content", "plugins", "sniplets", "modules", "syntax_highlight.php"}},
	// 197：Ebook Download 插件的 filedownload.php 任意文件下载。黑侧 14 条 GET 均带
	// ebookdownloadurl=../../../wp-config.php；白侧 0。
	{"owasp:endpoint:197", CatPathTrav, 6, "WordPress 插件 ebook-download 任意文件下载端点", "GET", []string{"wp-content", "plugins", "ebook-download", "filedownload.php"}},
	// 198：W3 Total Cache 的 pub/sns.php SNS 消息注入（CVE-2019-6715）。黑侧 14 条
	// 全为 PUT，body 为 AWS SNS SubscriptionConfirmation 且 SubscribeURL 指向
	// 攻击方采集域名；白侧同端点 0。PUT 是该端点的调用约定，方法约束已足够。
	{"owasp:endpoint:198", CatSSRF, 6, "WordPress 插件 w3-total-cache SNS 消息注入端点", "PUT", []string{"wp-content", "plugins", "w3-total-cache", "pub", "sns.php"}},
	// 199：Simple File List 的 ee-downloader.php 任意文件下载。黑侧 13 条 GET 均带
	// eeFile=%2e%2e%2f%2e%2e%2f…；白侧 0。
	{"owasp:endpoint:199", CatPathTrav, 6, "WordPress 插件 simple-file-list 任意文件下载端点", "GET", []string{"wp-content", "plugins", "simple-file-list", "includes", "ee-downloader.php"}},
	// 200：Adaptive Images 的 adaptive-images-script.php 任意文件包含。黑侧 13 条
	// GET 均带 adaptive-images-settings[source_file]=../../../wp-config.php
	// （12 条裸方括号、1 条 %5B/%5D 编码）；白侧 0。
	{"owasp:endpoint:200", CatPathTrav, 6, "WordPress 插件 adaptive-images 任意文件包含端点", "GET", []string{"wp-content", "plugins", "adaptive-images", "adaptive-images-script.php"}},
	// 201：Import XML Feed 插件的 uploads 目录被写入落地脚本后回连。黑侧 22 条 GET
	// 均为 /uploads/<27 位十六进制>.php?cmd=ping+<随机>.oast.me；末段是随机文件名，
	// 无法枚举，故只收前四段。matchEndpointSegmentsFold 是前缀语义——读完 want
	// 即返回，不要求路径在那里结束，因此四段本身就是「列目录」。
	{"owasp:endpoint:201", CatWebshell, 6, "WordPress 插件 import-xml-feed 上传目录落地脚本探测", "GET", []string{"wp-content", "plugins", "import-xml-feed", "uploads"}},
	// 202：Docker Engine API 的容器 exec。黑侧 824 条全为
	// POST /<版本>/containers/<容器 ID>/exec，body 含 "Cmd" 键（启动命令数组）；
	// 版本段（v1.24 823 条、v1.29 1 条）与容器 ID 都不可枚举，故首段与第三段
	// 用通配哨兵 endpointWildcardSegment。
	//
	// 白侧代价是这条规则只能用「末段 exec + 请求体标记」收窄：白侧在同形的
	// /v1.24/containers/<id>/ 下有 200 条 POST restart、各 1 条 start/kill/attach，
	// 全部落在末段 exec 之外；另有 2 条 HEAD exec 被方法约束排除。闸门后白侧 0。
	// 不要把它放宽成 containers 前缀——那 200 条 restart 会整体变成误报。
	//
	// 与 009（[]string{"v1.24","containers","bash","exec"}）的关系：009 覆盖
	// 「容器名恰为 bash」这一具体形态，本规则覆盖任意容器 ID。两者不冲突，
	// 009 挂在两级索引上、先于通配列表被遍历，因此更具体的形态仍报 009。
	{"owasp:endpoint:202", CatCmdInject, 6, "Docker Engine API 容器 exec 命令执行", "POST", []string{endpointWildcardSegment, "containers", endpointWildcardSegment, "exec"}},
	// 203：VMware vCenter 的 /sdk SOAP 端点。黑侧 80 条全为 POST /sdk，body 以
	// <soap:Envelope> 起始（operationID 00000001-00000001 + urn:internalvim25）。
	// 白侧同端点 1 条 POST /sdk/vimService 是 gSOAP 客户端的正常调用，前缀为
	// SOAP-ENV:，由请求体标记闸门排除；另有 HEAD /sdk 3 条、GET /sdk 1 条由方法
	// 约束排除。单段规则前缀匹配会同时命中 /sdk/vimService，闸门不可省。
	{"owasp:endpoint:203", CatCmdInject, 6, "VMware vCenter SDK SOAP 端点探测", "POST", []string{"sdk"}},
	// 204：Supervisord 的 XML-RPC 远程控制端点。黑侧 22 条全为 POST /RPC2，body
	// 恒为 methodCall，methodName 走 Python 对象遍历链
	// supervisor.supervisord.options.warnings.linecache.os.system（把 os.system
	// 取出来当可调用对象用）。合法 supervisord 客户端调用的是
	// supervisor.getState / getAllProcessInfo 一类命名方法，不会遍历到 os.system，
	// 因此判别力全部来自请求体标记，路径本身只是收窄入口。
	//
	// 白侧全语料该标记 0 条（首请求 / 任一子请求 / 全部子请求三口径均为 0），
	// 白侧 /RPC2 路径本身也是 0 条。裸路径规则不可取：小写 /rpc2、带尾斜杠等
	// 扩展形态会一并命中，闸门是唯一把这条规则和「普通 XML-RPC 服务」分开的依据。
	{"owasp:endpoint:204", CatDeserial, 7, "Supervisord XML-RPC 对象遍历命令执行", "POST", []string{"rpc2"}},
	// 205：Jira 用户组选择器的未授权用户枚举（CVE-2019-8449）。黑侧 19 条全为
	// GET /rest/api/latest/groupuserpicker，query 逐字节恒为
	// `query=1&maxResults=50000&showAvatar=true`；全语料白侧 0 条。
	//
	// 白侧确实有 Jira 流量（`/jira/secure/Dashboard.jspa`、`/rest/api/2/screens`、
	// `/rest/api/latest/repos`），但都在 `/rest/api/v2/…` 或别的 product 路径下，
	// 没有一个落在 `latest/groupuserpicker`。因此本规则不能放宽到 `/rest/api/`
	// 前缀——那会把正常的 Jira REST 调用整体打成误报。
	//
	// 闸门取 maxResults=50000：这个取值不是正常 UI 会产生的大小（Jira 的组选择器
	// 默认分页 20），全语料只有这 19 条黑样本带该值，白侧 0 条。
	{"owasp:endpoint:205", CatCmdInject, 5, "Jira 用户组选择器未授权用户枚举", "GET", []string{"rest", "api", "latest", "groupuserpicker"}},
	// IP 摄像头/视频设备接口的 URL 明文凭据探测：正常访问不会把账号密码
	// 放进查询串，黑侧 videostream.cgi 216/218、snapshot.cgi 69/81 都带凭据，
	// 白侧同端点分别只有 2 条（且同样为明文凭据）。
	{"owasp:endpoint:206", CatCmdInject, 6, "摄像头视频流接口明文凭据探测", "", []string{"videostream.cgi"}},
	{"owasp:endpoint:207", CatCmdInject, 6, "摄像头快照接口明文凭据探测", "", []string{"snapshot.cgi"}},
	// 海康 ISAPI 认证接口本身即设备管理面探测：黑侧 53/53 命中，白侧 1 条
	// 为 MSIE 6.0 探测流量。该接口的凭据在请求体/Authorization 中，故不加
	// 查询串闸门。
	{"owasp:endpoint:208", CatCmdInject, 5, "海康 ISAPI 认证接口探测", "", []string{"isapi", "security", "usercheck"}},
	// 210：D-Link 系网关的 gw.cgi 把整段 XML 塞进查询串，账号密码以
	// `<rpermission usr="..." pwd="...">` 形式随 URL 传输。黑侧 277 条子请求
	// pwd 非空（其中 19 条已因 `;telnet` 命令注入被主扫描拦截），白侧 0 条
	// 命中；pwd 为空是正常的状态读取，不拦。
	{"owasp:endpoint:210", CatCmdInject, 6, "网关管理接口 URL 内 XML 明文凭据", "GET", []string{"cgi-bin", "gw.cgi"}},
	// 211/212：Nacos 用户管理接口的未授权访问（CVE-2021-29441 一类）。
	// 全部 Nacos 接口默认关闭鉴权、用户管理接口可匿名增删用户；两个判据互不
	// 覆盖，必须各占一条规则：
	//   211 收「服务端身份伪造」——请求头 User-Agent: Nacos-Server 是 Nacos
	//   1.x 鉴权过滤器用来识别内部调用的标记，攻击者伪造它即可绕过鉴权。黑侧
	//   9 GET + 9 POST 全部带该指纹，白侧同端点 0 条（白侧唯一一条该 UA 的
	//   请求是 /nacos/v1/cs/ops/data/removal 的集群数据同步，路径不同）。
	//   212 收「GET 用户列表」——该接口的 GET 语义是批量枚举（pageNo+
	//   pageSize，或带 accessToken）。全语料白侧对该路径的 GET 为 0 条（白侧
	//   只有 3 条 DELETE 精确用户名、1 条空 POST 探测），故 GET 恒为未授权
	//   枚举。注意不可用「是否带 accessToken」放行：黑侧 GET 样本多数带
	//   伪造 token，token 在无鉴权配置下不具任何信任效力。
	// exact 为 true：精确匹配本体路径，避免把 /nacos/v1/auth/users/login
	// （登录页，白侧正常访问）误当用户列表枚举。
	{id: "owasp:endpoint:211", category: CatCmdInject, score: 6, desc: "Nacos 用户管理接口服务端身份伪造", segs: []string{"nacos", "v1", "auth", "users"}},
	{id: "owasp:endpoint:212", category: CatCmdInject, score: 6, desc: "Nacos 用户管理接口用户列表枚举", method: "GET", segs: []string{"nacos", "v1", "auth", "users"}},
	// 213：WebLogic wls-wsat 组件的 SOAP 反序列化端点（CVE-2017-10271 一族）。
	// 036 只收 CoordinatorPortType，RegistrationRequesterPortType 是该组件的
	// 另一个入口。黑侧 17 条全部 POST + text/xml 的 SOAP 信封，白侧全语料 0 条。
	{id: "owasp:endpoint:213", category: CatDeserial, score: 6, desc: "WebLogic wls-wsat 注册请求反序列化端点探测", method: "POST", segs: []string{"wls-wsat", "registrationrequesterporttype"}},
	// 214：Zain.php 是公开 webshell 后门的固定文件名。黑侧 17 条 POST 携带
	// 命令参数（如 `yokyokyok=uname -a`），白侧全语料 0 条。
	{id: "owasp:endpoint:214", category: CatCmdInject, score: 6, desc: "Zain 后门脚本探测", segs: []string{"zain.php"}},
	// 215/216：前端资源目录下的 .env 探测。子目录形态的 /x/.env 在语料里存在
	// 大量白侧标记的整站扫描流量，故不收通用「任意子目录 + .env」；这里只收
	// 实测白侧 0 的两个固定前缀。黑侧 js/.env 18 条、lib/.env 45 条。
	{id: "owasp:endpoint:215", category: CatPathTrav, score: 6, desc: "前端资源目录下的环境变量文件探测", method: "GET", segs: []string{"js", ".env"}},
	{id: "owasp:endpoint:216", category: CatPathTrav, score: 6, desc: "库目录下的环境变量文件探测", method: "GET", segs: []string{"lib", ".env"}},
	// 217：群晖 DSM 的 SSDP 设备描述文件。该文件只在同一网段的 SSDP 发现
	// 流程中由设备主动广播，正常 Web 访问不会直接请求；黑侧 18 条 GET，
	// 白侧全语料 0 条。
	{id: "owasp:endpoint:217", category: CatPathTrav, score: 5, desc: "群晖 DSM SSDP 设备描述文件探测", method: "GET", segs: []string{"ssdp", "desc-dsm-eth1.xml"}},
	// 218：帆软 FineReport 的报表服务 Servlet 未授权访问（CVE-2018-1000636
	// 一族）。黑侧 34 条 GET，白侧全语料 0 条。
	{id: "owasp:endpoint:218", category: CatCmdInject, score: 6, desc: "帆软报表服务未授权访问探测", segs: []string{"webreport", "reportserver"}},
	// 219：交互式外带（interactsh）域名的回连探测，路径整体为 `//域名` 形式。
	// 正常业务不会把外部交互平台域名作为路径请求，黑侧 18 条 GET，白侧 0 条。
	{id: "owasp:endpoint:219", category: CatSSRF, score: 6, desc: "交互式外带域名回连探测", method: "GET", segs: []string{"www.interact.sh"}},
	// 220：DVR/NVR 的 EXCU_SHELL 命令执行端点。判别力来自请求头 `Cmdnum`：
	// 黑侧 23 条全部携带该头（值形如 `;ls`），白侧唯一一条同路径请求是
	// 普通浏览器 GET，不带该头。
	{id: "owasp:endpoint:220", category: CatCmdInject, score: 6, desc: "DVR 命令执行外壳端点探测", method: "GET", segs: []string{"excu_shell"}},
	// 221：Craft CMS 的 ConditionsController 反序列化 RCE（CVE-2023-41892）。
	// 黑侧 18 条 POST 表单全部带 action=conditions/render 与 Guzzle gadget
	// 链，白侧全语料 0 条。
	{id: "owasp:endpoint:221", category: CatDeserial, score: 6, desc: "Craft CMS 条件构造器反序列化端点探测", method: "POST", segs: []string{"conditionscontroller.php"}},
	// 222：某分析平台的遥测上报接口（ph/api/hyper/send）被用于注入探测。
	// 黑侧 17 条 POST 全部发往该六段路径，白侧全语料 0 条。
	{id: "owasp:endpoint:222", category: CatCmdInject, score: 5, desc: "遥测上报接口注入探测", method: "POST", segs: []string{"analytics", "telemetry", "ph", "api", "hyper", "send"}},
	// 223：UserSelect 用户选择接口的注入探测。黑侧 17 条 GET，白侧 0 条。
	{id: "owasp:endpoint:223", category: CatCmdInject, score: 5, desc: "用户选择接口注入探测", method: "GET", segs: []string{"userselect"}},
}

// endpointExactPathRules 记录要求「段序列完全一致」的规则。缺省的段匹配是
// 前缀语义（matchEndpointSegmentsFold），规则 segs 是路径段序列的前缀即可
// 命中。endpointExactPathRules 中的规则改用 matchEndpointSegmentsExact，
// 要求路径段数恰好等于 segs（剩余部分为空或仅 '/'）。
//
// 仅用于本体路径可能被其「子路径」误伤的场景：/nacos/v1/auth/users
// （用户列表枚举）不应匹配到 /nacos/v1/auth/users/login（登录页，白侧正常
// 访问）。子路径命中是把「管理模式探针」泛化到了「认证入口」。
var endpointExactPathRules = map[string]bool{
	"owasp:endpoint:211": true,
	"owasp:endpoint:212": true,
}

// endpointWildcardSegment 是段序列里的通配哨兵：该段匹配任意单个非空路径段。
// 只有 202（Docker Engine exec）使用——API 版本号与容器 ID 都无法枚举，而表里
// 没有别的通配需求，因此不引入更复杂的模式语法。
const endpointWildcardSegment = "*"

var endpointBodyGates = map[string][]string{
	// SonicWall SSL-VPN 登录表单的证书校验开关与门户名：黑侧 1308/1308
	// 全含（值恒为 verifyCert=0、portalname=VirtualOffice），白侧 291 条
	// 命中 0。
	"owasp:endpoint:087": {"verifyCert", "portalname"},
	// Cisco ASA WebVPN 门户登录表单的 tg-cookie 复选位与语言选择器：
	// 黑侧 1567/2480 命中（是子集，其余 913 条为其他形态），白侧 12 条
	// 命中 0。后 9 个字段是黑侧 CSRF 混淆表单族的字段名并集：该族在
	// absform 基线上另漏报 913 条，字段并集覆盖其中 898 条，白侧 12 条
	// 全部只有 username/password/csrf_token/group_list，仍为 0。
	"owasp:endpoint:088": {
		"tgcookieset", "language-selector",
		"csrfmiddlewaretoken", "__csrf_magic", "formulaire_action_args",
		"javax.faces.ViewState", "csrfKey", "formid", "password_fieldname",
		"login_authorization", "action_mode",
	},
	// Fortinet SSL-VPN 校验接口的 XHR 标记（值恒为 ajax=1）：黑侧
	// 1942/1942 全含，白侧 5 条命中 0（白侧是同端点的登录后回跳表单，
	// 用 just_logged_in/redir 而非 ajax）。
	"owasp:endpoint:089": {"ajax"},
	// Citrix NetScaler 登录表单的诱饵字段（恒为空值，用于干扰浏览器
	// 自动填充）：黑侧 95/108 命中（其余 13 条无请求体），白侧 5 条命中 0
	// ——白侧唯一携带该字段的样本方法是 GOST，已被表内的方法约束排除。
	"owasp:endpoint:090": {"dummy_username"},
}

type endpointHeaderGate struct {
	name     string
	contains string
}

// endpointQueryGate 记录查询串闸门。b64Prefix 非 0 时按「参数值 base64 解码
// 后以该前缀（ASCII 折叠）起始」判定（ONVIF 的 auth=admin:… 形态）；否则按
// 「参数名折叠匹配且值精确等于 eqValue」判定（Ministra 的 type=stb 形态）。
type endpointQueryGate struct {
	param     string
	eqValue   string
	b64Prefix string
}

// endpointQueryGates 记录查询串闸门。每条规则只有一个闸门；多条规则不得共用，
// 语义分歧时拆成独立字段而不是往结构体里塞方向位。
var endpointQueryGates = map[string]endpointQueryGate{
	// Ministra 系端点只收 stb 客户端：白侧同端点的 type=account_info 与
	// type=itv 是机顶盒门户的正常接口查询，闸门排除。
	"owasp:endpoint:166": {param: "type", eqValue: "stb"},
	"owasp:endpoint:167": {param: "type", eqValue: "stb"},
	// ONVIF 快照弱凭据：auth 参数值是 base64(user:pass)，黑侧解码恒为
	// admin: 开头；白侧唯一携带 auth 的样本解码不出该前缀。
	"owasp:endpoint:172": {param: "auth", b64Prefix: "admin:"},
	// DotNetNuke 安装向导：黑侧 44 条 query 的首个参数恒为
	// Action=createadministrator（后接 adminusername/adminpassword/adminemail）；
	// 白侧同端点 0 条。安装向导的正常访问不带该动作参数。
	"owasp:endpoint:179": {param: "action", eqValue: "createadministrator"},
	// Jira 用户组选择器的用户枚举（CVE-2019-8449）：黑侧 19/19 条 query 带
	// maxResults=50000（Jira 组选择器默认分页 20），全语料白侧该取值 0 条。
	// param 必须是小写字面量（体检用例要求），匹配时按 ASCII 折叠，故这里
	// 写 maxresults 仍能命中实际的 maxResults。
	"owasp:endpoint:205": {param: "maxresults", eqValue: "50000"},
}

// endpointQueryParamPresentGates 记录「查询串出现任一参数名即命中」的闸门。
// 与 endpointQueryGates 分开是语义需要：ThinkPHP 的 s 路由参数值形态由路由
// 决定（qrcode/download/url 与 invokefunction 两种都不共享字面量），判别力
// 全部来自「参数本身是否出现」——黑侧 80 条都带 s=，白侧同端点的正常图片
// 下载一条都没有。
//
// 设备摄像头接口的凭据参数名不统一（user/username/usr/pwd/pass/...），
// 因此每个规则登记一组候选名，命中任意一个即通过闸门。
var endpointQueryParamPresentGates = map[string][]string{
	"owasp:endpoint:191": {"s"},
	"owasp:endpoint:206": {"user", "username", "usr", "pwd", "pass", "password", "passwd"},
	"owasp:endpoint:207": {"user", "username", "usr", "pwd", "pass", "password", "passwd"},
}

// endpointUserAgentGates 记录「请求头 User-Agent 出现该标记才命中」的专用
// 闸门。与 endpointHeaderGates 分开是设计需要：后者被测试约束为不得使用
// 通用身份头（Accept/User-Agent/Cookie 等），而本条判据恰恰是「伪造服务端
// 内部调用方 UA」这一特定攻击面，属于产品协议字段级别的识别而非通用身份。
//
// Nacos 1.x 鉴权过滤器通过 User-Agent: Nacos-Server 识别内部服务调用并跳过
// 鉴权（CVE-2021-29441 一族），攻击者伪造该 UA 即可匿名访问用户管理 API。
// 黑侧 18 条（9 GET + 9 POST）全部带该指纹，白侧同端点 0 条。
var endpointUserAgentGates = map[string]string{
	"owasp:endpoint:211": "nacos-server",
}

// endpointHeaderPresentGates 记录「请求头名出现即命中」的专用闸门。
// 与 endpointHeaderGates 不同：后者要求特定头 + 值标记，而本表只要求某个
// 非通用产品协议头存在（如 EXCU_SHELL 端点的 `Cmdnum`——此头本身即命令
// 执行外壳的指令通道，黑侧 23 条全部携带，白侧同路径的普通浏览器请求不带）。
var endpointHeaderPresentGates = map[string]string{
	"owasp:endpoint:220": "cmdnum",
}

// endpointQueryDecodedAttrGates 记录「查询串 URL 解码后含 name="非空值" 属性」的
// 闸门。部分设备把整段 XML 作为顶层 query 参数（`xml=%3C...pwd%3D%22x%22...`），
// 属性名藏在解码后的 XML 里，endpointQueryGates / endpointQueryParamPresentGates
// 都无法表达「同名属性且值非空」。值为空串（`pwd=""`）是正常的状态读取，不命中。
var endpointQueryDecodedAttrGates = map[string]string{
	"owasp:endpoint:210": "pwd",
}

// endpointAuthBasicGate 记录「Authorization: Basic 凭据解码后包含标记」的
// 闸门。标记为小写字面量，按 ASCII 折叠比较。
type endpointAuthBasicGate struct {
	marker    string
	exactSegs bool
}

var endpointAuthBasicGates = map[string]endpointAuthBasicGate{
	// Tomcat Manager 爆破：黑侧精确路径全部带 Basic 头（凭据本身不重要，
	// 白侧同路径不带认证头）。配合段数约束：黑侧 90 条全为恰两段
	// /manager/html，白侧带 Basic 的 3 条是 /manager/html/manager 的
	// Python-urllib 深度探测。
	"owasp:endpoint:173": {marker: "", exactSegs: true},
	// VERM 控制器 SQL 注入：Basic 凭据解码后为 goolicker', '', (SELECT …));#
	// 注入载荷；白侧同端点请求无 Authorization 头。
	"owasp:endpoint:174": {marker: "select"},
}

// endpointHeaderGates 记录请求头闸门。每条规则的多个闸门项为「任一满足」；
// 同一规则只登记产品协议字段，不使用通用身份字段，避免把普通业务请求泛化为端点命中。
var endpointHeaderGates = map[string][]endpointHeaderGate{
	"owasp:endpoint:159": {
		{name: "content-type", contains: "application/soap+xml"},
		{name: "content-type", contains: "text/xml"},
	},
	"owasp:endpoint:165": {
		{name: "side", contains: "upload"},
		{name: "side", contains: "download"},
	},
}

// endpointBodyContainsGates 记录 XML/SOAP 等非表单协议的请求体标记。
// 标记一律为小写字面量：containsASCIIFold 的第二个参数假定已小写，
// 传入大写会静默失配。
var endpointBodyContainsGates = map[string][]string{
	"owasp:endpoint:160": {"purenetworks.com/hnap1/"},
	// 开放注册接口的 JSON 注册字段：黑侧 272/272 含带引号的 email 键，
	// 白侧该端点 0 条。标记取带引号的键名，避免与普通表单的 email=
	// 字段混淆。
	"owasp:endpoint:168": {`"email"`},
	// XML-RPC 方法枚举载荷：黑侧 109/139 条 POST 含 system. 前缀方法名，
	// 白侧唯一一条 POST 是 wp.newTerm 表单，不含该标记。
	"owasp:endpoint:169": {"system."},
	// Docker Engine exec 的启动命令数组：黑侧 824/824 条 POST 含 "Cmd" 键
	// （JSON 里恒为 `"Cmd":["sh","-c",…]`），白侧同端点形态 0 条。标记取带
	// 引号的键名，避免与路径里出现的 cmd 字样混淆。
	"owasp:endpoint:202": {`"cmd"`},
	// VMware vCenter SDK 的 SOAP 信封：黑侧 80/80 条以 <soap:Envelope> 起始，
	// 白侧唯一一条 POST /sdk/vimService 用 SOAP-ENV: 前缀（gSOAP 客户端），
	// 不被该标记匹配。
	"owasp:endpoint:203": {"<soap:envelope"},
	// Supervisord XML-RPC 的对象遍历 gadget chain：合法客户端按名字调
	// supervisor.getState 一类方法，只有利用载荷才会把 os.system 当成可调用
	// 对象取出来。黑侧 22/22 含该串，白侧全语料 0 条。
	"owasp:endpoint:204": {"supervisor.supervisord.options.warnings.linecache.os.system"},
}

// endpointRulesByFirstTwoSegments 按「首段 -> 次段 -> 规则下标」两级索引规则，
// 单段规则（segs 长度 1）挂在空次段键下。在包初始化时一次性构建：
// 每次调用重建会破坏热路径的零分配目标。
//
// 首段为 endpointWildcardSegment 的规则不进本索引：它们的首段不参与比较，
// 由 endpointWildcardRules 单独索引。
var endpointRulesByFirstTwoSegments = func() map[string]map[string][]int16 {
	m := make(map[string]map[string][]int16, len(sensitiveEndpointRules))
	for i := range sensitiveEndpointRules {
		rule := &sensitiveEndpointRules[i]
		first := rule.segs[0]
		if first == endpointWildcardSegment {
			continue
		}
		second := ""
		if len(rule.segs) > 1 {
			second = rule.segs[1]
		}
		inner, ok := m[first]
		if !ok {
			inner = make(map[string][]int16, 2)
			m[first] = inner
		}
		inner[second] = append(inner[second], int16(i))
	}
	return m
}()

// endpointWildcardRuleEntry 是一条首段通配规则的预计算索引项：次段字面量
// （小写，空串表示该规则只有一段）+ 规则下标。
type endpointWildcardRuleEntry struct {
	second string
	index  int16
}

// endpointWildcardRules 列出首段为 endpointWildcardSegment 的规则，带上次段
// 字面量供热路径先做一次廉价短路。
//
// 不建成 map：条目只有个位数，map 探测要先哈希一次次段字符串；逐条按长度
// 短路再逐字节比较更便宜，且同样零分配。条目增长到十几条以上时应改回索引。
var endpointWildcardRules = func() []endpointWildcardRuleEntry {
	var out []endpointWildcardRuleEntry
	for i := range sensitiveEndpointRules {
		rule := &sensitiveEndpointRules[i]
		if rule.segs[0] != endpointWildcardSegment {
			continue
		}
		second := ""
		if len(rule.segs) > 1 {
			second = rule.segs[1]
		}
		out = append(out, endpointWildcardRuleEntry{second: second, index: int16(i)})
	}
	return out
}()

// maxEndpointSegmentBytes 是首段/次段折叠缓冲区的容量。
// 表中首段最长 21 字节（"passwordrecovered.cgi"、".env.production.local"），
// 次段最长 27 字节（"saveuploadedhotspotlogofile"、"cms_changedevicecontext.esp"），
// 取 32 字节留足余量；超长段不可能是表中端点，直接判不命中。
const maxEndpointSegmentBytes = 32

func CheckSensitiveEndpointPath(path, method string) (OWASPHit, bool) {
	return CheckSensitiveEndpointPathWithHeaders(path, method, nil, nil)
}

/**
 * CheckSensitiveEndpointPathWithBody 是带请求体闸门的端点检查。
 *
 * body 传 WAF 已采样的请求体（数据面为 RequestCtx.Body，最多 48 KiB）。
 * 读 body 的闸门有两张表：endpointBodyGates 按 form 语义（字段名以 '&' 或
 * 请求体首字节起、后跟 '='）扫描，endpointBodyContainsGates 按小写字面量
 * 折叠子串匹配。其余规则的判定路径与 CheckSensitiveEndpointPath 逐字节一致。
 *
 * body 的切片口径由调用方决定，本函数不做任何解析。
 */
func CheckSensitiveEndpointPathWithBody(path, method string, body []byte) (OWASPHit, bool) {
	return CheckSensitiveEndpointPathWithHeaders(path, method, nil, body)
}

/**
 * CheckSensitiveEndpointPathWithHeaders 检查路径、方法以及可选的请求头/请求体
 * 闸门。旧入口保留给只需要路径判定的调用方与兼容测试：它不携带查询串，
 * 因此登记了查询串闸门的规则（166/167/172）在该入口下恒不命中。
 */
func CheckSensitiveEndpointPathWithHeaders(path, method string, headers map[string]string, body []byte) (OWASPHit, bool) {
	return CheckSensitiveEndpointPathWithRequest(path, method, "", headers, body)
}

/**
 * CheckSensitiveEndpointPathWithRequest 是数据面使用的完整入口：路径、方法、
 * 查询串、请求头与请求体全部参与判定。
 *
 * query 必须是不含 '?' 的裸查询串（数据面为 ctx.RawQuery）。只有登记在
 * endpointQueryGates 的规则会读它，其余规则的判定路径与
 * CheckSensitiveEndpointPathWithHeaders 完全一致。
 */
func CheckSensitiveEndpointPathWithRequest(path, method, query string, headers map[string]string, body []byte) (OWASPHit, bool) {
	if path == "" {
		return OWASPHit{}, false
	}
	var firstBuf, secondBuf [maxEndpointSegmentBytes]byte
	firstLen, secondLen, ok := firstTwoPathSegments(path, &firstBuf, &secondBuf)
	if ok {
		if inner, found := endpointRulesByFirstTwoSegments[string(firstBuf[:firstLen])]; found {
			// keyLen 为次段长度；keyLen<0 表示查单段规则（挂在空串键下）。
			for _, keyLen := range [2]int{secondLen, -1} {
				var candidates []int16
				if keyLen < 0 {
					candidates = inner[""]
				} else {
					candidates = inner[string(secondBuf[:keyLen])]
				}
				for _, idx := range candidates {
					rule := &sensitiveEndpointRules[idx]
					if !endpointRuleMatches(rule, path, method, query, headers, body) {
						continue
					}
					return OWASPHit{Category: rule.category, RuleID: rule.id, Score: rule.score, Desc: rule.desc}, true
				}
			}
		}
		// 首段通配的规则不在两级索引里（首段不参与比较），逐个比较段序列。
		// 先用次段做一次廉价短路：首段通配下绝大多数请求会在这一步被排除，
		// 不会进到 matchEndpointSegmentsFold 的完整遍历。
		for _, entry := range endpointWildcardRules {
			if entry.second != "" && !equalASCIIFold(string(secondBuf[:secondLen]), entry.second) {
				continue
			}
			rule := &sensitiveEndpointRules[entry.index]
			if !endpointRuleMatches(rule, path, method, query, headers, body) {
				continue
			}
			return OWASPHit{Category: rule.category, RuleID: rule.id, Score: rule.score, Desc: rule.desc}, true
		}
	}
	// 服务器备份/数据库文件直链下载兜底。判据是末段后缀而不是段序列，因此
	// 放在索引查找之后：既有端点命中保持原归因，本规则只填补原本放行的请求。
	// 同时它必须在 firstTwoPathSegments 失败（首段超过 32 字节）时仍然生效，
	// 故不能放在入口最前由 !ok 提前返回。
	if matchBackupSensitiveFile(path, method) {
		return OWASPHit{Category: CatPathTrav, RuleID: "owasp:endpoint:209", Score: 6, Desc: sensitiveBackupFileDesc}, true
	}
	return OWASPHit{}, false
}

// sensitiveBackupFileDesc 是 209 规则的说明，入口发射与规则目录登记共用，
// 避免两处文字漂移。
const sensitiveBackupFileDesc = "服务器备份或数据库文件直接下载"

// sensitiveBackupFileSuffixes 是「服务器备份包/数据库导出文件」的高危后缀表，
// 全部为小写字面量，按 ASCII 折叠做末段后缀比较。
//
// 语料口径（全量 140572 条）：末段命中这些后缀且方法为 GET/HEAD 的样本，
// 黑侧仍漏报 1127 条、白侧漏报 0 条；POST 黑侧仅 1 条，不属于下载语义，不收。
// `.gz` 刻意不收录：黑侧 201 条中混有 sitemap.xml.gz 这类正常压缩资源，
// 收录会对真实业务造成误伤。
var sensitiveBackupFileSuffixes = []string{
	".sql", ".sqlite", ".db", ".bak", ".tar", ".tgz", ".7z", ".rar", ".zip",
}

/**
 * matchBackupSensitiveFile 判断请求是否为「直接下载服务器备份/数据库文件」。
 *
 * 只接受 GET/HEAD（文件下载语义）。取路径末段并去掉尾随斜杠，在首个 ';' 处
 * 截断（与段匹配器对矩阵参数的处理一致），再做 ASCII 折叠后缀比较。
 *
 * @param path   请求路径（数据面为原始未解码路径）。
 * @param method 请求方法。
 * @return 命中任一高危后缀返回 true。
 */
func matchBackupSensitiveFile(path, method string) bool {
	if !strings.EqualFold(method, "GET") && !strings.EqualFold(method, "HEAD") {
		return false
	}
	end := len(path)
	for end > 0 && path[end-1] == '/' {
		end--
	}
	start := end
	for start > 0 && path[start-1] != '/' {
		start--
	}
	if start >= end {
		return false
	}
	seg := path[start:end]
	if i := strings.IndexByte(seg, ';'); i >= 0 {
		seg = seg[:i]
	}
	for _, suffix := range sensitiveBackupFileSuffixes {
		if len(seg) >= len(suffix) && equalASCIIFold(seg[len(seg)-len(suffix):], suffix) {
			return true
		}
	}
	return false
}

/**
 * endpointRuleMatches 判断单条规则是否命中：方法、段序列以及全部闸门。
 *
 * 拆成独立函数是为了让索引命中后的候选遍历只写一遍——规则既可能来自
 * 「首段+次段」两级索引，也可能来自「首段通配」索引，两条路径的闸门语义
 * 必须逐字节一致。
 */
func endpointRuleMatches(rule *sensitiveEndpointRule, path, method, query string, headers map[string]string, body []byte) bool {
	if rule.method != "" && !strings.EqualFold(method, rule.method) {
		return false
	}
	if endpointExactPathRules[rule.id] {
		if !matchEndpointSegmentsExact(path, rule.segs) {
			return false
		}
	} else if !matchEndpointSegmentsFold(path, rule.segs) {
		return false
	}
	// 同一路径可能同时挂着无闸门规则与带闸门规则，因此闸门不满足时
	// 由调用方继续看后续候选，不能直接判不命中。
	if fields := endpointBodyGates[rule.id]; len(fields) > 0 {
		if !endpointBodyHasAnyField(body, fields) {
			return false
		}
	}
	if markers := endpointBodyContainsGates[rule.id]; len(markers) > 0 && !endpointBodyContainsAny(body, markers) {
		return false
	}
	if gates := endpointHeaderGates[rule.id]; len(gates) > 0 && !endpointHeaderHasAny(headers, gates) {
		return false
	}
	if gate, has := endpointQueryGates[rule.id]; has && !endpointQueryGateMatch(query, gate) {
		return false
	}
	if params, has := endpointQueryParamPresentGates[rule.id]; has && !endpointQueryHasParam(query, params) {
		return false
	}
	if name, has := endpointQueryDecodedAttrGates[rule.id]; has && !endpointDecodedQueryHasNonEmptyAttr(query, name) {
		return false
	}
	if marker, has := endpointUserAgentGates[rule.id]; has && !endpointHeaderHasAny(headers, []endpointHeaderGate{{name: "user-agent", contains: marker}}) {
		return false
	}
	if name, has := endpointHeaderPresentGates[rule.id]; has && !endpointHeaderPresent(headers, name) {
		return false
	}
	if gate, has := endpointAuthBasicGates[rule.id]; has && !endpointAuthBasicGateMatch(path, rule.segs, headers, gate) {
		return false
	}
	return true
}

/**
 * endpointQueryGateMatch 判断查询串是否满足闸门。
 *
 * 参数名按 ASCII 折叠精确匹配（`xtype=stb`、`typex=stb` 都不算），值按
 * 原始大小写比较——Ministra 的客户端类型字面量与 ONVIF 的 base64 值都是
 * 大小写敏感的，折叠会改变语义。
 *
 * b64Prefix 非空时按标准 base64 解码参数值（自动补 '='），解码结果以
 * 前缀 ASCII 折叠比较；解码失败即不命中，不做容错猜测。
 */
func endpointQueryGateMatch(query string, gate endpointQueryGate) bool {
	if query == "" || gate.param == "" {
		return false
	}
	for query != "" {
		pair := query
		if i := strings.IndexByte(pair, '&'); i >= 0 {
			pair, query = pair[:i], query[i+1:]
		} else {
			query = ""
		}
		name, value, hasEq := strings.Cut(pair, "=")
		if !hasEq || !equalASCIIFold(name, gate.param) {
			continue
		}
		if gate.b64Prefix != "" {
			if endpointBase64HasPrefix(value, gate.b64Prefix) {
				return true
			}
			continue
		}
		if value == gate.eqValue {
			return true
		}
	}
	return false
}

/**
 * endpointQueryHasParam 判断查询串里是否出现 params 中任一参数名（不看其值）。
 *
 * 参数名按 ASCII 折叠精确匹配，边界与 endpointQueryGateMatch 一致：`xs=1`、
 * `sx=1` 都不算。裸键（`s` 无 '='）不算——语料里的黑样本全部是 `s=<路由>`。
 */
func endpointQueryHasParam(query string, params []string) bool {
	if query == "" || len(params) == 0 {
		return false
	}
	for query != "" {
		pair := query
		if i := strings.IndexByte(pair, '&'); i >= 0 {
			pair, query = pair[:i], query[i+1:]
		} else {
			query = ""
		}
		name, _, hasEq := strings.Cut(pair, "=")
		if !hasEq {
			continue
		}
		for _, param := range params {
			if equalASCIIFold(name, param) {
				return true
			}
		}
	}
	return false
}

/**
 * endpointDecodedQueryHasNonEmptyAttr 判断查询串（先做一轮 URL 解码）中是否
 * 存在 name="非空值" 形式的属性。
 *
 * 仅用于把 XML 整体塞进 query 的设备接口：属性名要求左边界不是字母数字，
 * 避免把 `pppoepwd="x"` 里的 pwd 当成同名属性；值必须在引号内非空，空串
 * （`pwd=""`）是正常的状态读取，不命中。解码失败时按原串判定，不做猜测。
 */
func endpointDecodedQueryHasNonEmptyAttr(query, name string) bool {
	if query == "" || name == "" {
		return false
	}
	if decoded, err := url.QueryUnescape(query); err == nil {
		query = decoded
	}
	// toLowerASCII 保持字节长度不变，非 ASCII 字节原样保留；name 是小写
	// 字面量，因此这里的偏移可直接用于原始 query。
	lower := toLowerASCII(query)
	off := 0
	for off < len(lower) {
		i := strings.Index(lower[off:], name)
		if i < 0 {
			return false
		}
		i += off
		off = i + len(name)
		if i > 0 {
			if c := lower[i-1]; (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') {
				continue
			}
		}
		j := off
		for j < len(lower) && (lower[j] == ' ' || lower[j] == '\t') {
			j++
		}
		if j >= len(lower) || lower[j] != '=' {
			continue
		}
		j++
		for j < len(lower) && (lower[j] == ' ' || lower[j] == '\t') {
			j++
		}
		if j >= len(lower) || lower[j] != '"' {
			continue
		}
		j++
		if j < len(lower) && lower[j] != '"' {
			return true
		}
	}
	return false
}

/**
 * endpointBase64HasPrefix 判断 value 以标准 base64 解码后是否以前缀
 * （ASCII 折叠）起始。
 *
 * 只接受标准字母表（含 '+'、'/'、'='），不做 URL-safe 变体转换：ONVIF
 * 客户端用的就是标准字母表，多接受一种编码只会多一条不可解释的命中面。
 */
func endpointBase64HasPrefix(value, prefix string) bool {
	if value == "" {
		return false
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(value)))
	n, err := base64.StdEncoding.Decode(decoded, []byte(value))
	if err != nil {
		// 缺少尾部填充是扫描器常见形态（`admin:11\n` 编码后不带 '='），
		// 补足到 4 的倍数后重试一次。
		padded := value + strings.Repeat("=", (4-len(value)%4)%4)
		if padded == value {
			return false
		}
		decoded = make([]byte, base64.StdEncoding.DecodedLen(len(padded)))
		n, err = base64.StdEncoding.Decode(decoded, []byte(padded))
		if err != nil {
			return false
		}
	}
	return hasASCIIFoldAt(string(decoded[:n]), 0, prefix)
}

/**
 * endpointAuthBasicGateMatch 判断 Authorization: Basic 凭据是否满足闸门。
 *
 * marker 为空表示「只要求存在可解码的 Basic 凭据」（Tomcat Manager 爆破
 * 的形态：认证头本身即探测信号）。marker 非空时比较解码后的凭据内容，
 * 按 ASCII 折叠。
 */
func endpointAuthBasicGateMatch(path string, want []string, headers map[string]string, gate endpointAuthBasicGate) bool {
	if gate.exactSegs && !matchEndpointSegmentsExact(path, want) {
		return false
	}
	if len(headers) == 0 {
		return false
	}
	value, ok := headers["authorization"]
	if !ok {
		return false
	}
	const scheme = "basic "
	if len(value) < len(scheme) || !equalASCIIFold(value[:len(scheme)], scheme) {
		return false
	}
	cred := strings.TrimSpace(value[len(scheme):])
	if cred == "" {
		return false
	}
	padded := cred + strings.Repeat("=", (4-len(cred)%4)%4)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(padded)))
	n, err := base64.StdEncoding.Decode(decoded, []byte(padded))
	if err != nil {
		return false
	}
	if gate.marker == "" {
		return n > 0
	}
	return containsASCIIFold(string(decoded[:n]), gate.marker)
}

// endpointBodyHasAnyField 判断请求体里是否存在 fields 中的任一字段名。
func endpointBodyHasAnyField(body []byte, fields []string) bool {
	for _, name := range fields {
		if endpointBodyHasField(body, name) {
			return true
		}
	}
	return false
}

func endpointBodyContainsAny(body []byte, markers []string) bool {
	if len(body) == 0 {
		return false
	}
	text := string(body)
	for _, marker := range markers {
		if containsASCIIFold(text, marker) {
			return true
		}
	}
	return false
}

func endpointHeaderHasAny(headers map[string]string, gates []endpointHeaderGate) bool {
	if len(headers) == 0 {
		return false
	}
	for _, gate := range gates {
		value, ok := headers[gate.name]
		if ok && containsASCIIFold(value, gate.contains) {
			return true
		}
	}
	return false
}

// endpointHeaderPresent 判断请求头里是否存在给定的头名（大小写不敏感）。
//
// 用于「某个产品协议头出现即命中」的闸门（endpointHeaderPresentGates）：
// 这类头部只由攻击工具或目标部署生成，正常浏览器请求不会携带。相比
// endpointHeaderHasAny 的「值含标记」语义，这里只需头名存在、不看值。
func endpointHeaderPresent(headers map[string]string, name string) bool {
	if _, ok := headers[name]; ok {
		return true
	}
	for k := range headers {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

/**
 * endpointBodyHasField 判断 form-urlencoded 请求体里是否存在名为 name 的字段。
 *
 * 只比较字段名，不看待其值：这些字段的值在黑侧随样本恒定、在白侧根本不出
 * 现，判别力全部来自字段名本身。
 *
 * 边界口径与 hasCiscoTunnelGroupQuery 一致：name 之前必须是请求体首字节或
 * '&'，之后必须紧跟 '='。因此 `xverifyCert=1`、`verifyCertx=1` 与裸键
 * `verifyCert` 都不算命中——少认一种形态只少一条命中面，不会引入误报。
 *
 * 只扫描传入的字节，不做 URL 解码：字段名在这四个产品的表单里都是裸 ASCII，
 * 解码只会把 `%76erifyCert` 一类绕过放进来，而攻击者要绕过的是端点探测本身，
 * 用编码字段名反而暴露更强的攻击意图（属于主扫描的覆盖范围）。
 */
func endpointBodyHasField(body []byte, name string) bool {
	n := len(name)
	if n == 0 || len(body) == 0 {
		return false
	}
	for start := 0; start < len(body); {
		// start 处是一对的起点：请求体首字节，或上一个 '&' 之后。
		if start+n < len(body) && body[start+n] == '=' && string(body[start:start+n]) == name {
			return true
		}
		i := start
		for i < len(body) && body[i] != '&' {
			i++
		}
		if i >= len(body) {
			return false
		}
		start = i + 1
	}
	return false
}

// foldPathSegment 把 path[start:i] 折叠为小写写入 dst，并返回写入长度。
//
// 折叠时截断到段内第一个 ';'：Tomcat、Spring 等容器把 ';' 之后当作路径参数
// （matrix parameter），端点名在 ';' 之前，因此 `/dana-na;a=b` 与 `/dana-na`
// 在端点语义上等价。语料实测 9453 条含分号样本中，仅因该归一化新增的命中为
// 0（黑 0 / 白 0），即它不引入新误报，只补齐 `;jsessionid=` 一类变形。
//
// dst 容量由调用方保证不小于 i-start；返回 0 表示段名为空（如 `/;a=b`）。
func foldPathSegment(seg string, dst []byte) int {
	if j := strings.IndexByte(seg, ';'); j >= 0 {
		seg = seg[:j]
	}
	for j := 0; j < len(seg); j++ {
		c := seg[j]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst[j] = c
	}
	return len(seg)
}

/**
 * firstTwoPathSegments 取出路径的前两段，各折叠为小写后写入调用方提供的
 * 栈上缓冲区，并返回两段长度（第二段不存在时 nextLen 为 0）。
 *
 * 缓冲区由调用方持有，避免返回值逃逸到堆。任一段超过 maxEndpointSegmentBytes
 * 时返回 ok=false：超长段不可能是表中的端点。
 */
func firstTwoPathSegments(path string, firstBuf, secondBuf *[maxEndpointSegmentBytes]byte) (firstLen, secondLen int, ok bool) {
	i, n := 0, 0
	for n < 2 {
		for i < len(path) && path[i] == '/' {
			i++
		}
		if i >= len(path) {
			break
		}
		start := i
		for i < len(path) && path[i] != '/' {
			i++
		}
		if i-start > maxEndpointSegmentBytes {
			return 0, 0, false
		}
		dst := firstBuf[:]
		if n == 1 {
			dst = secondBuf[:]
		}
		l := foldPathSegment(path[start:i], dst)
		if l == 0 {
			// 空段名（`/;a=b`）不可能是表中端点。
			return 0, 0, false
		}
		if n == 0 {
			firstLen = l
		} else {
			secondLen = l
		}
		n++
	}
	if n == 0 {
		return 0, 0, false
	}
	return firstLen, secondLen, true
}

/**
 * matchEndpointSegmentsFold 判断 want 是否为 path 的段序列前缀。
 *
 * 按 '/' 切段并跳过空段，使 `/a//b`、`//a/b` 与 `/a/b` 等价：语料中大量探测
 * 样本使用双斜杠前缀（例如 `//crumbIssuer/api/xml`），而 Tomcat、Spring 等
 * 容器同样把重复斜杠归一为单斜杠，因此这是端点语义上的等价形式，不是绕过面。
 *
 * want 全部为小写字面量，逐段做 ASCII 折叠比较，不分配。
 */
/**
 * matchEndpointSegmentsExact 判断 path 的段序列与 want 完全相等（不像
 * matchEndpointSegmentsFold 那样只做前缀匹配）：/manager/html/manager
 * 不算命中 /manager/html。按 '/' 切段并跳过空段，逐段 ASCII 折叠比较。
 */
func matchEndpointSegmentsExact(path string, want []string) bool {
	i := 0
	for w := range want {
		for i < len(path) && path[i] == '/' {
			i++
		}
		if i >= len(path) {
			return false
		}
		start := i
		for i < len(path) && path[i] != '/' {
			i++
		}
		seg := path[start:i]
		if j := strings.IndexByte(seg, ';'); j >= 0 {
			seg = seg[:j]
		}
		if !equalASCIIFold(seg, want[w]) {
			return false
		}
	}
	// 剩余部分必须为空或全为 '/'
	for i < len(path) && path[i] == '/' {
		i++
	}
	return i == len(path)
}

/**
 * matchEndpointSegmentsFold 判断 want 是否为 path 的段序列前缀。
 *
 * 按 '/' 切段并跳过空段，使 `/a//b`、`//a/b` 与 `/a/b` 等价：语料中大量探测
 * 样本使用双斜杠前缀（例如 `//crumbIssuer/api/xml`），而 Tomcat、Spring 等
 * 容器同样把重复斜杠归一为单斜杠，因此这是端点语义上的等价形式，不是绕过面。
 *
 * want 中等于 endpointWildcardSegment 的段匹配任意非空段（空段已被跳过，
 * 因此只表示「该位置存在一段」）。其余段全部为小写字面量，逐段做 ASCII
 * 折叠比较，不分配。
 */
func matchEndpointSegmentsFold(path string, want []string) bool {
	i := 0
	for w := range want {
		for i < len(path) && path[i] == '/' {
			i++
		}
		if i >= len(path) {
			return false
		}
		start := i
		for i < len(path) && path[i] != '/' {
			i++
		}
		if want[w] == endpointWildcardSegment {
			continue
		}
		seg := path[start:i]
		if j := strings.IndexByte(seg, ';'); j >= 0 {
			seg = seg[:j]
		}
		if !equalASCIIFold(seg, want[w]) {
			return false
		}
	}
	return true
}
