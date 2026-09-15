package owasp

import (
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// BuiltinRuleDefinitions returns the complete metadata inventory for every stable RuleID emitted by the detector.
func BuiltinRuleDefinitions() []store.OWASPRuleCatalog {
	definitions := make(map[string]store.OWASPRuleCatalog)
	for _, rule := range DefaultOWASPRegistry.All() {
		definitions[rule.ID] = store.OWASPRuleCatalog{
			RuleID: rule.ID, Category: rule.Category, Name: rule.Name, Description: rule.Description,
			DefaultEnabled: rule.Enabled, DefaultAction: "intercept", BuiltinVersion: "1", Active: true,
		}
	}
	add := func(ruleID, category, name, description string) {
		if _, exists := definitions[ruleID]; exists {
			return
		}
		definitions[ruleID] = store.OWASPRuleCatalog{
			RuleID: ruleID, Category: category, Name: name, Description: description,
			DefaultEnabled: true, DefaultAction: "intercept", BuiltinVersion: "1", Active: true,
		}
	}
	add("owasp:upload:001", string(CatFileUpload), "上传文件名空字节", "检测文件名或路径中的空字节截断；风险分值 6")
	add("owasp:upload:002", string(CatFileUpload), "上传双扩展名", "检测可执行扩展名后追加伪装扩展名；风险分值 5")
	add("owasp:upload:003", string(CatFileUpload), "危险文件扩展名", "检测 PHP、JSP、ASP 等服务端可执行文件扩展名；风险分值 5")
	add("owasp:upload:004", string(CatFileUpload), "htaccess 覆写上传", "检测 .htaccess 覆写尝试；风险分值 5")
	add("owasp:upload:005", string(CatFileUpload), "图片 Content-Type 不匹配", "检测图片扩展名与声明 Content-Type 不一致；风险分值 3")
	add("owasp:upload:006", string(CatFileUpload), "上传文件名路径穿越", "检测上传文件名中的 ../ 或反斜杠路径穿越；风险分值 6")
	add("owasp:upload:007", string(CatFileUpload), "可执行文件伪装图片", "检测可执行扩展名配合 image/* Content-Type 的绕过；风险分值 5")

	add("owasp:proto:001", string(CatProtoViol), "CL/TE 请求走私", "检测 Content-Length 与 chunked Transfer-Encoding 冲突；风险分值 6")
	add("owasp:proto:002", string(CatProtoViol), "重复 Content-Length", "检测多个 Content-Length 值；风险分值 5")
	add("owasp:proto:003", string(CatProtoViol), "超长请求头", "检测单个请求头名称和值超过协议安全边界；风险分值 4")
	add("owasp:proto:004", string(CatProtoViol), "TRACE/TRACK 方法", "检测 TRACE 或 TRACK 危险 HTTP 方法；风险分值 5")
	add("owasp:proto:005", string(CatProtoViol), "CONNECT 隧道方法", "检测 CONNECT 隧道请求；风险分值 5")
	add("owasp:proto:006", string(CatProtoViol), "DEBUG 诊断方法", "检测 ASP.NET DEBUG 诊断方法；风险分值 5")
	add("owasp:proto:007", string(CatProtoViol), "WebDAV 方法", "检测 PROPFIND、PROPPATCH、MKCOL、COPY、MOVE、LOCK、UNLOCK；风险分值 4")
	add("owasp:proto:008", string(CatProtoViol), "PATCH 非常用方法", "检测需要显式评估的 PATCH 请求；风险分值 3")
	add("owasp:proto:009", string(CatProtoViol), "非 CORS OPTIONS", "检测缺少 Origin 或 Access-Control-Request-Method 的 OPTIONS 请求；风险分值 3")
	add("owasp:proto:010", string(CatProtoViol), "不透明编码请求体", "检测无 Content-Type 的高风险不透明编码请求体；风险分值 5")

	pathRules := []struct {
		id, category, name, description string
	}{
		{"owasp:path:001", string(CatCmdInject), "F5 BIG-IP RCE 端点", "检测 F5 BIG-IP 管理命令执行端点；风险分值 6"},
		{"owasp:path:002", string(CatDeserial), "Liferay JSONWS 反序列化", "检测 Liferay JSONWS invoke 反序列化端点；风险分值 6"},
		{"owasp:path:004", string(CatDeserial), "Apache OFBiz WebTools RCE", "检测 Apache OFBiz XML-RPC/SOAP 远程代码执行端点；风险分值 6"},
		{"owasp:path:005", string(CatExprLang), "Confluence OGNL 注入", "检测 Confluence TinyMCE 宏预览 OGNL 注入端点；风险分值 6"},
		{"owasp:path:006", string(CatPathTrav), "Cisco ASA 路径穿越", "检测 +CSCOE+ / +CSCOT+ 路径穿越；风险分值 5"},
		{"owasp:path:007", string(CatWebshell), "ThinkPHP invokefunction RCE", "检测 ThinkPHP invokefunction 远程代码执行端点；风险分值 6"},
		{"owasp:path:008", string(CatSSRF), "Atlassian Gadgets SSRF", "检测 /gadgets/makeRequest 服务端请求伪造端点；风险分值 5"},
		{"owasp:path:009", string(CatCmdInject), "Nexus CoreUI RCE", "检测 Nexus Repository Manager CoreUI 远程代码执行端点；风险分值 5"},
		{"owasp:path:010", string(CatPathTrav), "Coremail 配置泄露", "检测 Coremail /mailsms/ 配置泄露路径；风险分值 5"},
		{"owasp:path:011", string(CatPathTrav), ".git 目录访问", "检测暴露的 .git 版本控制目录；风险分值 5"},
		{"owasp:path:012", string(CatCmdInject), "Jenkins Script Security RCE", "检测 Jenkins SecurityRealm descriptor 远程代码执行端点；风险分值 5"},
		{"owasp:path:013", string(CatXXE), "OFS XXE 端点", "检测 OFS XML 外部实体相关端点；风险分值 5"},
		{"owasp:path:014", string(CatPathTrav), "分号路径参数绕过", "检测 Swagger、Actuator、Admin、Console、Manager 的分号路径绕过；风险分值 5"},
		{"owasp:path:015", string(CatPathTrav), "Joomla API 配置泄露", "检测 Joomla v1 config API 信息泄露路径及 Cisco translation-table 变体；风险分值 5"},
		{"owasp:path:016", string(CatCmdInject), "Nexus Repository API", "检测 Nexus Repository Manager 高风险仓库 API 路径；风险分值 5"},
		{"owasp:path:017", string(CatCmdInject), "ExtDirect RCE 端点", "检测 /service/extdirect 远程代码执行端点；风险分值 5"},
	}
	for _, rule := range pathRules {
		add(rule.id, rule.category, rule.name, rule.description)
	}
	add("owasp:deser:012", string(CatDeserial), "URL 编码 Java 序列化魔数", "检测 URL 编码或十六进制形式的 AC ED 00 05 Java 序列化魔数；风险分值 5")
	add("owasp:crlf:005", string(CatCRLF), "URL 路径裸 CR/LF", "检测 URL 路径中的裸回车或换行字符；风险分值 5")

	items := make([]store.OWASPRuleCatalog, 0, len(definitions))
	for _, item := range definitions {
		items = append(items, item)
	}
	return items
}

// ReconcileBuiltinCatalog upserts current metadata and retires definitions no longer emitted by this build.
func ReconcileBuiltinCatalog(db *gorm.DB) error {
	definitions := BuiltinRuleDefinitions()
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&store.OWASPRuleCatalog{}).Where("active = ?", true).Update("active", false).Error; err != nil {
			return err
		}
		for i := range definitions {
			item := definitions[i]
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "rule_id"}},
				DoUpdates: clause.AssignmentColumns([]string{"category", "name", "description", "default_enabled", "default_action", "default_sensitivity", "builtin_version", "active", "updated_at"}),
			}).Create(&item).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
