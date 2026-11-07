package owasp

import (
	"strings"
	"testing"
)

/**
 * TestSensitiveEndpointCorpusBatchRules 锁定 166-174 这批「全语料任一请求
 * 口径白侧 0」判据的命中形态。判据数字均来自全语料 140572 条的复扫：
 *
 *	166	server/load.php  + type=stb	黑 712 / 白 0
 *	167	portal.php       + type=stb	黑 208 / 白 0
 *	168	api/user/reg     + "email"	黑 272 / 白 0
 *	169	xmlrpc.php       + system.	黑 109 / 白 0
 *	170	bot/statistic    POST		黑 80 / 白 0
 *	171	images/vos3000.ico		黑 74 / 白 0
 *	172	onvif-http/snapshot + auth=admin:	黑 122 / 白 0
 *	173	manager/html     + Basic	黑 90 / 白 0
 *	174	verm + Basic(SELECT)		黑 565 / 白 0
 */
func TestSensitiveEndpointCorpusBatchRules(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		method  string
		query   string
		headers map[string]string
		body    string
		wantID  string
	}{
		{
			name:   "166 Ministra 中间件握手",
			path:   "/server/load.php",
			query:  "type=stb&action=handshake&token=9BDYSKXL",
			method: "GET",
			wantID: "owasp:endpoint:166",
		},
		{
			name:   "166 参数大小写折叠",
			path:   "/server/load.php",
			query:  "Type=stb",
			method: "GET",
			wantID: "owasp:endpoint:166",
		},
		{
			name:   "167 Ministra 门户握手",
			path:   "/portal.php",
			query:  "type=stb&action=get_profile",
			method: "GET",
			wantID: "owasp:endpoint:167",
		},
		{
			name:   "168 批量注册 JSON",
			path:   "/api/user/reg",
			method: "POST",
			body:   `{"email":"x@interact.sh","password":"p","username":"u"}`,
			wantID: "owasp:endpoint:168",
		},
		{
			name:   "169 XML-RPC 枚举",
			path:   "/xmlrpc.php",
			method: "POST",
			body:   `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>`,
			wantID: "owasp:endpoint:169",
		},
		{
			name:   "170 僵尸网络回传",
			path:   "/bot/statistic",
			method: "POST",
			body:   "_=YWUlKlc1UWpJaz5EOG4yTw==",
			wantID: "owasp:endpoint:170",
		},
		{
			name:   "171 VOS3000 指纹图标",
			path:   "/images/vos3000.ico",
			method: "GET",
			wantID: "owasp:endpoint:171",
		},
		{
			name:   "172 ONVIF 弱凭据",
			path:   "/onvif-http/snapshot",
			query:  "auth=YWRtaW46MTEK",
			method: "GET",
			wantID: "owasp:endpoint:172",
		},
		{
			name:   "173 Tomcat Manager 爆破",
			path:   "/manager/html",
			method: "GET",
			headers: map[string]string{
				"authorization": "Basic YWRtaW46dG9tY2F0MTIz",
			},
			wantID: "owasp:endpoint:173",
		},
		{
			name:   "174 VERM SQL 注入",
			path:   "/VERM/VERM_AJAX_functions.php",
			query:  "function=log_custom_report&KZZRA=K6QRQ",
			method: "GET",
			headers: map[string]string{
				"authorization": "Basic Z29vbGlja2VyJywgJycsIChTRUxFQ1QgKE5VTEwpKSk7IyA6cGFzc3dvcmQ=",
			},
			wantID: "owasp:endpoint:174",
		},
	}
	for _, tc := range cases {
		hit, ok := CheckSensitiveEndpointPathWithRequest(tc.path, tc.method, tc.query, tc.headers, []byte(tc.body))
		if !ok {
			t.Errorf("%s: 应命中 %s", tc.name, tc.wantID)
			continue
		}
		if hit.RuleID != tc.wantID {
			t.Errorf("%s: 命中 %s，期望 %s", tc.name, hit.RuleID, tc.wantID)
		}
		if hit.Score <= 0 || hit.Desc == "" {
			t.Errorf("%s: 命中缺少分值或说明: %+v", tc.name, hit)
		}
	}
}

/**
 * TestSensitiveEndpointCorpusBatchRulesReject 锁定闸门不成立时不得命中的
 * 形态。全部对应全语料白侧实测：
 *
 *   - 166/167 白侧同端点的 type=account_info / type=itv（机顶盒门户正常
 *     接口查询）；
 *   - 168 GET 无请求体；
 *   - 169 白侧 POST 为 wp.newTerm 表单，不带 system.*；
 *   - 170 GET 空体；
 *   - 172 白侧 auth=ywrtaw46mtek 解码不出 admin:；
 *   - 173 白侧同路径无 Authorization 头；
 *   - 174 白侧同端点无 Authorization 头。
 */
func TestSensitiveEndpointCorpusBatchRulesReject(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		method  string
		query   string
		headers map[string]string
		body    string
	}{
		{
			name:   "166 白侧账号信息查询",
			path:   "/server/load.php",
			query:  "type=account_info&action=get_main_info&JsHttpRequest=1-xml",
			method: "GET",
		},
		{
			name:   "166 值不匹配",
			path:   "/server/load.php",
			query:  "type=stbx",
			method: "GET",
		},
		{
			name:   "166 参数名前缀不成立",
			path:   "/server/load.php",
			query:  "xtype=stb",
			method: "GET",
		},
		{
			name:   "167 白侧 itv 取链",
			path:   "/portal.php",
			query:  "type=itv&action=create_link",
			method: "GET",
		},
		{
			name:   "168 GET 无请求体",
			path:   "/api/user/reg",
			method: "GET",
			body:   `{"email":"x@x"}`,
		},
		{
			name:   "168 非注册表单",
			path:   "/api/user/reg",
			method: "POST",
			body:   `{"foo":1}`,
		},
		{
			name:   "169 白侧 wp.newTerm",
			path:   "/xmlrpc.php",
			method: "POST",
			body:   `<?xml version='1.0'?><methodCall><methodName>wp.newTerm</methodName></methodCall>`,
		},
		{
			name:   "169 GET 不带体",
			path:   "/xmlrpc.php",
			method: "GET",
			query:  "rsd",
		},
		{
			name:   "170 GET 空体",
			path:   "/bot/statistic",
			method: "GET",
		},
		{
			name:   "172 白侧坏 base64",
			path:   "/onvif-http/snapshot",
			query:  "auth=ywrtaw46mtek",
			method: "GET",
		},
		{
			name:   "172 无 auth 参数",
			path:   "/onvif-http/snapshot",
			method: "GET",
		},
		{
			name:   "172 凭据非 admin",
			path:   "/onvif-http/snapshot",
			query:  "auth=" + b64("root:11"),
			method: "GET",
		},
		{
			name:   "173 白侧无认证头",
			path:   "/manager/html",
			method: "GET",
		},
		{
			name:   "173 非 Basic 认证",
			path:   "/manager/html",
			method: "GET",
			headers: map[string]string{
				"authorization": "Bearer eyJhbGciOi",
			},
		},
		{
			name:   "174 白侧无认证头",
			path:   "/verm/verm_ajax_functions.php",
			query:  "function=log_custom_report&lb401=1jbjx",
			method: "GET",
		},
		{
			name:   "174 凭据无注入载荷",
			path:   "/VERM/VERM_AJAX_functions.php",
			method: "GET",
			headers: map[string]string{
				"authorization": "Basic " + b64("admin:admin"),
			},
		},
	}
	for _, tc := range cases {
		if hit, ok := CheckSensitiveEndpointPathWithRequest(tc.path, tc.method, tc.query, tc.headers, []byte(tc.body)); ok {
			t.Errorf("%s: 不得命中，实际命中 %s", tc.name, hit.RuleID)
		}
	}
}

/**
 * TestSensitiveEndpointCorpusBatchLegacyEntry 锁定旧入口与新入口的边界：
 * 带查询串闸门的规则（166/167/172）与带请求体闸门的规则（168/169）在旧
 * 入口上（无 query、无 body）恒不命中；无闸门的规则（170/171）两条入口
 * 行为一致。该用例只调用本批之前就存在的公开入口，在旧代码上可编译且
 * 必然断言失败（旧代码没有这批规则）。
 */
func TestSensitiveEndpointCorpusBatchLegacyEntry(t *testing.T) {
	// 旧入口既无 query 也无 body：带任一闸门的规则必须不命中。
	for _, tc := range []struct{ path, method string }{
		{"/server/load.php", "GET"},
		{"/portal.php", "GET"},
		{"/onvif-http/snapshot", "GET"},
		{"/api/user/reg", "POST"},
		{"/xmlrpc.php", "POST"},
	} {
		if hit, ok := CheckSensitiveEndpointPath(tc.path, tc.method); ok {
			t.Errorf("旧入口（无 query/body）%q 不得命中，实际命中 %s", tc.path, hit.RuleID)
		}
	}
	// 带请求体闸门的规则：新入口带上对应标记后必须命中。
	for _, tc := range []struct{ path, body, wantID string }{
		{"/api/user/reg", `{"email":"x","username":"y"}`, "owasp:endpoint:168"},
		{"/xmlrpc.php", "<system.listMethods>", "owasp:endpoint:169"},
	} {
		hit, ok := CheckSensitiveEndpointPathWithHeaders(tc.path, "POST", nil, []byte(tc.body))
		if !ok || hit.RuleID != tc.wantID {
			t.Errorf("%q 期望新入口命中 %s，实际 ok=%v id=%q", tc.path, tc.wantID, ok, hit.RuleID)
		}
	}
	// 无闸门的规则：两条入口行为一致。
	for _, tc := range []struct {
		path, method, wantID string
	}{
		{"/bot/statistic", "POST", "owasp:endpoint:170"},
		{"/images/vos3000.ico", "GET", "owasp:endpoint:171"},
	} {
		a, aok := CheckSensitiveEndpointPath(tc.path, tc.method)
		b, bok := CheckSensitiveEndpointPathWithHeaders(tc.path, tc.method, nil, nil)
		if aok != bok || (aok && a.RuleID != b.RuleID) {
			t.Errorf("%q 两条入口行为不一致: legacy=(%v,%v) withHeaders=(%v,%v)", tc.path, aok, a, bok, b)
		}
		if !aok || a.RuleID != tc.wantID {
			t.Errorf("%q 期望命中 %s，实际 %v/%v", tc.path, tc.wantID, aok, a.RuleID)
		}
	}
}

/**
 * TestSensitiveEndpointCorpusBatchGateRegistries 锁定本批闸门表的完整性：
 * 键必须落在规则表内，参数名小写，Basic 闸门标记小写。
 */
func TestSensitiveEndpointCorpusBatchGateRegistries(t *testing.T) {
	known := make(map[string]bool, len(sensitiveEndpointRules))
	for i := range sensitiveEndpointRules {
		known[sensitiveEndpointRules[i].id] = true
	}
	for ruleID, gate := range endpointQueryGates {
		if !known[ruleID] {
			t.Errorf("查询串闸门键 %q 不在 sensitiveEndpointRules 中", ruleID)
		}
		if gate.param == "" || gate.param != strings.ToLower(gate.param) {
			t.Errorf("%s: 查询串闸门参数名 %q 必须是非空小写字面量", ruleID, gate.param)
		}
		if gate.b64Prefix == "" && gate.eqValue == "" {
			t.Errorf("%s: 查询串闸门缺少判值", ruleID)
		}
		if gate.b64Prefix != "" && gate.eqValue != "" {
			t.Errorf("%s: 查询串闸门同时设置两种判值", ruleID)
		}
		if gate.b64Prefix != "" && gate.b64Prefix != strings.ToLower(gate.b64Prefix) {
			t.Errorf("%s: b64 前缀 %q 必须是小写字面量", ruleID, gate.b64Prefix)
		}
	}
	for ruleID, gate := range endpointAuthBasicGates {
		if !known[ruleID] {
			t.Errorf("Basic 凭据闸门键 %q 不在 sensitiveEndpointRules 中", ruleID)
		}
		if gate.marker != strings.ToLower(gate.marker) {
			t.Errorf("%s: Basic 凭据标记 %q 必须是小写字面量", ruleID, gate.marker)
		}
	}
}

/**
 * TestEndpointQueryGateMatch 与 TestEndpointAuthBasicGateMatch 锁定两个
 * 新闸门匹配器的边界口径。
 */
func TestEndpointQueryGateMatch(t *testing.T) {
	gate := endpointQueryGate{param: "type", eqValue: "stb"}
	positives := []string{"type=stb", "Type=stb", "action=x&type=stb&y=z", "a=1&type=stb"}
	for _, q := range positives {
		if !endpointQueryGateMatch(q, gate) {
			t.Errorf("endpointQueryGateMatch(%q) 应命中", q)
		}
	}
	negatives := []string{"", "type=account_info", "xtype=stb", "typex=stb", "type", "type=STB"}
	for _, q := range negatives {
		if endpointQueryGateMatch(q, gate) {
			t.Errorf("endpointQueryGateMatch(%q) 不得命中", q)
		}
	}
	og := endpointQueryGate{param: "auth", b64Prefix: "admin:"}
	if !endpointQueryGateMatch("auth=YWRtaW46MTEK", og) {
		t.Error("ONVIF admin:11 编码应命中")
	}
	if endpointQueryGateMatch("auth=ywrtaw46mtek", og) {
		t.Error("白侧坏 base64 不得命中")
	}
}

func TestEndpointAuthBasicGateMatch(t *testing.T) {
	any := endpointAuthBasicGate{}
	if !endpointAuthBasicGateMatch("/manager/html", []string{"manager", "html"}, map[string]string{"authorization": "Basic YWRtaW46YWRtaW4="}, any) {
		t.Error("存在 Basic 凭据即应命中空标记闸门")
	}
	if endpointAuthBasicGateMatch("/manager/html", []string{"manager", "html"}, map[string]string{"authorization": "Basic "}, any) {
		t.Error("空凭据不得命中")
	}
	if endpointAuthBasicGateMatch("/manager/html", []string{"manager", "html"}, map[string]string{"authorization": "Bearer x"}, any) {
		t.Error("非 Basic 认证不得命中")
	}
	if endpointAuthBasicGateMatch("/manager/html", []string{"manager", "html"}, nil, any) {
		t.Error("无请求头不得命中")
	}
	// exactSegs 闸门：第三段 /manager/html/manager 不得命中 /manager/html
	exact := endpointAuthBasicGate{marker: "", exactSegs: true}
	if !endpointAuthBasicGateMatch("/manager/html", []string{"manager", "html"}, map[string]string{"authorization": "Basic YWRtaW46YWRtaW4="}, exact) {
		t.Error("精确两段应命中")
	}
	if endpointAuthBasicGateMatch("/manager/html/manager", []string{"manager", "html"}, map[string]string{"authorization": "Basic YWRtaW46YWRtaW4="}, exact) {
		t.Error("/manager/html/manager 不得命中精确两段闸门")
	}
	if !endpointAuthBasicGateMatch("/manager/html/", []string{"manager", "html"}, map[string]string{"authorization": "Basic YWRtaW46YWRtaW4="}, exact) {
		t.Error("尾部斜杠仍是精确两段")
	}
	sel := endpointAuthBasicGate{marker: "select"}
	verm := "Basic Z29vbGlja2VyJywgJycsIChTRUxFQ1QgKE5VTEwpKSk7IyA6cGFzc3dvcmQ="
	if !endpointAuthBasicGateMatch("/VERM/VERM_AJAX_functions.php", []string{"verm", "verm_ajax_functions.php"}, map[string]string{"authorization": verm}, sel) {
		t.Error("goolicker SELECT 载荷应命中")
	}
	if endpointAuthBasicGateMatch("/VERM/VERM_AJAX_functions.php", []string{"verm", "verm_ajax_functions.php"}, map[string]string{"authorization": "Basic " + b64("admin:admin")}, sel) {
		t.Error("普通凭据不得命中 select 标记")
	}
}

// b64 是测试辅助：标准 base64 编码（测试表内联可读性优先）。
func b64(s string) string {
	const std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	data := []byte(s)
	for i := 0; i < len(data); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], data[i:])
		v := uint32(chunk[0])<<16 | uint32(chunk[1])<<8 | uint32(chunk[2])
		out = append(out, std[v>>18&0x3f], std[v>>12&0x3f])
		if n > 1 {
			out = append(out, std[v>>6&0x3f])
		} else {
			out = append(out, '=')
		}
		if n > 2 {
			out = append(out, std[v&0x3f])
		} else {
			out = append(out, '=')
		}
	}
	return string(out)
}
