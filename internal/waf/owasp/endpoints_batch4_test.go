package owasp

import "testing"

/**
 * TestSensitiveEndpointBatch4Rules 锁定 192-203 这批端点规则的命中形态。
 *
 * 收录口径：全语料 140572 条按 endpoints.go 的真实段匹配语义重算，白侧任一
 * 请求命中 0；黑侧数字是 r91 基线上仍漏报（fn）的首请求样本数。每条规则给出
 * 一条正向用例（黑侧真实形态），反例放在 TestSensitiveEndpointBatch4Rejects。
 */
func TestSensitiveEndpointBatch4Rules(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		body   string
		wantID string
	}{
		{
			name:   "192 elementor 版本文件",
			path:   "/wp-content/plugins/elementor/readme.txt",
			method: "GET",
			wantID: "owasp:endpoint:192",
		},
		{
			name:   "193 hash-form 版本文件",
			path:   "/wp-content/plugins/hash-form/readme.txt",
			method: "GET",
			wantID: "owasp:endpoint:193",
		},
		{
			name:   "194 wp-statistics 版本文件",
			path:   "/wp-content/plugins/wp-statistics/readme.txt",
			method: "GET",
			wantID: "owasp:endpoint:194",
		},
		{
			name:   "195 backup-heart 代码注入",
			path:   "/wp-content/plugins/backup-backup/includes/backup-heart.php",
			method: "POST",
			wantID: "owasp:endpoint:195",
		},
		{
			name:   "196 sniplets 文件包含",
			path:   "/wp-content/plugins/sniplets/modules/syntax_highlight.php",
			method: "GET",
			wantID: "owasp:endpoint:196",
		},
		{
			name:   "197 ebook-download 文件下载",
			path:   "/wp-content/plugins/ebook-download/filedownload.php",
			method: "GET",
			wantID: "owasp:endpoint:197",
		},
		{
			name:   "198 w3-total-cache SNS 注入",
			path:   "/wp-content/plugins/w3-total-cache/pub/sns.php",
			method: "PUT",
			wantID: "owasp:endpoint:198",
		},
		{
			name:   "199 simple-file-list 文件下载",
			path:   "/wp-content/plugins/simple-file-list/includes/ee-downloader.php",
			method: "GET",
			wantID: "owasp:endpoint:199",
		},
		{
			name:   "200 adaptive-images 文件包含",
			path:   "/wp-content/plugins/adaptive-images/adaptive-images-script.php",
			method: "GET",
			wantID: "owasp:endpoint:200",
		},
		{
			name:   "201 import-xml-feed 落地脚本",
			path:   "/wp-content/plugins/import-xml-feed/uploads/169227090864de013cac47b.php",
			method: "GET",
			wantID: "owasp:endpoint:201",
		},
		{
			name:   "202 Docker exec v1.24",
			path:   "/v1.24/containers/nm7mkp5zpi0s/exec",
			method: "POST",
			body:   `{"AttachStderr":false,"AttachStdout":false,"Cmd":["sh","-c","echo x"]}`,
			wantID: "owasp:endpoint:202",
		},
		{
			name:   "202 Docker exec v1.29",
			path:   "/v1.29/containers/abc123/exec",
			method: "POST",
			body:   `{"Cmd":["id"]}`,
			wantID: "owasp:endpoint:202",
		},
		{
			name:   "203 vCenter SDK SOAP",
			path:   "/sdk",
			method: "POST",
			body:   `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>`,
			wantID: "owasp:endpoint:203",
		},
	}
	for _, tc := range cases {
		hit, ok := CheckSensitiveEndpointPathWithBody(tc.path, tc.method, []byte(tc.body))
		if !ok {
			t.Errorf("%s: (%q, %q) 未命中，期望 %s", tc.name, tc.path, tc.method, tc.wantID)
			continue
		}
		if hit.RuleID != tc.wantID {
			t.Errorf("%s: 命中规则 = %q，期望 %q", tc.name, hit.RuleID, tc.wantID)
		}
		if hit.Score <= 0 || hit.Desc == "" {
			t.Errorf("%s: 命中缺少分值或说明: %+v", tc.name, hit)
		}
	}
}

/**
 * TestSensitiveEndpointBatch4Rejects 覆盖每条新规则的近似路径反例：
 * 段边界不成立、末端被替换、方法不符、闸门不满足。
 *
 * 这些形态直接取自白侧语料与相邻端点——例如 192-194 的白侧代价来自
 * wp-planet、woocommerce-* 等真实站点自带插件，把它们写成通配会让这些
 * 正常请求变成误报，因此逐条锁死。
 */
func TestSensitiveEndpointBatch4Rejects(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		body   string
	}{
		// 192-194：插件名与文件名都必须是表内字面量。
		{"192 白侧真实插件", "/wp-content/plugins/wp-planet/readme.txt", "GET", ""},
		{"192 插件名后缀近似", "/wp-content/plugins/elementor-pro/readme.txt", "GET", ""},
		{"192 文件名近似", "/wp-content/plugins/elementor/readme.md", "GET", ""},
		{"193 插件名近似", "/wp-content/plugins/hash-forms/readme.txt", "GET", ""},
		{"194 插件名近似", "/wp-content/plugins/wp-statistic/readme.txt", "GET", ""},
		// 195：方法约束与末端文件名。
		{"195 方法不符", "/wp-content/plugins/backup-backup/includes/backup-heart.php", "GET", ""},
		{"195 末端近似", "/wp-content/plugins/backup-backup/includes/backup-heart.php.bak", "GET", ""},
		// 196-197、199-200：白侧同端点的方法与正常路径。
		{"196 白侧 HEAD 探测", "/wp-content/plugins/sniplets/modules/syntax_highlight.php", "HEAD", ""},
		{"196 插件 readme 不命中", "/wp-content/plugins/sniplets/readme.txt", "GET", ""},
		{"197 方法不符", "/wp-content/plugins/ebook-download/filedownload.php", "POST", ""},
		{"197 目录近似", "/wp-content/plugins/ebook-download/readme.txt", "GET", ""},
		// 198：PUT 是调用约定，POST 不算。
		{"198 方法不符", "/wp-content/plugins/w3-total-cache/pub/sns.php", "POST", ""},
		{"198 白侧 lib 路径", "/wp-content/plugins/w3-total-cache/lib/aws/aws/api/parser", "GET", ""},
		{"199 末端近似", "/wp-content/plugins/simple-file-list/includes/ee-upload-engine.php", "GET", ""},
		{"200 插件名近似", "/wp-content/plugins/adaptive-image/adaptive-images-script.php", "GET", ""},
		// 201：目录前缀只到 uploads，插件自身的其它目录不命中。
		{"201 插件根路径", "/wp-content/plugins/import-xml-feed/readme.txt", "GET", ""},
		{"201 方法不符", "/wp-content/plugins/import-xml-feed/uploads/x.php", "POST", ""},
		// 202：末段必须是 exec，body 必须带 Cmd 键。
		{"202 白侧 restart", "/v1.24/containers/os0wab5zzh1p/restart", "POST", ""},
		{"202 白侧 start", "/v1.24/containers/os0wab5zzh1p/start", "POST", ""},
		{"202 白侧 kill", "/v1.24/containers/os0wab5zzh1p/kill", "POST", ""},
		{"202 白侧 attach", "/v1.24/containers/os0wab5zzh1p/attach", "POST", ""},
		{"202 白侧 HEAD exec", "/v1.24/containers/uj1tcj6zbj2k/exec", "HEAD", ""},
		{"202 缺少 Cmd 标记", "/v1.24/containers/abc123/exec", "POST", `{"Detach":true}`},
		{"202 段数不足", "/v1.24/containers/exec", "POST", `{"Cmd":["id"]}`},
		{"202 次段不是 containers", "/v1.24/volumes/abc123/exec", "POST", `{"Cmd":["id"]}`},
		// 203：白侧 gSOAP 客户端用 SOAP-ENV: 前缀。
		{"203 白侧 vimService", "/sdk/vimService", "POST", `<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body/></SOAP-ENV:Envelope>`},
		{"203 方法不符", "/sdk", "GET", ""},
		{"203 无 SOAP 信封", "/sdk", "POST", `<language>x</language>`},
	}
	for _, tc := range cases {
		if hit, ok := CheckSensitiveEndpointPathWithBody(tc.path, tc.method, []byte(tc.body)); ok {
			t.Errorf("%s: (%q, %q) 误命中 %s", tc.name, tc.path, tc.method, hit.RuleID)
		}
	}
}

/**
 * TestSensitiveEndpointBatch4WildcardSegment 锁定通配哨兵的匹配语义：
 * 只匹配「恰好一段且非空」，不跨段、不匹配空段（重复斜杠在切段时已跳过）。
 */
func TestSensitiveEndpointBatch4WildcardSegment(t *testing.T) {
	want := []string{endpointWildcardSegment, "containers", endpointWildcardSegment, "exec"}
	positives := []string{
		"/v1.24/containers/abc/exec",
		"/v1.29/containers/a/exec",
		"/V1.24/Containers/ABC/EXEC",
		"//v1.24//containers//abc//exec",
		"/v1.24/containers/abc;jsessionid=1/exec",
		"/v1.24/containers/abc/exec/",
		"/v1.24/containers/abc/exec/json",
		// 通配段匹配任意非空段，包括字面量 exec 本身。
		"/v1.24/containers/exec/exec",
	}
	for _, path := range positives {
		if !matchEndpointSegmentsFold(path, want) {
			t.Errorf("matchEndpointSegmentsFold(%q) 应命中通配段序列", path)
		}
	}
	negatives := []string{
		// 段数不足：无版本前缀的 /containers/<id>/exec 是三段，不在本规则内。
		"/containers/abc/exec",
		"/v1.24/containers/exec",
		"/v1.24/containers/a/b/exec",
		"/v1.24/volume/abc/exec",
		"/v1.24/containers/abc/execs",
	}
	for _, path := range negatives {
		if matchEndpointSegmentsFold(path, want) {
			t.Errorf("matchEndpointSegmentsFold(%q) 误命中通配段序列", path)
		}
	}
}

/**
 * TestSensitiveEndpointBatch4WildcardIndexIsolation 校验首段通配规则不进
 * 「首段+次段」两级索引：否则 map 里会出现 "*" 这个不可能来自真实路径的键，
 * 那部分规则将永远无法被该索引命中。
 */
func TestSensitiveEndpointBatch4WildcardIndexIsolation(t *testing.T) {
	if _, exists := endpointRulesByFirstTwoSegments[endpointWildcardSegment]; exists {
		t.Errorf("首段通配键 %q 不得出现在两级索引中", endpointWildcardSegment)
	}
	found := false
	for _, entry := range endpointWildcardRules {
		if sensitiveEndpointRules[entry.index].id == "owasp:endpoint:202" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("202 未登记在首段通配索引中，实际 %v", endpointWildcardRules)
	}
	// 通配索引只能收首段为哨兵的规则，否则会在热路径重复判定同一条规则。
	for _, entry := range endpointWildcardRules {
		if segs := sensitiveEndpointRules[entry.index].segs; segs[0] != endpointWildcardSegment {
			t.Errorf("%s 的首段 %q 不是通配哨兵，不应进通配索引", sensitiveEndpointRules[entry.index].id, segs[0])
		}
		// 预计算的次段必须与规则表一致，否则短路会误杀候选。
		got := ""
		if len(sensitiveEndpointRules[entry.index].segs) > 1 {
			got = sensitiveEndpointRules[entry.index].segs[1]
		}
		if entry.second != got {
			t.Errorf("%s: 索引次段 %q 与规则表 %q 不一致", sensitiveEndpointRules[entry.index].id, entry.second, got)
		}
	}
}

/**
 * TestSensitiveEndpointBatch4NoSideEffects 校验新规则不改变既有端点的命中归属：
 * 009 的「容器名恰为 bash」形态必须仍报 009，不能被 202 抢走。
 */
func TestSensitiveEndpointBatch4NoSideEffects(t *testing.T) {
	hit, ok := CheckSensitiveEndpointPathWithBody(
		"/v1.24/containers/bash/exec", "POST", []byte(`{"Cmd":["id"]}`))
	if !ok {
		t.Fatal("/v1.24/containers/bash/exec 应命中既有规则 009")
	}
	if hit.RuleID != "owasp:endpoint:009" {
		t.Errorf("命中规则 = %q，期望 owasp:endpoint:009", hit.RuleID)
	}
	// 008（containers/create）同样不应被 202 影响：末段不是 exec。
	hit, ok = CheckSensitiveEndpointPathWithBody(
		"/v1.24/containers/create", "POST", []byte(`{"Cmd":["id"]}`))
	if !ok || hit.RuleID != "owasp:endpoint:008" {
		t.Errorf("/v1.24/containers/create 期望 008，实际 ok=%v id=%q", ok, hit.RuleID)
	}
}
