package owasp

import "testing"

/**
 * absolute-form 判据锁（owasp:proto:011）。
 *
 * 形态来源：数据面 FixURIConn（internal/dataplane/inbound_conn.go）对请求行
 * 第二 token 不以 '/' 或 '*' 开头的请求在 method 后插入一个 '/'，因此
 * 「GET http://host/path HTTP/1.1」到达 WAF 时 path == "/http://host/path"。
 * 全语料 140572 条按 .white/.black 标签实测：
 *   - 命中 "/http[s]://" 前缀：黑 2040 / 白 0；
 *   - 白侧唯一相近样本 "/https://:@oast.me%5C@oast.me" 以 ":@"（userinfo 空）
 *     开头，不属于 absolute-form 请求行，origin-form 的路径本来就可能是这个
 *     字面形态，因此判据要求 scheme:// 之后第一个字符不是 ':'，将其排除。
 */

func TestHasAbsoluteFormRequestTarget(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"http absolute", "/http://gfs270n447.userstorage.mega.co.nz/dl/abc/0-0", true},
		{"https absolute", "/https://query.cleaning/v4/headers.php", true},
		{"http absolute root", "/http://111.170.7.47:80", true},
		{"https absolute with port", "/http://supstandards.com:80/feed/", true},
		{"uppercase scheme", "/HTTP://EXAMPLE.TEST/x", true},
		{"mixed case scheme", "/HtTpS://example.test/x", true},
		{"percent space in host", "/http://%20sandycable.co.uk:80/player_api.php", true},
		{"origin form normal", "/normal/path/x.php", false},
		{"origin form root", "/", false},
		{"scheme-relative keeps double slash", "//http://example.test", false},
		{"https path prefix only", "/https-containing-word", false},
		{"http word not scheme", "/http:/not-a-scheme", false},
		{"triple slash", "///etc/passwd", false},
		{"empty", "", false},
		{"short", "/http://", false},
		{"query only", "/?a=1", false},
		{"userinfo colon is not absolute form", "/https://:@oast.me%5C@oast.me", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasAbsoluteFormRequestTarget(tc.path); got != tc.want {
				t.Fatalf("hasAbsoluteFormRequestTarget(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestProto011EmitsThroughFirstOWASPHit 锁定发射点在主扫描函数内生效：
// 构造 absolute-form 路径时 FirstOWASPHitWithThresholds 必须返回 proto:011，
// origin-form 同路径不得返回。
func TestProto011EmitsThroughFirstOWASPHit(t *testing.T) {
	th := CompileThresholds("low")
	abs := "/http://query.cleaning/v4/headers.php"
	hit, ok := FirstOWASPHitWithThresholds(th, abs, "", nil, nil)
	if !ok {
		t.Fatalf("absolute-form path %q 未产生命中", abs)
	}
	if hit.RuleID != "owasp:proto:011" {
		t.Fatalf("RuleID = %q, want owasp:proto:011", hit.RuleID)
	}
	if hit.Category != CatProtoViol {
		t.Fatalf("Category = %q, want %q", hit.Category, CatProtoViol)
	}
	// origin-form 同路径不命中。
	origin := "/v4/headers.php"
	if h, ok := FirstOWASPHitWithThresholds(th, origin, "", nil, nil); ok {
		t.Fatalf("origin-form path %q 不应命中，得到 %+v", origin, h)
	}
}

// TestProto011ExcludesUserinfoColon 锁定白侧唯一同形样本的排除条件：
// scheme:// 后紧跟 ':'（空 userinfo）不是 absolute-form。
func TestProto011ExcludesUserinfoColon(t *testing.T) {
	th := CompileThresholds("low")
	p := "/https://:@oast.me%5C@oast.me"
	if hasAbsoluteFormRequestTarget(p) {
		t.Fatalf("%q 不应判为 absolute-form", p)
	}
	if _, ok := FirstOWASPHitWithThresholds(th, p, "", nil, nil); ok {
		t.Fatalf("白侧同形样本 %q 不应产生命中", p)
	}
}

// TestProto011RespectsCategoryDisabled 锁定类别关闭时不发射：
// protocol_violation 类别整体关闭（off）时判据不参与判定。
func TestProto011RespectsCategoryDisabled(t *testing.T) {
	th := CompileThresholds("low", map[string]string{"protocol_violation": "off"})
	abs := "/http://query.cleaning/v4/headers.php"
	if h, ok := FirstOWASPHitWithThresholds(th, abs, "", nil, nil); ok {
		t.Fatalf("类别关闭时不应命中，得到 %+v", h)
	}
}
