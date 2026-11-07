package snapshot

import (
	"testing"

	"My-OpenWaf/internal/store"
)

// TestBuildHTMLToMarkdownEnabledFromBotSettings 覆盖配置层验收点：
// 全局开关从 bot_settings 的 html_to_markdown_enabled 读取，并烤进站点运行时与快照。
func TestBuildHTMLToMarkdownEnabledFromBotSettings(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	if err := db.Create(&store.Site{
		Host:         "markdown.example.test",
		Bind:         ":80",
		Network:      "tcp",
		UpstreamURLs: "http://127.0.0.1:8080",
		Enabled:      true,
	}).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}
	if err := db.Create(&store.SystemSettings{
		Key:   "bot_settings",
		Value: `{"html_to_markdown_enabled":true}`,
	}).Error; err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}

	sn, err := Build(db, 1, testDynamicKeyBase)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if !sn.HTMLToMarkdownEnabled {
		t.Fatal("snapshot must carry the global html-to-markdown switch")
	}
	rt, ok := sn.MatchSite(":80", "markdown.example.test")
	if !ok {
		t.Fatal("site was not matched")
	}
	if !rt.HTMLToMarkdownEnabled {
		t.Fatal("site runtime must carry the global html-to-markdown switch")
	}
}

// TestBuildHTMLToMarkdownDisabledByDefault 覆盖默认关闭：
// 未配置时开关为 false，既有站点行为逐字节不变。
func TestBuildHTMLToMarkdownDisabledByDefault(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	if err := db.Create(&store.Site{
		Host:         "markdown-off.example.test",
		Bind:         ":80",
		Network:      "tcp",
		UpstreamURLs: "http://127.0.0.1:8080",
		Enabled:      true,
	}).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}

	sn, err := Build(db, 1, testDynamicKeyBase)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if sn.HTMLToMarkdownEnabled {
		t.Fatal("html-to-markdown must default to disabled")
	}
	rt, _ := sn.MatchSite(":80", "markdown-off.example.test")
	if rt.HTMLToMarkdownEnabled {
		t.Fatal("site runtime must default to disabled")
	}
}

// TestBuildHTMLToMarkdownIndependentlyOfDynamicProtection 覆盖独立性：
// 该开关不依赖 dynamic_protection_enabled，主开关关闭时仍可独立生效。
func TestBuildHTMLToMarkdownIndependentlyOfDynamicProtection(t *testing.T) {
	db, _ := newSnapshotBuildDBForTest(t)
	if err := db.Create(&store.Site{
		Host:         "markdown-independent.example.test",
		Bind:         ":80",
		Network:      "tcp",
		UpstreamURLs: "http://127.0.0.1:8080",
		Enabled:      true,
	}).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}
	if err := db.Create(&store.SystemSettings{
		Key:   "bot_settings",
		Value: `{"dynamic_protection_enabled":false,"html_to_markdown_enabled":true}`,
	}).Error; err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}

	sn, err := Build(db, 1, testDynamicKeyBase)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	rt, _ := sn.MatchSite(":80", "markdown-independent.example.test")
	if !rt.HTMLToMarkdownEnabled {
		t.Fatal("html-to-markdown must not be gated by dynamic_protection_enabled")
	}
	if rt.DynamicProtection.HTMLObfuscationEnabled {
		t.Fatal("dynamic protection must stay off in this fixture")
	}
}

// TestParseHTMLToMarkdownEnabled 覆盖解析边界：空串、非法 JSON、缺字段。
func TestParseHTMLToMarkdownEnabled(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"empty", "", false},
		{"missing field", `{"dynamic_protection_enabled":true}`, false},
		{"explicit true", `{"html_to_markdown_enabled":true}`, true},
		{"explicit false", `{"html_to_markdown_enabled":false}`, false},
		{"invalid json", `{`, false},
		{"non bool", `{"html_to_markdown_enabled":"yes"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseHTMLToMarkdownEnabled(tc.raw); got != tc.want {
				t.Fatalf("parseHTMLToMarkdownEnabled(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}
