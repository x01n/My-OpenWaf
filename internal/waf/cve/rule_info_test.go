package cve

import "testing"

// TestCustomRuleMatchCarriesSourceAndSeverity 守护 CVE 事件的"来源与危险度"
// 链路：数据库规则行（cve_rules）的 Source/CVSSScore/CWEType/References 必须
// 出现在命中结果上，命中部位与匹配片段同样不能丢。
func TestCustomRuleMatchCarriesSourceAndSeverity(t *testing.T) {
	d := NewCVEDetector()
	d.ReloadCustomRules([]CustomCVERule{{
		CVEID: "CVE-2099-0003", Category: "cve_java", Pattern: `(?i)rule_info_marker`,
		Target: "url", Severity: "high", Action: "", Enabled: true,
		Description: "来源与危险度测试规则", Source: "nvd",
		CVSSScore: 8.1, CWEType: "CWE-502",
		References: "https://example.invalid/CVE-2099-0003",
	}})

	req := CVERequest{}
	BuildCVERequestInto(&req, "/x", "q=$where=rule_info_marker", map[string]string{}, nil, "")
	matches := d.Detect(&req, nil)
	if len(matches) == 0 {
		t.Fatal("no match")
	}
	var found bool
	for _, m := range matches {
		if m.CVEID != "CVE-2099-0003" {
			continue
		}
		found = true
		if m.Source != "nvd" || m.CVSSScore != 8.1 || m.CWEType != "CWE-502" || m.References == "" {
			t.Errorf("来源/危险度未透传: %+v", m)
		}
		if m.MatchedPart != "url" {
			t.Errorf("命中部位 = %q, want url", m.MatchedPart)
		}
		if m.Snippet == "" {
			t.Errorf("匹配片段为空: %+v", m)
		}
	}
	if !found {
		t.Fatalf("自定义规则未命中: %+v", matches)
	}
}

// TestRegistryRuleMatchTaggedBuiltin 守护注册表规则的来源标记：内置注册表
// 规则没有 cve_rules 数据库行，来源固定为 builtin；危险度取自规则定义，
// 因此必须非空。
//
// 注册表规则的检测正则封闭在各自 CheckFunc 内，命中结果无法回溯目标串，
// 因此 Snippet 预期为空——这是有意为之，不是缺陷。
func TestRegistryRuleMatchTaggedBuiltin(t *testing.T) {
	shellshockUA := "() { :;}; /bin/bash -c 'echo pwned'"
	matches := globalCVERuleRegistry.DetectAll("/cgi-bin/x", "", shellshockUA, nil)
	if len(matches) == 0 {
		t.Fatal("expected a registry match for the shellshock user agent")
	}
	var found bool
	for _, m := range matches {
		if m.Source != "builtin" {
			t.Errorf("registry rule source = %q, want builtin", m.Source)
		}
		if m.Severity == "" {
			t.Errorf("registry rule severity empty: %+v", m)
		}
		if m.CVEID == "CVE-2014-6271" {
			found = true
		}
	}
	if !found {
		t.Fatalf("shellshock rule not matched: %+v", matches)
	}
}
