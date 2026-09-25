package bot

import (
	"net"
	"strings"
	"testing"
)

func TestScoreGeoAttrFourTiers(t *testing.T) {
	orgString := func(who string) GeoInfo {
		return GeoInfo{ASNOrg: who}
	}
	cases := []struct {
		name     string
		info     GeoInfo
		wantMin  int // 最低期望
		wantZero bool
	}{
		{"datacenter org", orgString("DigitalOcean, LLC datacenter"), 12, false},
		{"vpn org", orgString("M247 Ltd proxy network"), 8, false},
		{"hosting org", orgString("OVH Hosting Inc."), 5, false},
		{"empty org zero", orgString(""), 0, true},
		{"unremarkable org", orgString("Example Org"), 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := scoreGeoAttrWithPolicy(tc.info, DefaultGeoAttrPolicy())
			if tc.wantZero && res.Score != 0 {
				t.Fatalf("want zero, got %+v", res)
			}
			if !tc.wantZero && res.Score < tc.wantMin {
				t.Fatalf("want >= %d, got %+v", tc.wantMin, res)
			}
			if res.Score > maxGeoAttrScore {
				t.Fatalf("score %d over max %d", res.Score, maxGeoAttrScore)
			}
			for _, r := range res.Reasons {
				if !strings.HasPrefix(r, "geoip:") && !strings.Contains(r, "+") {
					t.Fatalf("reason should announce geoip contribution: %q", r)
				}
			}
		})
	}
}

/**
 * TestScoreGeoAttrPrecedence 验证互斥分档的优先级，不是叠加。
 */
func TestScoreGeoAttrPrecedence(t *testing.T) {
	both := GeoInfo{ASNOrg: "Vultr Holdings LLC"}
	gotVultr := ScoreGeoAttr(both)
	if gotVultr.Score < 5 {
		t.Fatalf("vultr should hit at least hosting tier: %+v", gotVultr)
	}
	res := scoreGeoAttrWithPolicy(GeoInfo{ASNOrg: "DigitalOcean datacenter vpn proxy hosting"}, DefaultGeoAttrPolicy())
	if res.Score != 12 && res.Score != 8 && res.Score != 5 && res.Score != 0 {
		t.Fatalf("unexpected precedence score: %+v", res)
	}
}

/**
 * TestLookupGeoAttrNoResolverZeroCost 验证 globalGeo 未装配或 IP 为 nil 时代价 0。
 */
func TestLookupGeoAttrNoResolverZeroCost(t *testing.T) {
	if res := LookupGeoAttr(nil); res.Score != 0 {
		t.Fatalf("nil IP must be zero cost: %+v", res)
	}
	_ = net.ParseIP
	// 无 resolver 时 LookupGeo 返回空 GeoInfo，评分必须为 0。
	if res := LookupGeoAttr(net.ParseIP("8.8.8.8")); res.Score != 0 {
		t.Fatalf("no-resolver lookup must be zero cost: %+v", res)
	}
}
