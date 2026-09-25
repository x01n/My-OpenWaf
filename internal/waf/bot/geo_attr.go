package bot

import (
	"net"
	"strings"
)

// GeoAttrResult 是单个 IP 的 GEO 属性可疑度评估结果。
// Score 已被保证在 [0, maxGeoAttrScore] 区间内，调用方可直接累加。
type GeoAttrResult struct {
	Score   int      // 0..maxGeoAttrScore，越大越可疑
	Reasons []string // 每个评分贡献的简述（按命中顺序）
}

// maxGeoAttrScore 是 IP 属性维度单次贡献的上限（总 IP 属性面 <= 20 分）。
const maxGeoAttrScore = 20

// GeoAttrPolicy 提供 GEO 属性映射的关键词集合。
// 这些是保守的公开性关键词（数据中心/托管/VPN 组织名称里常见的大类片段），
// 不在代码里写死具体 ASN 或国家列表，也不参与拦截判定——只贡献盾验分数。
type GeoAttrPolicy struct {
	DataCenterKeywords []string // 数据中心/云 ASN 组织关键词（12 分档）
	VPNProxyKeywords   []string // VPN/代理 ASN 组织关键词（8 分档）
	HostingKeywords    []string // 服务器/托管 ASN 组织关键词（5 分档）
}

// DefaultGeoAttrPolicy 返回保守的 GEO 属性映射关键词表。
// 只收录语义明确的大类词，刻意避开 "llc/ltd/limited/inc" 这类通用公司后缀，
// 避免把任何有限公司都打成数据中心。
func DefaultGeoAttrPolicy() GeoAttrPolicy {
	return GeoAttrPolicy{
		DataCenterKeywords: []string{
			"datacenter", "data-center", "colo", "colocation", "dedicated server",
			"dedicated hosting", "bare metal", "vps", "virtual private server",
			"server hosting", "hosting services", "hosting solutions", "cloud hosting",
		},
		VPNProxyKeywords: []string{
			"vpn", "proxy", "privacy network", "anonymizer", "anonymity",
			"backconnect", "residential proxy", "mobile proxy",
		},
		HostingKeywords: []string{
			"hosting", "host", "cloud", "server", "servers", "digitalocean",
			"vultr", "linode", "ovh", "hetzner", "scaleway", "upcloud",
		},
	}
}

// ScoreGeoAttr 对 GeoInfo 应用 GEO 属性映射并返回可疑度。纯函数、无状态。
func ScoreGeoAttr(info GeoInfo) GeoAttrResult {
	return scoreGeoAttrWithPolicy(info, DefaultGeoAttrPolicy())
}

// LookupGeoAttr 解析 IP 的 GEO 属性并按默认策略评分。
// globalGeo 未装配或查询失败时返回零分（属性信息不全时代价 0）。
func LookupGeoAttr(ip net.IP) GeoAttrResult {
	if ip == nil {
		return GeoAttrResult{}
	}
	return scoreGeoAttrWithPolicy(LookupGeo(ip), DefaultGeoAttrPolicy())
}

func scoreGeoAttrWithPolicy(info GeoInfo, policy GeoAttrPolicy) GeoAttrResult {
	org := strings.ToLower(info.ASNOrg)
	if org == "" {
		return GeoAttrResult{}
	}
	if hitAny(org, policy.DataCenterKeywords) {
		return GeoAttrResult{Score: 12, Reasons: []string{"geoip: datacenter-like ASN organization (+12)"}}
	}
	if hitAny(org, policy.VPNProxyKeywords) {
		return GeoAttrResult{Score: 8, Reasons: []string{"geoip: vpn/proxy-like ASN organization (+8)"}}
	}
	if hitAny(org, policy.HostingKeywords) {
		return GeoAttrResult{Score: 5, Reasons: []string{"geoip: hosting-like ASN organization (+5)"}}
	}
	return GeoAttrResult{}
}

func hitAny(org string, keywords []string) bool {
	for _, kw := range keywords {
		if kw == "" || len(kw) < 3 {
			continue
		}
		if strings.Contains(org, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}
