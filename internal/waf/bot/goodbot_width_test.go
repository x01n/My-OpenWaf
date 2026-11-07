package bot

import (
	"net"
	"strconv"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// 良性爬虫白名单的匹配宽度：裸词必须收窄，官方 UA 形态必须仍然命中
// ─────────────────────────────────────────────────────────────────────────────

// goodBotWidthCase 逐条描述一次宽度收窄。
//
// impersonations 是「改动前命中、改动后不命中」的冒充样例，
// officials 是「改动前后都必须命中」的官方 UA 字面量。
// 前者证明收窄生效，后者证明没有修过头。
type goodBotWidthCase struct {
	// idx 是 goodBotUA 中的下标。下标是隐式契约（goodBotDNSPatterns 用它索引），
	// 收窄只允许改正则内容，不允许改下标或顺序。
	idx int
	// impersonations 是应当被拒的冒充 UA。
	impersonations []string
	// officials 是必须仍然命中的官方 UA。
	officials []string
}

// goodBotWidthCases 是本次收窄的三条模式。
//
// 收窄依据（均为厂商侧公开字面量，不是推测）：
//   - 下标 8：LinkedIn 的抓取器产品名是 LinkedInBot，裸词 linkedin 没有对应的
//     官方 UA 形态。
//   - 下标 10：Discord 官方支持文档明确「在 UA 文本中查找 Discordbot 一词」，
//     裸词 discord 没有对应的官方 UA 形态。
//   - 下标 16：Ahrefs 官方爬虫页列出的爬虫只有 AhrefsBot 与 AhrefsSiteAudit 两个，
//     裸词 ahrefs 应替换为这两个产品 token。
var goodBotWidthCases = []goodBotWidthCase{
	{
		idx: 8,
		impersonations: []string{
			"X-Linkedin-Research-Crawler/1.0",
			"linkedin-scraper/0.1",
		},
		officials: []string{
			"LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
		},
	},
	{
		idx: 10,
		impersonations: []string{
			"discord-scraper/0.1",
			"nuclei - discord:attacker",
		},
		officials: []string{
			"Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
		},
	},
	{
		idx: 16,
		impersonations: []string{
			"My-Ahrefs-Scraper/0.1",
			"ahrefs-monitor/2.0",
		},
		officials: []string{
			"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
			"Mozilla/5.0 (compatible; AhrefsSiteAudit/6.1; +http://ahrefs.com/robot/site-audit)",
			"Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
			"Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://www.majestic12.co.uk/bot.php?+)",
			"Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot; help@moz.com)",
		},
	},
}

// TestGoodBotUAWidthTightened 断言三处裸词收窄后，冒充样例不再命中白名单模式，
// 而官方 UA 字面量仍然命中。
//
// 本用例直接断言白名单正则的匹配宽度（goodBotUA[i].MatchString），不经过
// matchGoodBotUA：因为不可校验模式在 verifyGoodBotDNS 上必然返回未通过，
// 走 matchGoodBotUA 会掩盖宽度本身的变化。
func TestGoodBotUAWidthTightened(t *testing.T) {
	// 下标是隐式契约：goodBotDNSPatterns 用下标索引 goodBotUA，
	// 收窄只允许改正则内容。条目数变化必须同步复查本用例。
	if len(goodBotUA) != 17 {
		t.Fatalf("goodBotUA 条目数=%d，下标契约已变，请同步复查本用例与 goodBotDNSPatterns", len(goodBotUA))
	}

	for _, tc := range goodBotWidthCases {
		re := goodBotUA[tc.idx]
		t.Run("goodBotUA_"+strconv.Itoa(tc.idx), func(t *testing.T) {
			t.Logf("goodBotUA[%d] = %s", tc.idx, re.String())

			for _, ua := range tc.impersonations {
				if re.MatchString(ua) {
					t.Fatalf("冒充样例仍命中白名单模式 %s：UA=%q", re.String(), ua)
				}
			}
			for _, ua := range tc.officials {
				if !re.MatchString(ua) {
					t.Fatalf("官方 UA 被误拒：模式 %s 未命中 UA=%q", re.String(), ua)
				}
			}
		})
	}
}

// TestGoodBotUAUnverifiablePatternsAreDeadEntries 记录并锁定当前语义：
// 不在 goodBotDNSPatterns 里的模式，verifyGoodBotDNS 一律返回未通过，
// 因此这些条目在 matchGoodBotUA 上永远无法放行。
//
// 该分支不发起任何 DNS 查询（在查表失败时直接返回），故本用例完全离线。
func TestGoodBotUAUnverifiablePatternsAreDeadEntries(t *testing.T) {
	ip := net.ParseIP("8.8.8.8")
	dead, verifiable := 0, 0
	for i := range goodBotUA {
		if _, hasTable := goodBotDNSPatterns[i]; hasTable {
			verifiable++
			continue
		}
		dead++
		if verifyGoodBotDNS(ip, i) {
			t.Fatalf("goodBotUA[%d] 没有官方后缀表却通过校验：%s", i, goodBotUA[i].String())
		}
		t.Logf("goodBotUA[%2d] 无后缀表，条目不可放行：%s", i, goodBotUA[i].String())
	}
	if verifiable == 0 {
		t.Fatal("goodBotDNSPatterns 无任何条目，白名单已全量退化为拒绝")
	}
	t.Logf("可校验条目=%d，不可放行条目=%d", verifiable, dead)

	// 表中不得出现越界下标：越界会让 verifyGoodBotDNS 永远查不到，后续维护者
	// 误以为某条目已登记。
	for idx := range goodBotDNSPatterns {
		if idx < 0 || idx >= len(goodBotUA) {
			t.Fatalf("goodBotDNSPatterns 含越界下标 %d（goodBotUA 长度 %d）", idx, len(goodBotUA))
		}
	}
}

// TestGoodBotUAImpersonationNeverShortCircuits 是端到端回归锁：
// 冒充 UA 在任何 IP 下都不得被判为良性爬虫。
//
// 该锁针对的回归是「把 verifyGoodBotDNS 的不可校验分支改回无条件放行」——
// 一旦如此，上表的裸词与产品 token 会同时变成可绕过面，本用例立即失败。
func TestGoodBotUAImpersonationNeverShortCircuits(t *testing.T) {
	ims := []string{
		"X-Linkedin-Research-Crawler/1.0",
		"discord-scraper/0.1",
		"My-Ahrefs-Scraper/0.1",
		"sqlmap/1.7 whatsapp",
		"nuclei - discord:attacker",
	}
	ips := []net.IP{nil, net.ParseIP("203.0.113.77")}
	for _, ua := range ims {
		for _, ip := range ips {
			if _, _, ok := matchGoodBotUA(BotRequest{UserAgent: ua, ClientIP: ip}); ok {
				t.Fatalf("冒充 UA 被判良性：UA=%q IP=%v", ua, ip)
			}
		}
	}
}
