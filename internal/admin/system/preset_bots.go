package system

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

/**
 * 预置爬虫白名单：常见搜索引擎/合规服务爬虫的公开 IP 段。
 *
 * 数据来源为各服务商公开文档（Google/Bing/Baidu/360/Yandex/Sogou/DuckDuckGo）。
 * 因各家爬虫 IP 段会不定期扩展，此处仅内置常见/长期稳定的段作为快速起点，
 * 管理员应定期通过威胁情报订阅从各家官方 URL 补充。
 */
type presetBotEntry struct {
	Value string
	Note  string
}

var presetBotEntries = []presetBotEntry{
	// Google（Googlebot）：66.249.64.0/19 是长期稳定段
	{"66.249.64.0/19", "Google Googlebot"},
	// Bing：40.77.167.0/24、207.46.13.0/24 是长期稳定段
	{"40.77.167.0/24", "Microsoft Bingbot"},
	{"207.46.13.0/24", "Microsoft Bingbot"},
	// Baidu：180.76.15.0/24 常见
	{"180.76.15.0/24", "Baidu Spider"},
	// 360Spider：42.236.10.0/24
	{"42.236.10.0/24", "360 Spider"},
	// Yandex：5.45.192.0/22
	{"5.45.192.0/22", "Yandex Bot"},
	// Sogou：123.126.68.0/24
	{"123.126.68.0/24", "Sogou Spider"},
	// DuckDuckGo：常见的 40.88.21.235/32 和 40.114.240.0/24
	{"40.114.240.0/24", "DuckDuckGo Bot"},
}

/**
 * SeedBotWhitelistResp 预置结果统计。
 */
type SeedBotWhitelistResp struct {
	Added   int      `json:"added"`
	Skipped int      `json:"skipped"`
	Entries []string `json:"entries"`
}

/**
 * SeedBotWhitelist 将预置爬虫白名单注入 IP 名单表。
 *
 * 已存在（同 value）的条目会跳过；新条目以 whitelist 全局作用域写入。
 * 管理员触发一次即可，不会重复添加。
 *
 * @param repo   IP 名单仓库。
 * @param reload snapshot 重建回调。
 * @return Hertz 处理器。
 */
func SeedBotWhitelist(repo *repository.IPListRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		resp := SeedBotWhitelistResp{}
		// 一次性拉取现有条目用于判重（预置项<20，数据面白名单数据量通常也不大）。
		existing, _, err := repo.List(0, 500, "", nil)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		existingSet := make(map[string]bool, len(existing))
		for i := range existing {
			if existing[i].Kind == store.IPListWhite {
				existingSet[existing[i].Value] = true
			}
		}
		for _, e := range presetBotEntries {
			if existingSet[e.Value] {
				resp.Skipped++
				continue
			}
			item := &store.IPListEntry{
				Kind:    store.IPListWhite,
				Value:   e.Value,
				Note:    "[预置] " + e.Note,
				Enabled: true,
				Action:  "intercept",
			}
			if err := repo.Create(item); err != nil {
				c.JSON(500, map[string]string{"error": err.Error()})
				return
			}
			resp.Added++
			resp.Entries = append(resp.Entries, e.Value)
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "seeded but reload failed: " + err.Error(), "result": resp})
			return
		}
		c.JSON(200, resp)
	}
}

/**
 * ListPresetBotWhitelist 列出预置爬虫白名单条目（不写入 DB，仅供前端预览）。
 */
func ListPresetBotWhitelist() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		type item struct {
			Value string `json:"value"`
			Note  string `json:"note"`
		}
		items := make([]item, 0, len(presetBotEntries))
		for _, e := range presetBotEntries {
			items = append(items, item{Value: e.Value, Note: e.Note})
		}
		c.JSON(200, map[string]any{"items": items, "total": len(items)})
	}
}
