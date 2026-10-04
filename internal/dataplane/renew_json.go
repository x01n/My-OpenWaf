package dataplane

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
)

/**
 * cookieRenewJSONBody 是脚本上下文下返回的机器可读续期标记。
 *
 * 这是给**脚本**看的，不是给人看的：`fetch`/XHR 拿到 HTML 续期页会让
 * `response.json()` 抛 SyntaxError，调用方只能看到「请求失败」，无法区分
 * 「需要续期」与「真的出错」。
 *
 * 处理口径（必须让调用方知道，否则会误以为「返 JSON 就等于问题解决了」）：
 *   - 收到 {"renew":"required"} 的脚本**不能自行完成续期** —— 续期页需要在
 *     顶层导航里跑 WASM 才能落位 C2。脚本应把控制权交回页面路由层，由路由
 *     层导航一次当前 URL（GET）触发续期流程。
 *   - **若页面代码不做这个处理，本请求就是失败状态**：不是静默成功，也不会
 *     被服务端自动重试。服务端不提供「重试即通过」的语义。
 */
type cookieRenewJSONBody struct {
	Renew string `json:"renew"`
	URL   string `json:"url"`
	Hint  string `json:"hint"`
}

// renewJSONHint 是给人读的兜底说明（脚本不应解析它，只用于排查）。
const renewJSONHint = "navigate to this URL in the top-level context to complete the session renewal"

/**
 * requestWantsRenewJSON 判定「本请求是脚本发起的，应返回 JSON 而非 HTML 续期页」。
 *
 * 判据来自实测（真实 Chromium 抓头，非规范推断）：
 *
 * 	fetch/XHR            -> Sec-Fetch-Dest: empty,  Sec-Fetch-Mode: cors
 * 	表单 POST / reload   -> Sec-Fetch-Dest: document, Sec-Fetch-Mode: navigate
 *
 * 因此**只有 `Dest: empty` 或 `Mode: cors|same-origin` 才算脚本**；顶层导航
 * （`Mode: navigate`）一律走 HTML 页。注意不能只按 `Mode: navigate` 反推——POST
 * 表单提交与 `location.reload()` 重提交同样是 navigate，按 navigate 反推会让
 * POST 表单提交拿到 HTML，而页面 reload 又是 POST，形成循环。
 *
 * **缺失回退**：`Sec-Fetch-*` 是 Chromium/Firefox 系特有头，Safari 与部分
 * 爬虫不带。头缺失时一律返回 false（走现状的 HTML 页面），既不返 JSON 也不
 * 拒服务——否则老客户端会拿到它读不懂的 JSON。
 */
func requestWantsRenewJSON(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	dest := toLowerASCII(strings.TrimSpace(string(c.GetHeader("Sec-Fetch-Dest"))))
	mode := toLowerASCII(strings.TrimSpace(string(c.GetHeader("Sec-Fetch-Mode"))))
	switch dest {
	case "empty":
		return true
	case "document":
		// 顶层导航：明确不是脚本，直接判定，避免被下面的 mode 分支误判。
		return false
	}
	switch mode {
	case "cors", "same-origin":
		return true
	}
	// 含 mode 缺失、navigate、no-cors（如 <img>/<script> 子资源）等一律走 HTML。
	return false
}

/**
 * writeRenewJSON 输出 412 + 机器可读标记 + Retry-After。
 *
 * Retry-After 取 1 秒：它表达的是「稍后重试」而非「多久之后一定会好」——
 * 真正的完成条件由页面导航触发，与等待时长无关。
 */
func writeRenewJSON(c *app.RequestContext, reqID string, requestURL string) {
	if reqID != "" {
		c.Response.Header.Set("X-Request-ID", reqID)
	}
	c.Response.Header.Del("Server")
	c.Response.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	c.Response.Header.Set("X-OWAF-Probe", "renew-json")
	c.Response.Header.Set("Retry-After", "1")
	body, err := json.Marshal(cookieRenewJSONBody{
		Renew: "required",
		URL:   requestURL,
		Hint:  renewJSONHint,
	})
	if err != nil {
		c.Data(http.StatusPreconditionFailed, "application/json", []byte(`{"renew":"required"}`))
		return
	}
	c.Data(http.StatusPreconditionFailed, "application/json; charset=utf-8", body)
}
