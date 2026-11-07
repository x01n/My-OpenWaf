package rules

import (
	"net"

	"My-OpenWaf/internal/core/pipeline"
)

/**
 * matchCtxForCCRateBound 构造带站点身份的 cc_rate 匹配上下文。
 *
 * cc_rate 的计数键是 bind+siteID+规范化 Host+客户端 IP，纯零值上下文会让
 * 不同用例落进同一个桶，因此统一走 pipeline 填充路径。
 *
 * @param ip   客户端 IP 文本
 * @param path 请求路径
 * @return 匹配上下文
 */
func matchCtxForCCRateBound(ip, path string) MatchCtx {
	return ctxFromPipeline(&pipeline.RequestCtx{
		Bind:     ":80",
		SiteID:   1,
		Host:     "ccrate-bound.example",
		Path:     path,
		ClientIP: net.ParseIP(ip),
	}, false)
}
