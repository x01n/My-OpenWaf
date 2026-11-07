package proxy

import (
	"context"
	"net"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/imagery"
	"My-OpenWaf/internal/snapshot"
)

// 图像转换参数在查询串中的参数名（ESA 同名）。
const imageProcessQueryKey = "image_process"

// imageTransformPlan 描述单次请求要执行的图像转换。
//
// 之所以单独成结构而不是直接塞进 entity，是因为它需要同时携带「协商结果」
// （是否由 Accept 触发转 WebP）——该结果既影响编码输出，也影响 Vary 与缓存键。
type imageTransformPlan struct {
	// opts 是解析后的转换参数（已含自适应协商后的最终格式）。
	opts imagery.Options
	// adaptiveWebP 表示最终格式是「由 Accept 协商得来」而非 URL 显式指定。
	//
	// 只有它为真时才需要 Vary: Accept——显式 format,webp 的响应与 Accept 无关，
	// 声明 Vary 只会无谓地把响应排除出共享缓存。
	adaptiveWebP bool
}

// imageTransformPlanFor 依据请求与站点配置决定是否执行图像转换。
//
// 触发条件（全部满足才返回非 nil）：
//
//  1. 站点配置 ImageTransform.Enabled；
//  2. 请求带有 image_process 查询参数且解析成功；或启用了自适应 WebP
//     且客户端 Accept 含 image/webp。
//
// 解析失败（含参数注入与越界值）返回 nil，即原图直通——与 ESA
// 「任意参数值为非法时不做任何处理」的口径一致。
//
// @param rt 站点运行时。
// @param c Hertz 请求上下文。
// @return 转换计划；不适用时为 nil。
func imageTransformPlanFor(rt snapshot.SiteRuntime, c *app.RequestContext) *imageTransformPlan {
	cfg := rt.ImageTransform
	if !cfg.Enabled || c == nil {
		return nil
	}

	raw := imageProcessValue(c)
	opts, err := imagery.Parse(raw)
	if err != nil {
		return nil
	}

	if opts.IsZero() {
		// 没有显式参数时，仅自适应 WebP 可能生效。
		if !cfg.AdaptiveWebP || !imagery.AcceptsWebP(string(c.GetHeader("Accept"))) {
			return nil
		}
		opts.Format = imagery.FormatWebP
		return &imageTransformPlan{opts: opts, adaptiveWebP: true}
	}

	plan := &imageTransformPlan{opts: opts}
	// 显式指定了 webp 时无需再协商；其余情况由 Accept 决定是否改写到 WebP。
	if cfg.AdaptiveWebP && opts.Format != imagery.FormatWebP && imagery.AcceptsWebP(string(c.GetHeader("Accept"))) {
		plan.opts.Format = imagery.FormatWebP
		plan.adaptiveWebP = true
	}
	return plan
}

// imageProcessValue 取出 image_process 查询参数的原始值。
//
// 只取同名参数中的第一个：ESA 语义是单值参数，重复出现时以首个为准，
// 不做拼接（拼接会让「重复参数」成为一种绕过解析白名单的手段）。
//
// @param c Hertz 请求上下文。
// @return 参数值；不存在时为空串。
func imageProcessValue(c *app.RequestContext) string {
	args := c.URI().QueryArgs()
	if args == nil {
		return ""
	}
	if !args.Has(imageProcessQueryKey) {
		return ""
	}
	return string(args.Peek(imageProcessQueryKey))
}

// imageContentTypeUpper 判断内容类型是否属于可转换的图片类型。
//
// 可接受的范围比 dynamic 的 ShouldProcessContentType 更宽：除了 png/jpeg/gif
// 之外还包含 webp/bmp/tiff（转换能力本身就支持这些输入）。
//
// @param contentType 内容类型。
// @return 可转换时为 true。
func imageContentTypeUpper(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp", "image/bmp", "image/x-ms-bmp", "image/tiff":
		return true
	default:
		return false
	}
}

// applyImageTransform 执行图像转换，并把结果写回实体。
//
// 返回的实体在未发生变换时原样返回；发生变换时更新 Body、ContentType，
// 并在由 Accept 协商得到格式时置 VaryAccept（响应需声明 Vary: Accept）。
//
// @param ctx 请求上下文。
// @param entity 响应实体。
// @param rt 站点运行时。
// @param c Hertz 请求上下文。
// @return 变换后的实体。
func applyImageTransform(ctx context.Context, entity identityResponseEntity, rt snapshot.SiteRuntime, c *app.RequestContext) identityResponseEntity {
	if !imageContentTypeUpper(entity.ContentType) {
		return entity
	}
	plan := imageTransformPlanFor(rt, c)
	if plan == nil {
		return entity
	}

	cfg := rt.ImageTransform
	opts := plan.opts
	if opts.Quality == 0 && cfg.DefaultQuality > 0 {
		opts.Quality = cfg.DefaultQuality
	}

	res := imagery.TransformGuarded(ctx, entity.Body, entity.ContentType, opts, watermarkTextFor(rt), cfg.DecodeLimits(), cfg.Timeout())
	if !res.Changed {
		return entity
	}

	entity.Body = res.Body
	entity.ContentType = res.ContentType
	// 自适应格式的响应与 Accept 相关，必须声明 Vary: Accept；否则中间缓存
	// 会把 WebP 版本回放给不支持 WebP 的客户端。显式指定 format,webp 时
	// 结果与 Accept 无关，不需要 Vary。
	//
	// 注意本层只声明 Vary，不改动缓存策略：图像产物仍沿用响应变换路径既有
	// 的 Cache-Control 处理，不额外延长 TTL。原因是水印文案来自站点配置，
	// 配置变更后中间缓存里的旧水印图会在 TTL 内继续可见；给转换产物设定
	// 独立的缓存生命周期需要先有按配置修订号失效的能力，本轮不做。
	if plan.adaptiveWebP {
		entity.VaryAccept = true
	}
	// 标记该实体由图像转换产生，供调用方（Vary 判定与测试）识别。
	entity.ImageVariant = true
	return entity
}

// watermarkTextFor 取站点配置的水印文案。
//
// @param rt 站点运行时。
// @return 水印文案；未配置时为空串（由 imagery 回退到 "Protected"）。
func watermarkTextFor(rt snapshot.SiteRuntime) string {
	return rt.DynamicProtection.WatermarkText
}

// appendVaryAccept 在响应上追加 Vary: Accept，避免重复追加。
//
// @param c Hertz 请求上下文。
func appendVaryAccept(c *app.RequestContext) {
	if c == nil {
		return
	}
	vary := string(c.Response.Header.Peek("Vary"))
	for _, item := range strings.Split(vary, ",") {
		if strings.EqualFold(strings.TrimSpace(item), "Accept") {
			return
		}
	}
	if vary == "" {
		c.Response.Header.Set("Vary", "Accept")
		return
	}
	c.Response.Header.Set("Vary", vary+", Accept")
}

// 编译期断言：protocol 与 net 包被引用（查询参数与客户端 IP 类型）。
var (
	_ = protocol.Args{}
	_ net.IP
)
