package proxy

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"

	htmltomarkdown "github.com/JohannesKaufmann/html-to-markdown/v2/converter"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/base"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/commonmark"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/strikethrough"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/table"
	"github.com/cloudwego/hertz/pkg/app"
	"golang.org/x/net/html"

	"My-OpenWaf/internal/snapshot"
)

/**
 * HTML → Markdown 响应协商（Accept: text/markdown）。
 *
 * 只处理「客户端显式索取 Markdown」这一种情形，不做通配符回退：全通配符与
 * 类型通配符只表示「任何表示都可以接受」，与项目既有 clientAcceptsHTML 的口径
 * 一致（internal/dataplane/handler.go），不足以据此改写响应形态。
 *
 * 命中协商的响应短路跳过动态保护与脚本改写链：Markdown 输出不携带脚本，
 * HTML 混淆无的放矢；把密文交给主动索取结构化文本的客户端既是功能缺陷，
 * 也不产生任何防护收益。
 */

// MarkdownContentType 是转换成功后的响应 Content-Type。
//
// 显式带 charset：Markdown 是文本，客户端按 UTF-8 解码是既定预期。
const MarkdownContentType = "text/markdown; charset=utf-8"

// markdownMediaType 是 Accept 协商使用的媒体类型（不含参数）。
const markdownMediaType = "text/markdown"

// htmlToMarkdownConverter 是进程级共享的转换器。
//
// 官方 README 明确 Converter 可从多个 goroutine 并发调用（内部有互斥保护，
// 且有并发测试验证），因此建单例复用，不按请求构造——插件注册与校验有成本。
//
// 必须显式注册 4 个插件，不能用 htmltomarkdown.ConvertString 便利函数：便利
// 函数内部只装 base + commonmark，实测会把 <table> 压平成裸文本（GFM 表格、
// <del>、行尾双空格都依赖 strikethrough 与 table 插件）。
var htmlToMarkdownConverter = htmltomarkdown.NewConverter(htmltomarkdown.WithPlugins(
	base.NewBasePlugin(),
	commonmark.NewCommonmarkPlugin(),
	strikethrough.NewStrikethroughPlugin(),
	table.NewTablePlugin(),
))

// htmlToMarkdownConvert 是实际执行转换的函数。
//
// 抽成变量而非直接调用，是为了让测试能注入失败路径——转换契约要求「任何错误
// 都必须原样直通 HTML」，该分支必须被真实覆盖。
var htmlToMarkdownConvert = convertHTMLToMarkdown

/**
 * convertHTMLToMarkdown 尽力而为地把 HTML 转换为 Markdown。
 * @param page 上游响应体。
 * @return Markdown 字节串与解析错误；仅标准转换出错时返回 error。
 */
func convertHTMLToMarkdown(page []byte) ([]byte, error) {
	md, err := htmlToMarkdownConverter.ConvertReader(bytes.NewReader(page))
	if err != nil {
		return nil, err
	}

	meta := extractPageMetadata(page)

	if strings.TrimSpace(string(md)) == "" {
		// SPA 外壳页：正文为空，用元数据兜底。
		return renderMetadataMarkdown(meta), nil
	}

	// 正文非空：title 未被转换器带出来时前置为 H1。
	if meta.Title != "" && !strings.Contains(string(md), meta.Title) {
		md = append([]byte("# "+meta.Title+"\n\n"), md...)
	}
	return md, nil
}

/**
 * pageMetadata 是从 <head> 与页面资源中提取的元数据。
 *
 * 独立于 html-to-markdown：转换器主动剥离的元素（title/meta/script/link/
 * noscript），在这里被当作"尽力而为"的素材重新收集。
 */
type pageMetadata struct {
	Title       string
	Description string
	Keywords    string
	NoScript    string   // noscript 内容的 Markdown
	Resources   []string // script src / link rel:href，按文档顺序
}

/**
 * extractPageMetadata 解析原始 HTML，提取 title、meta 与资源引用。
 *
 * x/net/html 的解析器容错极强（对标浏览器），畸形标记不会报错，最坏情况是
 * 某项提取不到——符合尽力而为语义。
 */
func extractPageMetadata(page []byte) pageMetadata {
	root, err := html.Parse(bytes.NewReader(page))
	if err != nil {
		return pageMetadata{}
	}
	var meta pageMetadata
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "title":
				if meta.Title == "" && n.FirstChild != nil {
					meta.Title = strings.TrimSpace(n.FirstChild.Data)
				}
			case "meta":
				switch strings.ToLower(nodeAttr(n, "name")) {
				case "description":
					meta.Description = strings.TrimSpace(nodeAttr(n, "content"))
				case "keywords":
					meta.Keywords = strings.TrimSpace(nodeAttr(n, "content"))
				}
			case "script":
				if src := nodeAttr(n, "src"); src != "" {
					meta.Resources = append(meta.Resources, "script: "+src)
				}
			case "link":
				if href := nodeAttr(n, "href"); href != "" {
					rel := nodeAttr(n, "rel")
					if rel == "" {
						rel = "link"
					}
					meta.Resources = append(meta.Resources, rel+": "+href)
				}
			case "noscript":
				// noscript 在启用 JS 的浏览器里不渲染，但 Markdown 客户端
				// 恰恰"没有 JS"，其内容对它们就是正文。
				var inner bytes.Buffer
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if err := html.Render(&inner, c); err != nil {
						continue
					}
				}
				if converted, err := htmlToMarkdownConverter.ConvertReader(&inner); err == nil {
					meta.NoScript = strings.TrimSpace(string(converted))
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return meta
}

// nodeAttr 读取元素节点的属性值，缺失返回空串。
func nodeAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

/**
 * renderMetadataMarkdown 把元数据拼装为可读的结构化摘要。
 *
 * 仅提取到内容时才输出对应小节，避免空标题污染输出。
 */
func renderMetadataMarkdown(m pageMetadata) []byte {
	var b strings.Builder
	if m.Title != "" {
		fmt.Fprintf(&b, "# %s\n\n", m.Title)
	}
	if m.Description != "" {
		fmt.Fprintf(&b, "%s\n\n", m.Description)
	}
	if m.Keywords != "" {
		fmt.Fprintf(&b, "- Keywords: %s\n\n", m.Keywords)
	}
	if m.NoScript != "" {
		fmt.Fprintf(&b, "%s\n\n", m.NoScript)
	}
	if len(m.Resources) > 0 {
		b.WriteString("## Page Resources\n\n")
		for _, r := range m.Resources {
			fmt.Fprintf(&b, "- `%s`\n", r)
		}
	}
	return []byte(b.String())
}

/**
 * acceptMediaTypes 是 Accept 头的解析结果：显式列出的媒体类型及其 q 值。
 *
 * 与 Accept-Encoding 的 acceptEncodingScores 不同，这里不能按固定字段存储——
 * Accept 的取值范围是开放的。q 值解析内核复用 compression.go 的
 * acceptEncodingQParamBytes，不重复实现。
 */
type acceptMediaTypes struct {
	// exact 是精确媒体类型（如 "text/markdown"）到 q 值的映射，键已小写。
	exact map[string]float64
	// typeWildcard 是主类型通配（如 "text/*"）到 q 值的映射，键为小写主类型。
	typeWildcard map[string]float64
	// wildcard 是 "*/*" 的 q 值，仅在 hasWildcard 为真时有意义。
	wildcard    float64
	hasWildcard bool
}

/**
 * parseAcceptMediaTypes 解析 Accept 头为媒体类型与 q 值的集合。
 *
 * 格式遵循 RFC 7231 §5.3.2：以逗号分隔的 `type/subtype`，可带 `;q=` 参数。
 * 同一类型重复出现时后者覆盖前者（与 parseAcceptEncodingScoresBytes 一致）。
 *
 * @param raw Accept 头原始字节。
 * @return 解析结果；空头返回零值，其 q 查询恒为 0。
 */
func parseAcceptMediaTypes(raw []byte) acceptMediaTypes {
	var m acceptMediaTypes
	raw = trimASCIIHeaderSpaceBytes(raw)
	for len(raw) > 0 {
		token := raw
		if comma := bytes.IndexByte(raw, ','); comma >= 0 {
			token = raw[:comma]
			raw = raw[comma+1:]
		} else {
			raw = nil
		}
		part := trimASCIIHeaderSpaceBytes(token)
		if len(part) == 0 {
			continue
		}
		name := part
		q := 1.0
		if semi := bytes.IndexByte(part, ';'); semi >= 0 {
			name = trimASCIIHeaderSpaceBytes(part[:semi])
			q = acceptEncodingQParamBytes(part[semi+1:])
		}
		m.set(name, q)
	}
	return m
}

// set 记录一个媒体类型的 q 值，按精确类型 / 主类型通配 / 全通配分档存放。
func (m *acceptMediaTypes) set(name []byte, q float64) {
	media := strings.ToLower(string(trimASCIIHeaderSpaceBytes(name)))
	if media == "" {
		return
	}
	if media == "*/*" {
		m.wildcard = q
		m.hasWildcard = true
		return
	}
	if slash := strings.IndexByte(media, '/'); slash >= 0 && media[slash+1:] == "*" {
		if m.typeWildcard == nil {
			m.typeWildcard = make(map[string]float64, 2)
		}
		m.typeWildcard[media[:slash]] = q
		return
	}
	if m.exact == nil {
		m.exact = make(map[string]float64, 4)
	}
	m.exact[media] = q
}

/**
 * q 按 RFC 7231 §5.3.2 的优先级解析媒体类型的可接受度。
 *
 * 精确匹配优先于类型通配，类型通配优先于全通配；无任何匹配项时返回 0。
 * 因此显式 `text/markdown;q=0` 配合全通配得到 0——更具体的显式拒绝压过通配符。
 *
 * @param mediaType 待查询的媒体类型（小写、不含参数）。
 * @return 匹配到的 q 值；无匹配返回 0。
 */
func (m acceptMediaTypes) q(mediaType string) float64 {
	if q, ok := m.exact[mediaType]; ok {
		return q
	}
	if slash := strings.IndexByte(mediaType, '/'); slash >= 0 {
		if q, ok := m.typeWildcard[mediaType[:slash]]; ok {
			return q
		}
	}
	if m.hasWildcard {
		return m.wildcard
	}
	return 0
}

/**
 * explicitlyAccepts 判断 Accept 是否显式列出并接受某媒体类型。
 *
 * 通配符一律不计入——与 dataplane.clientAcceptsHTML 的既有口径一致：全通配符
 * 表示「任何类型都接受」，不代表客户端真的要这一种表示。
 *
 * @param mediaType 待查询的媒体类型（小写、不含参数）。
 * @return 显式列出且 q > 0 时返回 true。
 */
func (m acceptMediaTypes) explicitlyAccepts(mediaType string) bool {
	q, ok := m.exact[mediaType]
	return ok && q > 0
}

// isMarkdownContentType 判断响应 Content-Type 是否为 text/markdown（忽略参数）。
func isMarkdownContentType(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct == "text/markdown"
}

// htmlToMarkdownTransformer 把 HTML 响应体转换为 Markdown。
type htmlToMarkdownTransformer struct{}

/**
 * Transform 在响应为 HTML 时把 body 转换为 Markdown 并改写 Content-Type。
 *
 * 失败一律原样直通：返回 error 会让调用方走 writeResponseTransformFailure 并
 * 回 502，而客户端此时要的是降级后的 HTML，不是网关错误。非 HTML 响应
 * （JSON、图片等）不做任何处理。
 *
 * 空转换结果不算失败：SPA 外壳页（正文靠 <script> 注入，body 只有空挂载点）
 * 剥离脚本后标准转换为空，但 convertHTMLToMarkdown 的尽力而为层会用元数据
 * 兜底产出结构化摘要。这里只对真实错误回退 HTML。
 *
 * @param entity 身份响应实体。
 * @return 转换后的实体；出错时返回原实体且不报错。
 */
func (t htmlToMarkdownTransformer) Transform(entity identityResponseEntity) (identityResponseEntity, error) {
	if len(entity.Body) == 0 || !isHTMLContentType(entity.ContentType) {
		return entity, nil
	}
	converted, err := htmlToMarkdownConvert(entity.Body)
	if err != nil {
		slog.Warn("html to markdown conversion failed, serving original html",
			slog.String("path", entity.Path),
			slog.String("content_type", entity.ContentType),
			slog.Int("body_bytes", len(entity.Body)),
			slog.Any("error", err),
		)
		return entity, nil
	}
	if len(converted) == 0 {
		// 空结果同样直通 HTML。元数据兜底并不保证非空：既无正文、又无
		// title/meta/noscript/资源引用的页面（纯空挂载点的 SPA 外壳）走完
		// convertHTMLToMarkdown 仍是零字节，此时改写 Content-Type 会把响应
		// 换成一个空体，比不转换更糟。
		return entity, nil
	}
	entity.Body = converted
	entity.ContentType = MarkdownContentType
	return entity, nil
}

/**
 * htmlToMarkdownTransformerFor 在站点启用该能力且客户端显式协商时返回转换器。
 *
 * 这是整条响应变换链的短路分支：命中时不再参与 dynamic 混淆、browser sign
 * 注入与 JS/Lua 响应改写。判定只依赖全局开关与 Accept，与站点策略无关——
 * 这是「客户端要不要」的协商，不是「站点要不要」的策略。
 *
 * @param c Hertz 请求上下文。
 * @param rt 站点运行时（开关在构建期从全局设置烤入）。
 * @return 命中的转换器；未命中返回 nil。
 */
func htmlToMarkdownTransformerFor(c *app.RequestContext, rt snapshot.SiteRuntime) identityResponseTransformer {
	if c == nil || !rt.HTMLToMarkdownEnabled {
		return nil
	}
	if !parseAcceptMediaTypes(c.GetHeader("Accept")).explicitlyAccepts(markdownMediaType) {
		return nil
	}
	return htmlToMarkdownTransformer{}
}

/**
 * applyResponseVariantHeaders 按变换后的表示设置缓存变体头。
 *
 * Markdown 是客户端按 Accept 协商选出的表示，变体维度是 Accept。不能走
 * markDynamicResponseVariant：那会把变体错标成 Cookie，并用 no-store 让响应
 * 完全不可缓存，而 HTML→Markdown 是确定性 CPU 变换，没有理由牺牲缓存。
 *
 * @param c Hertz 请求上下文。
 * @param entity 变换后的响应实体。
 */
func applyResponseVariantHeaders(c *app.RequestContext, entity identityResponseEntity) {
	if entity.ImageVariant {
		if entity.VaryAccept {
			ensureVaryAccept(c)
		}
		return
	}
	if isMarkdownContentType(entity.ContentType) {
		ensureVaryAccept(c)
		return
	}
	markDynamicResponseVariant(c)
}

/**
 * ensureVaryAccept 幂等地向 Vary 头追加 Accept。
 *
 * 写法对齐 compression.go 的 ensureVaryAcceptEncoding：同一 URL 因 Accept 而
 * 产生不同表示时，必须声明该维度，否则共享缓存会串表示。
 *
 * @param c Hertz 请求上下文。
 */
func ensureVaryAccept(c *app.RequestContext) {
	if c == nil {
		return
	}
	current := c.Response.Header.Peek("Vary")
	if len(current) == 0 {
		c.Response.Header.Set("Vary", "Accept")
		return
	}
	for _, item := range strings.Split(string(current), ",") {
		if strings.EqualFold(strings.TrimSpace(item), "Accept") {
			return
		}
	}
	c.Response.Header.Set("Vary", string(current)+", Accept")
}
