package imagery

import (
	"context"
	"encoding/json"
	"fmt"
	"image"
	"time"
)

// DefaultOpTimeout 是单张图转换的默认墙钟预算。
//
// 依据本机实测（loadavg 5-10 的窗口内，1024x768 输入）：
// JPEG 编码 25-55ms、WebP 22-55ms、PNG 67-190ms；叠加缩放与锐化后仍是
// 百毫秒量级。2 秒足以覆盖正常图片，同时能挡住异常输入造成的长尾占用。
const DefaultOpTimeout = 2 * time.Second

// InfoField 是 info 输出中的单字段。
//
// 取值统一为字符串，与 ESA/OSS 的 info 响应结构一致：
//
//	{"ImageWidth": {"value": "400"}}
type InfoField struct {
	Value string `json:"value"`
}

// InfoOutput 是 info 操作的响应体。
//
// 字段名与 ESA/OSS 一致（PascalCase）。恒定返回 FileSize、Format、
// FrameCount、ImageHeight、ImageWidth；Orientation 仅在图片实际携带 EXIF
// 朝向时返回。
//
// 语义要点：info 描述的是**原图**，不是转换结果。ESA/OSS 文档均明确说明
// 「加入缩放等图片处理参数后，获取到的仍是原图信息」。因此一旦请求 info，
// 就短路掉全部像素变换。
type InfoOutput map[string]InfoField

// BuildInfo 构造图片元信息响应体。
//
// 契约（改造 info 快路径后收窄，调用方按此理解）：
//
//   - 只读 decoded 的 Format / FrameCount / Height / Width 四个字段，**不读
//     Image**。因此 Image 为 nil 的 DecodeInput 也能得到合法结果——这不是
//     错误容忍，而是本函数本来的语义（info 描述原图元信息，不需要像素）。
//   - 调用方若只取元信息，应当传 decodeHeaderOnly 的结果（Image 为 nil，
//     不分配像素缓冲）；只有需要像素的路径才传 Decode 的结果。
//   - 反过来说：拿到 InfoOutput 并不意味着 decoded 可绘制。Image 为 nil 时
//     调用方若去 toRGBA(decoded.Image) 会拿到空画布，那是调用方的契约违反。
//
// @param data 原始图片字节。
// @param decoded 已解码或仅解析过头的输入；只读取其四个元信息字段。
// @param orientation EXIF Orientation；0 表示无。
// @return 元信息与 JSON 字节。
func BuildInfo(data []byte, decoded *DecodeInput, orientation int) (InfoOutput, []byte) {
	out := InfoOutput{
		"FileSize":    InfoField{Value: fmt.Sprintf("%d", len(data))},
		"Format":      InfoField{Value: string(decoded.Format)},
		"FrameCount":  InfoField{Value: fmt.Sprintf("%d", decoded.FrameCount)},
		"ImageHeight": InfoField{Value: fmt.Sprintf("%d", decoded.Height)},
		"ImageWidth":  InfoField{Value: fmt.Sprintf("%d", decoded.Width)},
	}
	if orientation > 0 {
		out["Orientation"] = InfoField{Value: fmt.Sprintf("%d", orientation)}
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		// 该结构不可能序列化失败；兜底返回空对象而非 panic。
		return out, []byte("{}")
	}
	return out, encoded
}

// Result 是一次图片转换的结果。
type Result struct {
	// Body 是输出字节；未发生变换时等于输入字节。
	Body []byte
	// ContentType 是输出内容类型；未变换时沿用输入的 Content-Type。
	ContentType string
	// Changed 表示 Body 与输入不同，调用方据此决定是否按变换后处理响应头
	// （Content-Length / ETag 失效等）。
	Changed bool
	// Format 是输出格式；未变换时为空串。
	Format Format
	// Info 非 nil 表示本次输出为 JSON 元信息（此时 Changed 为 true）。
	Info InfoOutput
	// SkipReason 记录未变换的原因，便于观测与排障；已变换时为空串。
	SkipReason string
}

// Transform 按参数对图片执行转换。
//
// 执行顺序固定（同一输入与参数必然得到同一输出，便于缓存）：
//
//	info 短路 → auto-orient → crop → resize → rotate → bright → contrast
//	→ sharpen → watermark → 编码输出
//
// 失败语义：任何解码/编码/参数问题都不向上抛错误，而是返回「跳过原因 +
// 原图直通」。这是刻意为之——图片转换失败不应把用户的图片打成 502，
// 旧水印实现同样采用「失败返回原图」。
//
// **例外（info 路径，仅此一处）**：当请求带 info 且输入属于「容器结构完整、
// 压缩数据损坏」时，返回的不再是原图直通，而是 200 + 元信息 JSON。
//
// 为什么这个例外可接受，而不是「反正还是 200 就没事」：
//
//   - 它只发生在 info 上。info 请求**本来就不会用到像素**——`Info` 在函数一
//     开始就短路掉全部像素变换，所以「解码成功与否」在这条路径上从来不影响
//     输出内容，只影响「报元信息还是退回原图」。其余所有路径（resize、crop、
//     rotate、watermark、auto-orient、格式转换）仍然严格遵守上面的失败语义，
//     逐字未变。
//   - 它换取的是 info 路径不再分配像素缓冲：4000×3000 JPEG 上交替配对实测，
//     全量解码中位 5.32e8 ns、只读头中位 1.05e4 ns（≈5 万倍；三对配对比值
//     2.3e4–7.5e4，随宿机负载波动），内存 36.2 MB → 18.8 KB/次。这不是微优化，
//     是把一条只读元信息的路径从「解码整张图」降到「读头」。
//   - 触发条件窄且无法被外部免费制造。要命中必须同时满足：容器块链自洽、
//     结束标记到位、只有压缩数据或段内字段损坏。逐字节翻转的实测命中面是
//     PNG 1045/1082、JPEG 326/1693、GIF 4715/6612、WebP 460/518、BMP 7/28854、
//     TIFF 0/38594（见 infopath_equiv_test.go 的封顶断言）。
//   - 后果有界：返回的 JSON 只含 FileSize/Format/FrameCount/ImageHeight/
//     ImageWidth/Orientation，全部取自真实头部；解压炸弹防线（MaxSide/
//     MaxPixels/MaxBytes）在分配像素之前就已生效，不存在内存放大。
//   - 反过来，截断输入（真实上游响应里损坏图片的常见形态）**不在此例**：
//     容器判定为不完整就回退到 Decode，与改造前逐字同错。这一点由
//     TestInfoFastPathFallsBackForTruncatedInputs 逐长度穷举、零容忍断言。
//
// 若下游要求损坏图一律原样透传，把 info 分支里的 decodeHeaderOnly 换成 Decode
// 即可（一行），但会同时失去上述加速，且 TestInfoFastPathSkipsPixelDecode 与
// TestInfoFastPathByteCorruptionDivergenceIsBounded 需要跟着改——这个取舍有
// 测试护栏，不会被无意间翻回去。
//
// info 路径不做像素解码：BuildInfo 读取的字段全部来自容器头部与帧结构扫描，
// 因此走 decodeHeaderOnly；容器完整性无法确认时该函数回退到 Decode。两处刻意
// 的顺序调整（都在 info 分支内，非 info 路径的结果不变）：exifOrientation 移到
// 分支里，避免为一条只读头的路径多做一次全容器扫描；Decode 移到 info 分支之后，
// 使 info 请求不再付出全量解码。
//
// 多帧输入（动画 GIF、动画 WebP）在需要像素级变换时退化为首帧：
// image.Decode 只返回首帧，保留全部帧需要完整的动画重编码路径（尚未实现）。
// 仅做 info 查询时不丢帧信息，FrameCount 如实报告。
//
// @param ctx 请求上下文；用于在阶段之间做墙钟超时检查。
// @param data 原始图片字节。
// @param contentType 上游返回的 Content-Type，仅用于未变换时原样回传。
// @param opts 已解析的转换参数。
// @param watermarkText 服务端配置的水印文案。
// @param limits 解码限额；零值使用 DefaultDecodeLimits。
// @return 转换结果。
func Transform(ctx context.Context, data []byte, contentType string, opts Options, watermarkText string, limits DecodeLimits) Result {
	if len(data) == 0 || opts.IsZero() {
		return Result{Body: data, ContentType: contentType, SkipReason: "no-op"}
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			recordTimeout()
			return Result{Body: data, ContentType: contentType, SkipReason: "context: " + err.Error()}
		}
	}

	// info 短路：只报告原图元信息，不产生任何像素变换。
	if opts.Info {
		header, err := decodeHeaderOnly(data, limits)
		if err != nil {
			recordSkip(err)
			return Result{Body: data, ContentType: contentType, SkipReason: "decode: " + err.Error()}
		}
		info, encoded := BuildInfo(data, header, exifOrientation(data))
		recordApplied()
		return Result{
			Body:        encoded,
			ContentType: "application/json; charset=utf-8",
			Changed:     true,
			Info:        info,
		}
	}

	decoded, err := Decode(data, limits)
	if err != nil {
		recordSkip(err)
		return Result{Body: data, ContentType: contentType, SkipReason: "decode: " + err.Error()}
	}

	orientation := exifOrientation(data)

	img := toRGBA(decoded.Image)

	if opts.AutoOrient && orientation > 1 {
		img = applyOrientation(img, orientation)
	}
	if ctx != nil && ctx.Err() != nil {
		recordTimeout()
		return Result{Body: data, ContentType: contentType, SkipReason: "context: timed out before pixel ops"}
	}

	if opts.Crop != nil {
		img = applyCrop(img, opts.Crop)
	}
	if opts.Resize != nil {
		img = applyResize(img, opts.Resize, len(data))
	}
	if opts.Rotate != 0 {
		img = Rotate(img, opts.Rotate)
	}
	if opts.Bright != nil {
		img = AdjustBrightness(img, *opts.Bright)
	}
	if opts.Contrast != nil {
		img = AdjustContrast(img, *opts.Contrast)
	}
	if opts.Sharpen != nil {
		img = Sharpen(img, *opts.Sharpen)
	}
	if opts.Watermark != nil {
		img = applyWatermarkOverlay(img, watermarkText)
	}

	targetFormat := targetFormatOf(opts, decoded.Format)
	if targetFormat == "" {
		recordSkip(ErrUnsupported)
		return Result{Body: data, ContentType: contentType, SkipReason: "unknown input format"}
	}

	if ctx != nil && ctx.Err() != nil {
		recordTimeout()
		return Result{Body: data, ContentType: contentType, SkipReason: "context: timed out before encode"}
	}

	encoded, outFormat, err := Encode(img, EncodingOptions{Format: targetFormat, Quality: opts.Quality})
	if err != nil {
		recordSkip(err)
		return Result{Body: data, ContentType: contentType, SkipReason: "encode: " + err.Error()}
	}
	recordApplied()
	return Result{
		Body:        encoded,
		ContentType: outFormat.ContentType(),
		Changed:     true,
		Format:      outFormat,
	}
}

// applyCrop 执行裁剪（含九宫格与居中定位）。
//
// 定位优先级：Center（crop,mid）> 显式坐标（x_/y_）> 九宫格（g_）> 居中。
//
// @param img 输入像素。
// @param spec 裁剪参数。
// @return 裁剪后的像素。
func applyCrop(img *image.RGBA, spec *CropSpec) *image.RGBA {
	b := img.Bounds()
	w, h := spec.Width, spec.Height
	if w <= 0 || w > b.Dx() {
		w = b.Dx()
	}
	if h <= 0 || h > b.Dy() {
		h = b.Dy()
	}

	if spec.Center {
		return CropCenter(img, w, h)
	}
	if spec.X >= 0 || spec.Y >= 0 {
		x, y := spec.X, spec.Y
		if x < 0 {
			x = 0
		}
		if y < 0 {
			y = 0
		}
		return Crop(img, image.Rect(b.Min.X+x, b.Min.Y+y, b.Min.X+x+w, b.Min.Y+y+h))
	}
	if spec.Gravity != "" {
		x, y := gravityOrigin(spec.Gravity, b.Dx(), b.Dy(), w, h)
		return Crop(img, image.Rect(b.Min.X+x, b.Min.Y+y, b.Min.X+x+w, b.Min.Y+y+h))
	}
	return CropCenter(img, w, h)
}

// applyResize 执行缩放（含阈值条件与多种缩放口径）。
//
// 优先级：Percent（p_）> FitWidth/FitHeight（fw_/fh_）> LongSide（l_）>
// ShortSide（s_）> Width/Height（w_/h_）。ESA 本身不允许同时给出多组驱动边，
// 这里定下固定优先级只为让畸形输入有确定行为。
//
// @param img 输入像素。
// @param spec 缩放参数。
// @param srcBytes 原图字节数，用于 threshold 判定。
// @return 缩放后的像素。
func applyResize(img *image.RGBA, spec *ResizeSpec, srcBytes int) *image.RGBA {
	if spec.Threshold > 0 && int64(srcBytes) < spec.Threshold {
		return img
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()

	if spec.Percent > 0 && spec.Percent < 100 {
		return Resize(img, w*spec.Percent/100, h*spec.Percent/100)
	}
	if spec.FitWidth > 0 && spec.FitHeight > 0 {
		return Resize(img, spec.FitWidth, spec.FitHeight)
	}
	if spec.LongSide > 0 {
		return ResizeByLongSide(img, spec.LongSide)
	}
	if spec.ShortSide > 0 {
		return ResizeByShortSide(img, spec.ShortSide)
	}
	return Resize(img, spec.Width, spec.Height)
}

// applyWatermarkOverlay 叠加服务端水印。
//
// 水印文案只来自服务端配置；spec 只携带位置信息。文案为空时使用 "Protected"
// （与 dynamic 的既有默认值一致）。
//
// @param img 输入像素。
// @param text 服务端水印文案。
// @return 叠加后的像素。
func applyWatermarkOverlay(img *image.RGBA, text string) *image.RGBA {
	if text == "" {
		text = "Protected"
	}
	addTextWatermark(img, text)
	return img
}

// gravityOrigin 根据九宫格定位计算叠加原点。
//
// @param gravity 定位名（nw/north/ne/west/center/east/sw/south/se）。
// @param bw、bh 底图尺寸。
// @param ow、oh 叠加物尺寸。
// @return 原点坐标；未知定位按居中处理。
func gravityOrigin(gravity string, bw, bh, ow, oh int) (int, int) {
	switch gravity {
	case "nw":
		return 0, 0
	case "north":
		return (bw - ow) / 2, 0
	case "ne":
		return bw - ow, 0
	case "west":
		return 0, (bh - oh) / 2
	case "east":
		return bw - ow, (bh - oh) / 2
	case "sw":
		return 0, bh - oh
	case "south":
		return (bw - ow) / 2, bh - oh
	case "se":
		return bw - ow, bh - oh
	default:
		return (bw - ow) / 2, (bh - oh) / 2
	}
}

// targetFormatOf 决定输出格式：显式 format 优先，否则保持输入格式。
//
// @param opts 转换参数。
// @param inputFormat 输入格式。
// @return 目标格式。
func targetFormatOf(opts Options, inputFormat Format) Format {
	if opts.Format != "" {
		return opts.Format
	}
	return inputFormat
}
