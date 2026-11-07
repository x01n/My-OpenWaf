package imagery

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// paramSeparator 分隔相邻操作（ESA 语义）。
const paramSeparator = "/"

// argSeparator 分隔同一操作内的参数。
const argSeparator = ","

// errInvalidParams 表示 image_process 参数不可用。
//
// 语义对齐 ESA：「当任意参数值为负数时，将不对图片进行任何处理直接返回原图」。
// 调用方收到该错误时应原图直通，不得猜测性降级。
var errInvalidParams = errors.New("imagery: invalid image_process parameters")

// Options 是一次图片转换的规范化参数集。
//
// 各字段为 nil/零值表示该操作未请求。多个操作按 ESA 的固定顺序执行，
// 见 Transform。
type Options struct {
	// Format 是目标格式；空串表示保持输入格式。
	Format Format
	// Quality 是绝对质量（1-100）；0 表示不指定。
	Quality int
	// Resize 是缩放参数；nil 表示不缩放。
	Resize *ResizeSpec
	// Crop 是裁剪参数；nil 表示不裁剪。
	Crop *CropSpec
	// Rotate 是顺时针旋转角度（90/180/270）；0 表示不旋转。
	Rotate int
	// AutoOrient 表示按 EXIF Orientation 修正朝向。
	AutoOrient bool
	// Bright 是亮度增量 [-100,100]；nil 表示不调整。
	Bright *int
	// Contrast 是对比度增量 [-100,100]；nil 表示不调整。
	Contrast *int
	// Sharpen 是锐化强度 [50,399]；nil 表示不锐化。
	Sharpen *int
	// Info 表示只输出图片元信息（JSON），不做任何像素变换。
	Info bool
	// Watermark 表示叠加水印；nil 表示不叠加。
	Watermark *WatermarkSpec
}

// ResizeSpec 是 resize 操作的参数。
type ResizeSpec struct {
	// Width、Height 是自适应等比缩放的驱动边（w_/h_），<=0 表示未指定。
	Width  int
	Height int
	// FitWidth、FitHeight 是指定宽高（fw_/fh_），两者同时给定。
	FitWidth  int
	FitHeight int
	// LongSide 是最长边（l_），<=0 表示未指定。
	LongSide int
	// ShortSide 是最短边（s_），<=0 表示未指定。
	ShortSide int
	// Percent 是按原图比例缩放（p_），0 表示未指定。
	Percent int
	// Threshold 是按条件缩放的阈值（threshold），单位字节；
	// 大于 0 时，只有原图字节数 >= Threshold 才执行本次缩放。
	Threshold int64
}

// CropSpec 是 crop 操作的参数。
type CropSpec struct {
	// Width、Height 是裁剪宽高，<=0 表示未指定。
	Width  int
	Height int
	// X、Y 是裁剪起点，<0 表示未指定（未指定时按 Gravity 定位）。
	X int
	Y int
	// Gravity 是九宫格定位（g_）；空串表示未指定。
	Gravity string
	// Center 表示 crop,mid（居中裁剪）。
	Center bool
}

// WatermarkSpec 是 watermark 操作的参数。
//
// 文本内容不来自 URL：本实现只接受调用方（服务端配置）提供的文本，
// URL 中的 text_ 与 image_ 参数一律拒绝，见 parseWatermark 的说明。
type WatermarkSpec struct {
	// Gravity 是水印位置（g_）。
	Gravity string
	// X、Y 是水印边距。
	X int
	Y int
	// Opacity 是透明度 [0,100]；<0 表示未指定。
	Opacity int
}

// Parse 解析 image_process 查询参数。
//
// 语法与 ESA 一致：`/` 分隔多个操作，`,` 分隔操作内参数，参数名与取值用
// `_` 连接，例如 `resize,l_200/threshold,1024000`、`crop,x_10,y_10,w_400,h_200`、
// `format,webp/quality,Q_90`。
//
// 解析策略是严格白名单：
//
//   - 未知操作名整体忽略（不进入任何 default 分支做「尽力而为」）；
//   - 已知操作内的未知参数名忽略；
//   - 已知参数取值非法（非数字、负数、超出区间、非法枚举）→ 返回错误，
//     调用方应原图直通。这与 ESA「任意参数值为负数时原图直通」的口径一致；
//   - watermark 的 text_ / image_ 参数直接判为非法（前者是内容注入，
//     后者会让边缘节点去拉取外部资源，即 SSRF）。
//
// @param raw image_process 参数的原始值（多个同名参数以 paramSeparator 连接）。
// @return 规范化参数；raw 为空时返回零值 Options 与 nil。
func Parse(raw string) (Options, error) {
	var opts Options
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return opts, nil
	}

	// pendingThreshold 承载独立的 threshold 操作。
	//
	// ESA 的 threshold 与 resize 同级（`resize,l_200/threshold,1024000`），
	// 语义是「仅当原图字节数 >= 该值时执行缩放」。它可能出现在 resize 之前
	// 或之后，因此先暂存，全部操作解析完再绑定。
	var pendingThreshold int64

	for _, opRaw := range strings.Split(raw, paramSeparator) {
		opRaw = strings.TrimSpace(opRaw)
		if opRaw == "" {
			continue
		}
		parts := strings.Split(opRaw, argSeparator)
		// 跳过前导空段：`//,/resize,w_100` 这类多余分隔符不应让操作名变成空串
		// （那会导致该操作被当作未知操作丢弃）。
		idx := 0
		for idx < len(parts) && strings.TrimSpace(parts[idx]) == "" {
			idx++
		}
		if idx >= len(parts) {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(parts[idx]))
		args := parts[idx+1:]

		switch name {
		case "format":
			f, err := parseFormatOp(args)
			if err != nil {
				return Options{}, err
			}
			opts.Format = f
		case "quality":
			q, err := parseQualityOp(args)
			if err != nil {
				return Options{}, err
			}
			opts.Quality = q
		case "resize":
			spec, err := parseResizeOp(args)
			if err != nil {
				return Options{}, err
			}
			opts.Resize = spec
		case "threshold":
			v, err := parseRangeOp(name, args, 0, 1<<31-1)
			if err != nil {
				return Options{}, err
			}
			if v <= 0 {
				return Options{}, fmt.Errorf("%w: threshold must be positive", errInvalidParams)
			}
			pendingThreshold = int64(v)
		case "crop":
			spec, err := parseCropOp(args)
			if err != nil {
				return Options{}, err
			}
			opts.Crop = spec
		case "rotate":
			deg, err := parseRotateOp(args)
			if err != nil {
				return Options{}, err
			}
			opts.Rotate = deg
		case "auto-orient":
			opts.AutoOrient = true
		case "bright":
			v, err := parseRangeOp(name, args, -100, 100)
			if err != nil {
				return Options{}, err
			}
			opts.Bright = &v
		case "contrast":
			v, err := parseRangeOp(name, args, -100, 100)
			if err != nil {
				return Options{}, err
			}
			opts.Contrast = &v
		case "sharpen":
			v, err := parseRangeOp(name, args, 50, 399)
			if err != nil {
				return Options{}, err
			}
			opts.Sharpen = &v
		case "info":
			opts.Info = true
		case "watermark":
			spec, err := parseWatermarkOp(args)
			if err != nil {
				return Options{}, err
			}
			opts.Watermark = spec
		default:
			// 未知操作名：忽略。ESA 会随版本演进增加操作，直接拒绝会让
			// 携带新操作的 URL 全部失效。
			continue
		}
	}

	// 绑定 threshold。仅出现 threshold 而无任何缩放驱动边时，等效于
	// 「不做任何缩放」——applyResize 会走到 Resize(0,0) 即恒等返回，
	// 但 threshold 判定仍然生效（不满足阈值时同样返回原像素）。
	if pendingThreshold > 0 {
		if opts.Resize == nil {
			opts.Resize = &ResizeSpec{}
		}
		opts.Resize.Threshold = pendingThreshold
	}
	return opts, nil
}

// IsZero 报告参数集不包含任何有效操作。
//
// @return 没有任何操作被请求时为 true。
func (o Options) IsZero() bool {
	return o.Format == "" && o.Quality == 0 && o.Resize == nil && o.Crop == nil &&
		o.Rotate == 0 && !o.AutoOrient && o.Bright == nil && o.Contrast == nil &&
		o.Sharpen == nil && !o.Info && o.Watermark == nil
}

// parseFormatOp 解析 format 操作。
//
// @param args 操作参数列表。
// @return 目标格式；无参数时返回空串表示保持原格式。
func parseFormatOp(args []string) (Format, error) {
	if len(args) == 0 {
		return "", nil
	}
	// format,jpg 这种「位置参数」写法：取第一个非空参数。
	for _, a := range args {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		// 允许 format,f_png 写法（ESA 的 name_value 风格）。
		if idx := strings.IndexByte(a, '_'); idx > 0 {
			a = a[idx+1:]
		}
		f := ParseFormat(a)
		if f == "" {
			// avif/jp2 等明确不支持的格式：拒绝而不是静默忽略，
			// 避免客户端误以为拿到了目标格式。
			return "", fmt.Errorf("%w: unsupported format %q", errInvalidParams, a)
		}
		return f, nil
	}
	return "", nil
}

// parseQualityOp 解析 quality 操作。
//
// 支持绝对质量 Q_90 与相对质量 q_90。相对质量依赖「原图当前质量」这一元数据，
// 而纯 Go 解码路径拿不到该值，因此 q_ 按「不指定质量」处理（返回 0）。
//
// @param args 操作参数列表。
// @return 绝对质量；相对质量或未指定时返回 0。
func parseQualityOp(args []string) (int, error) {
	if len(args) == 0 {
		return 0, fmt.Errorf("%w: quality requires a value", errInvalidParams)
	}
	for _, a := range args {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		prefix, value, ok := splitNameValue(a)
		if !ok {
			// 裸数字形式。
			value = a
			prefix = "q"
		}
		n, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("%w: quality value %q", errInvalidParams, value)
		}
		if n <= 0 {
			return 0, fmt.Errorf("%w: quality must be positive", errInvalidParams)
		}
		if n > 100 {
			return 0, fmt.Errorf("%w: quality above 100", errInvalidParams)
		}
		// 大写 Q 是绝对值，小写 q 是相对值。
		if prefix == "Q" {
			return n, nil
		}
		return 0, nil
	}
	return 0, nil
}

// parseResizeOp 解析 resize 操作。
//
// @param args 操作参数列表。
// @return 缩放参数；无有效参数时返回 nil。
func parseResizeOp(args []string) (*ResizeSpec, error) {
	spec := &ResizeSpec{}
	seen := false
	for _, a := range args {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		name, value, ok := splitNameValue(a)
		if !ok {
			return nil, fmt.Errorf("%w: resize argument %q", errInvalidParams, a)
		}
		n, err := parsePositiveInt(name, value)
		if err != nil {
			return nil, err
		}
		switch name {
		case "w":
			spec.Width = n
		case "h":
			spec.Height = n
		case "fw":
			spec.FitWidth = n
		case "fh":
			spec.FitHeight = n
		case "l":
			spec.LongSide = n
		case "s":
			spec.ShortSide = n
		case "p":
			if n > 100 {
				return nil, fmt.Errorf("%w: resize percent above 100", errInvalidParams)
			}
			spec.Percent = n
		case "threshold":
			spec.Threshold = int64(n)
		default:
			// 未识别的 resize 参数名忽略。
			continue
		}
		seen = true
	}
	if !seen {
		return nil, nil
	}
	return spec, nil
}

// parseCropOp 解析 crop 操作。
//
// @param args 操作参数列表。
// @return 裁剪参数；无有效参数时返回 nil。
func parseCropOp(args []string) (*CropSpec, error) {
	spec := &CropSpec{X: -1, Y: -1}
	seen := false
	for _, a := range args {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		lower := strings.ToLower(a)
		if lower == "mid" {
			spec.Center = true
			seen = true
			continue
		}
		if lower == "circle" {
			// 圆形裁剪需要引入透明遮罩，本轮不支持；按未知参数处理，
			// 让该操作退化为「只应用其余裁剪参数」而不是整体失败。
			continue
		}
		name, value, ok := splitNameValue(a)
		if !ok {
			return nil, fmt.Errorf("%w: crop argument %q", errInvalidParams, a)
		}
		if name == "g" {
			if !isValidGravity(value) {
				return nil, fmt.Errorf("%w: crop gravity %q", errInvalidParams, value)
			}
			spec.Gravity = value
			seen = true
			continue
		}
		n, err := parseNonNegativeInt(name, value)
		if err != nil {
			return nil, err
		}
		switch name {
		case "w":
			spec.Width = n
		case "h":
			spec.Height = n
		case "x":
			spec.X = n
		case "y":
			spec.Y = n
		default:
			continue
		}
		seen = true
	}
	if !seen {
		return nil, nil
	}
	return spec, nil
}

// parseRotateOp 解析 rotate 操作。
//
// @param args 操作参数列表。
// @return 顺时针角度；未指定或为 0 时返回 0。
func parseRotateOp(args []string) (int, error) {
	if len(args) == 0 {
		return 0, fmt.Errorf("%w: rotate requires an angle", errInvalidParams)
	}
	for _, a := range args {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		value := a
		if name, v, ok := splitNameValue(a); ok {
			if name != "a" && name != "A" {
				continue
			}
			value = v
		}
		n, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("%w: rotate angle %q", errInvalidParams, value)
		}
		if n < 0 {
			return 0, fmt.Errorf("%w: rotate angle must not be negative", errInvalidParams)
		}
		switch n % 360 {
		case 0:
			return 0, nil
		case 90, 180, 270:
			return n % 360, nil
		default:
			return 0, fmt.Errorf("%w: rotate angle must be 90/180/270", errInvalidParams)
		}
	}
	return 0, nil
}

// parseRangeOp 解析单值区间操作（bright/contrast/sharpen）。
//
// @param name 操作名，用于错误信息。
// @param args 操作参数列表。
// @param min、max 允许的闭区间。
// @return 取值。
func parseRangeOp(name string, args []string, min, max int) (int, error) {
	if len(args) == 0 {
		return 0, fmt.Errorf("%w: %s requires a value", errInvalidParams, name)
	}
	for _, a := range args {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		value := a
		if _, v, ok := splitNameValue(a); ok {
			value = v
		}
		n, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("%w: %s value %q", errInvalidParams, name, value)
		}
		if n < min || n > max {
			return 0, fmt.Errorf("%w: %s value %d out of range [%d,%d]", errInvalidParams, name, n, min, max)
		}
		return n, nil
	}
	return 0, nil
}

// parseWatermarkOp 解析 watermark 操作。
//
// 安全边界（与 ESA 的差异，刻意为之）：
//
//   - image_ 参数一律拒绝：ESA 的水印地址是任意外链，允许它等于让边缘节点
//     按客户端指令发起出站请求，即 SSRF。
//   - text_ 参数一律拒绝：把客户端文本渲染进服务端响应图片属于内容注入，
//     水印文案只能来自服务端配置。
//
// 位置参数（g_/x_/y_/t_）予以保留，它们只影响叠加位置，不引入外部数据。
//
// @param args 操作参数列表。
// @return 水印参数；无有效参数时返回空 spec。
func parseWatermarkOp(args []string) (*WatermarkSpec, error) {
	spec := &WatermarkSpec{Opacity: -1}
	for _, a := range args {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		name, value, ok := splitNameValue(a)
		if !ok {
			return nil, fmt.Errorf("%w: watermark argument %q", errInvalidParams, a)
		}
		switch name {
		case "image", "text", "type", "fill", "size", "rotate", "color":
			return nil, fmt.Errorf("%w: watermark argument %q is not accepted", errInvalidParams, name)
		case "g":
			if !isValidGravity(value) {
				return nil, fmt.Errorf("%w: watermark gravity %q", errInvalidParams, value)
			}
			spec.Gravity = value
		case "x":
			n, err := parseNonNegativeInt(name, value)
			if err != nil {
				return nil, err
			}
			spec.X = n
		case "y":
			n, err := parseNonNegativeInt(name, value)
			if err != nil {
				return nil, err
			}
			spec.Y = n
		case "t":
			n, err := parseNonNegativeInt(name, value)
			if err != nil {
				return nil, err
			}
			if n > 100 {
				return nil, fmt.Errorf("%w: watermark opacity above 100", errInvalidParams)
			}
			spec.Opacity = n
		default:
			continue
		}
	}
	return spec, nil
}

// splitNameValue 按首个下划线拆分 `name_value`。
//
// @param arg 单个参数。
// @return 名称、取值与是否拆分成功。
func splitNameValue(arg string) (string, string, bool) {
	idx := strings.IndexByte(arg, '_')
	if idx <= 0 || idx == len(arg)-1 {
		return "", "", false
	}
	return arg[:idx], arg[idx+1:], true
}

// parsePositiveInt 解析必须为正整数的参数。
//
// @param name 参数名（错误信息用）。
// @param value 取值的字符串形式。
// @return 解析结果。
func parsePositiveInt(name, value string) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%w: %s value %q", errInvalidParams, name, value)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%w: %s must be positive", errInvalidParams, name)
	}
	return n, nil
}

// parseNonNegativeInt 解析非负整数参数。
//
// @param name 参数名（错误信息用）。
// @param value 取值的字符串形式。
// @return 解析结果。
func parseNonNegativeInt(name, value string) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%w: %s value %q", errInvalidParams, name, value)
	}
	if n < 0 {
		return 0, fmt.Errorf("%w: %s must not be negative", errInvalidParams, name)
	}
	return n, nil
}

// isValidGravity 校验九宫格定位取值。
//
// @param value 定位名。
// @return 取值合法时为 true。
func isValidGravity(value string) bool {
	switch strings.ToLower(value) {
	case "nw", "north", "ne", "west", "center", "east", "sw", "south", "se":
		return true
	default:
		return false
	}
}
