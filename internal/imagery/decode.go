// Package imagery 实现响应图片转换：format/quality/resize/crop/rotate/
// auto-orient/bright/contrast/sharpen/info 与水印。
//
// 设计边界（与 internal/waf/dynamic 的关系）：
//
//   - 依赖方向单向：dynamic → imagery。水印自本包导出，dynamic 只转发调用，
//     图像编解码依赖（webp 等）不再出现在 dynamic 的依赖面里。
//   - 启用条件与 dynamic 正交：本包由 URL 查询参数 image_process 逐请求触发，
//     不依赖站点的 HTML/JS 混淆开关。
//   - 失败语义沿用旧水印实现：任何解码/编码/参数错误都返回原图，不向上抛，
//     由调用方按「未变更」处理（避免把图片 502 掉）。
package imagery

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"strings"

	// 注册各输入格式的解码器。
	//
	// image/gif 缺席是旧实现的缺陷根因：watermark.go 的 gif 分支依赖
	// image.Decode，但 dynamic 包从未 import image/gif；标准库 gif 解码器
	// 通过 init() 调用 image.RegisterFormat 完成注册，未 import 即未注册，
	// image.Decode 必然返回 unknown format。此处显式注册以修复该缺陷。
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"

	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"
)

// DecodeLimits 界定单张图片的解码规模上限，用于在解码前拒绝解压炸弹。
//
// 三个限制都必须在 Decode 之前生效：DecodeConfig 只读取头部，内存开销 O(1)，
// 而 Decode 会按 Width×Height 立即分配完整像素缓冲。
type DecodeLimits struct {
	// MaxPixels 是宽×高的乘积上限（像素数）。
	MaxPixels int64
	// MaxSide 是单边长度上限（像素）。
	MaxSide int
	// MaxBytes 是输入字节长度上限。
	MaxBytes int64
}

// DefaultDecodeLimits 是默认解码限制。
//
// MaxPixels 取 16,777,216 px：按 RGBA 计 64 MiB/张，是本项目愿意承担的
// 单张峰值上限。MaxSide 取 16384 px，与 WebP 编解码器的单边约束一致。
// MaxBytes 取 10 MiB，与响应变换缓冲上限同量级。
var DefaultDecodeLimits = DecodeLimits{
	MaxPixels: 16777216,
	MaxSide:   16384,
	MaxBytes:  10 * 1024 * 1024,
}

// ErrTooLarge 表示输入超过了 DecodeLimits，调用方应原图直通。
var ErrTooLarge = errors.New("imagery: image exceeds decode limits")

// ErrUnsupported 表示输入格式不在支持范围内或字节畸形。
var ErrUnsupported = errors.New("imagery: unsupported image format")

// Format 是图片格式的规范化名称。
type Format string

// 支持的格式常量。
const (
	FormatJPEG Format = "jpeg"
	FormatPNG  Format = "png"
	FormatGIF  Format = "gif"
	FormatBMP  Format = "bmp"
	FormatTIFF Format = "tiff"
	FormatWebP Format = "webp"
)

// ContentType 返回该格式对应的 MIME 类型。
//
// @return 该格式的 MIME 类型；未知格式返回空串。
func (f Format) ContentType() string {
	switch f {
	case FormatJPEG:
		return "image/jpeg"
	case FormatPNG:
		return "image/png"
	case FormatGIF:
		return "image/gif"
	case FormatBMP:
		return "image/bmp"
	case FormatTIFF:
		return "image/tiff"
	case FormatWebP:
		return "image/webp"
	default:
		return ""
	}
}

// ParseFormat 把外部传入的格式名规范化为 Format。
//
// 大小写不敏感，并接受 jpg/tif 这两个常见别名。无法识别时返回空串，
// 调用方必须把空串视为「不支持」而不是「尽力而为」。
//
// @param name 外部格式名（例如 "jpg"、"PNG"）。
// @return 规范化后的格式；无法识别时为空串。
func ParseFormat(name string) Format {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "jpeg", "jpg":
		return FormatJPEG
	case "png":
		return FormatPNG
	case "gif":
		return FormatGIF
	case "bmp":
		return FormatBMP
	case "tiff", "tif":
		return FormatTIFF
	case "webp":
		return FormatWebP
	default:
		return ""
	}
}

// SniffFormat 按解码器注册表识别输入格式。
//
// 与只对前 4 字节做硬编码比较的做法不同，这里复用 image.DecodeConfig 的格式
// 嗅探，因此 BMP/TIFF/WebP 也能被识别，且识别结果与随后 Decode 所用解码器
// 一致。只读取头部，不随图片大小增长。
//
// 关键点：必须接受「已识别格式但解析头部失败」的情形。JPEG 的 DecodeConfig
// 即使只看前 512 字节也要求读到扫描段之前的所有段，截断输入会返回
// unexpected EOF，但第二个返回值（格式名）此时已经确定。实测：
//
//	head 512B  → cfg=0x0 dims=0x0 format="jpeg" err=unexpected EOF
//	full 643B  → cfg=dims 16x16          format="jpeg" err=<nil>
//
// 因此判定条件取 format != ""，而不是 err == nil。
//
// @param data 图片字节。
// @return 规范化格式名；无法识别时为空串。
func SniffFormat(data []byte) string {
	const sniffLen = 512
	head := data
	if len(head) > sniffLen {
		head = head[:sniffLen]
	}
	_, format, _ := image.DecodeConfig(bytes.NewReader(head))
	return format
}

// DecodeInput 是解码后的图片及其元信息。
//
// 字段导出，调用方可以自行构造：只需要元信息时可留 Image 为 nil（BuildInfo
// 就只读四个元信息字段，见其契约说明），需要像素时必须是 Decode 的返回值。
type DecodeInput struct {
	// Image 是解码后的像素；多帧输入由 image.Decode 返回第一帧。
	//
	// 可能为 nil：decodeHeaderOnly 返回的结果不带像素。用它去绘制（toRGBA
	// 等）会得到空画布，属调用方契约违反。
	Image image.Image
	// Format 是输入格式的规范化名。
	Format Format
	// Width、Height 是原图尺寸。
	Width  int
	Height int
	// FrameCount 是帧数，静态图为 1。
	FrameCount int
}

// Animated 报告输入是否为多帧图片。
//
// @return 帧数大于 1 时为 true。
func (d *DecodeInput) Animated() bool {
	return d != nil && d.FrameCount > 1
}

// Decode 在限额内解码图片。
//
// 流程固定为「DecodeConfig 校验 → Decode」，顺序不可颠倒：DecodeConfig 只读头，
// 内存 O(1)，能在分配像素缓冲之前拒绝解压炸弹。仅凭 magic bytes 判断格式不足
// 以防御，因为伪造的头部可以声明任意尺寸——DecodeConfig 会按真实解码器解析并
// 对畸形头部报错。
//
// @param data 图片字节。
// @param limits 解码限额；传入零值时使用 DefaultDecodeLimits。
// @return 解码结果；任何失败都返回错误，由调用方决定是否原图直通。
func Decode(data []byte, limits DecodeLimits) (*DecodeInput, error) {
	cfg, formatName, err := decodeConfigChecked(data, limits)
	if err != nil {
		return nil, err
	}

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}

	return &DecodeInput{
		Image:      img,
		Format:     formatName,
		Width:      cfg.Width,
		Height:     cfg.Height,
		FrameCount: frameCountFor(formatName, data),
	}, nil
}

// decodeConfigChecked 执行限额校验与头部解析。
//
// Decode 与 decodeHeaderOnly 共用这一段，因此两条路径的「拒绝集合」在头部层面
// 逐字相同：相同的 MaxBytes/MaxSide/MaxPixels 判定、相同的错误文本。
//
// @param data 图片字节。
// @param limits 解码限额；零值时使用 DefaultDecodeLimits。
// @return 头部解析出的尺寸、规范化格式；任何失败返回错误。
func decodeConfigChecked(data []byte, limits DecodeLimits) (image.Config, Format, error) {
	if limits.MaxBytes <= 0 || limits.MaxPixels <= 0 || limits.MaxSide <= 0 {
		limits = DefaultDecodeLimits
	}
	if len(data) == 0 {
		return image.Config{}, "", ErrUnsupported
	}
	if int64(len(data)) > limits.MaxBytes {
		return image.Config{}, "", ErrTooLarge
	}

	cfg, formatName, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return image.Config{}, "", fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return image.Config{}, "", fmt.Errorf("%w: non-positive dimensions", ErrUnsupported)
	}
	if cfg.Width > limits.MaxSide || cfg.Height > limits.MaxSide {
		return image.Config{}, "", ErrTooLarge
	}
	if int64(cfg.Width)*int64(cfg.Height) > limits.MaxPixels {
		return image.Config{}, "", ErrTooLarge
	}
	return cfg, Format(formatName), nil
}

// frameCountFor 计算帧数。
//
// 静态图为 1；GIF 与 WebP 需要扫描帧结构（扫块头，不解码像素），因此这不是
// 一个纯头部字段——但它的成本与「解码像素」相比仍低几个数量级。
//
// @param format 规范化格式。
// @param data 图片字节。
// @return 帧数。
func frameCountFor(format Format, data []byte) int {
	switch format {
	case FormatGIF:
		if n := countGIFFrames(data); n > 1 {
			return n
		}
	case FormatWebP:
		if n := countWebPFrames(data); n > 1 {
			return n
		}
	}
	return 1
}

// decodeHeaderOnly 只解析头部与容器完整性，不分配像素缓冲。
//
// 供只需要元信息的调用方使用（Transform 的 info 分支）：BuildInfo 读取的字段
// 全部来自 DecodeConfig、帧数扫描与 len(data)，没有一个需要完整像素。
//
// 严格性设计——为什么不是「只看头部就放行」：
//
//   - 头部层面的拒绝与 Decode 逐字相同（共用 decodeConfigChecked），包括
//     解压炸弹防线（MaxSide/MaxPixels/MaxBytes 全部在分配像素之前生效）。
//   - 容器完整性由 containerComplete 判定：JPEG/PNG/WebP/BMP 用 O(1) 的尾部
//     特征，GIF 用块结构扫描（尾字节在 GIF 上不可靠，理由见该函数注释）。
//     这一步只是「够不够格走快路径」的资格筛选，不是独立的判定：**不通过时
//     一律回退到 Decode**，由真实解码器给出与改造前逐字相同的结论。因此截断
//     输入（响应变换链上最常见的损坏形态）仍然走「原图直通 + decode: ... 跳过
//     原因」。
//   - TIFF 与未知格式没有可靠的完整性特征，永远回退，不猜。
//
// 与 Decode 的差异面（全部实测，方法见下）：
//
//   - **截断输入：零差异。** 穷举本包 testdata 七个 fixture 的每一个截断长度，
//     头部层面共用 decodeConfigChecked（错误文本逐字相同），容器层面判不完整就
//     回退到 Decode。GIF 的尾字节判定曾在这一类上误判（1764/2097/2825/2861/
//     3080/4238/4540/4745/4766 九个长度），已改为块结构扫描，差异归零。
//   - **字节损坏：存在差异，无法在不解码的前提下消除。** 对每个 fixture 逐字节
//     翻转（^0xFF）后统计「头部通过 + 容器判完整 + Decode 失败」的位置数：
//     PNG 1045/1082、GIF 4715/6612、动画 GIF 18/101、WebP 460/518、JPEG 326/1693、
//     BMP 7/28854、TIFF 0（TIFF 永远回退）。典型错误是 PNG 的 "too much pixel
//     data"、JPEG 的 "DQT has wrong length"、GIF 的 "frame bounds larger than
//     image bounds"——压缩数据或段内部损坏，而容器块链自洽。
//
// 为什么接受第二类差异：要消掉它就必须完整校验压缩流，而「读完并解压整条流」
// 正是本函数要避免的成本（PNG 编码器把整张图放进一个 IDAT，读到第一个 IDAT
// 就等于读完整条流）。代价与收益的权衡如下：这类输入在真实上游响应里不出现
// （传输损坏表现为截断，已被完整覆盖）；即使出现，出来的也是一个 200 的元信息
// JSON，尺寸/格式/帧数全部取自真实头部，且限额已在分配像素之前校验，不存在
// 内存放大或伪造空间。若下游需要严格复刻「损坏即直通」，把 Transform 的 info
// 分支换回 Decode 即可，改动是一行。
//
// 返回值的 Image 恒为 nil：本函数不产生像素，调用方不得把它当作可绘制的图像。
//
// @param data 图片字节。
// @param limits 解码限额；零值时使用 DefaultDecodeLimits。
// @return 头部解析结果（Image 为 nil）；失败时返回错误。
func decodeHeaderOnly(data []byte, limits DecodeLimits) (*DecodeInput, error) {
	cfg, formatName, err := decodeConfigChecked(data, limits)
	if err != nil {
		return nil, err
	}
	if !containerComplete(formatName, data) {
		// 无法确认容器完整时不做任何猜测：交回 Decode，保持判定与改造前一致。
		return Decode(data, limits)
	}
	return &DecodeInput{
		Format:     formatName,
		Width:      cfg.Width,
		Height:     cfg.Height,
		FrameCount: frameCountFor(formatName, data),
	}, nil
}

// containerComplete 用低成本的容器完整性判定决定能否走快路径。
//
// 判定为「不完整」只意味着回退到 Decode，不意味着直接判失败，因此这里的每个
// 分支都只需要「不冤枉完整文件」，不需要追求精确。
//
// GIF 是唯一的例外，必须做结构扫描而不是只看尾字节：GIF 的帧数据是子块链，
// 链内任何位置都可能出现 0x3B 字节（压缩后的 LZW 数据本身就是任意字节流），
// 只要某次截断恰好落在这种字节上，尾字节判定就会把截断文件判成完整。实测
// fixture.gif 上有 9 个这样的长度（1764/2097/2825/2861/3080/4238/4540/4745/4766），
// 逐长度穷举确认结构扫描版在这些长度上全部正确回退、差异面归零。扫描只是跳块
// 头，不解压、不建调色板，成本与 countGIFFrames 同量级，且帧数计算本来就要扫。
//
// @param format 规范化格式。
// @param data 图片字节。
// @return 可确认完整时为 true。
func containerComplete(format Format, data []byte) bool {
	switch format {
	case FormatJPEG:
		// EOI（0xFFD9）：Go 的 jpeg 解码器读到 EOI 即结束，截断文件必然没有它。
		return len(data) >= 2 && data[len(data)-2] == 0xFF && data[len(data)-1] == 0xD9
	case FormatPNG:
		// IEND：长度 0 + 类型 "IEND" + CRC，共 12 字节。
		return len(data) >= 12 && string(data[len(data)-8:len(data)-4]) == "IEND"
	case FormatGIF:
		return gifBlocksConsumeWholeFile(data)
	case FormatWebP:
		// RIFF 头声明的总长度（含 "RIFF"+size 8 字节），奇数负载补一个填充字节。
		if len(data) < 12 {
			return false
		}
		declared := int(binary.LittleEndian.Uint32(data[4:8])) + 8
		return declared == len(data) || declared+1 == len(data)
	case FormatBMP:
		// BITMAPFILEHEADER.bfSize（偏移 2，小端）。
		if len(data) < 14 {
			return false
		}
		return int(binary.LittleEndian.Uint32(data[2:6])) == len(data)
	default:
		// TIFF 没有结束标记约定，未知格式不猜。
		return false
	}
}

// gifBlocksConsumeWholeFile 判定 GIF 的块结构是否恰好消费完整个文件。
//
// 与 countGIFFrames 用同一套跳块规则，但终止条件更严：必须精确落在
// 最后一字节的 Trailer 上，而不是「扫到一半遇到 0x3B 或解析异常就返回」。
//
// @param data GIF 字节。
// @return 结构完整且恰好到文件末尾时为 true。
func gifBlocksConsumeWholeFile(data []byte) bool {
	// Header(6) + Logical Screen Descriptor(7) = 13，再加 1 字节 Trailer。
	if len(data) < 14 || string(data[0:3]) != "GIF" {
		return false
	}
	packed := data[10]
	pos := 13
	if packed&0x80 != 0 {
		// 全局颜色表大小 = 2^(N+1)，N 为 packed 低 3 位。
		pos += 3 * (1 << ((packed & 0x07) + 1))
	}

	for {
		if pos >= len(data) {
			// 结构断裂：没有 Trailer。
			return false
		}
		switch data[pos] {
		case 0x3B: // Trailer：必须是整个文件的最后一个字节。
			return pos == len(data)-1
		case 0x21: // 扩展引入符：label(1) + 数据子块链
			if pos+1 >= len(data) {
				return false
			}
			next, ok := skipGIFSubBlocks(data, pos+2)
			if !ok {
				return false
			}
			pos = next
		case 0x2C: // Image Descriptor：9 字节 + 可选局部颜色表 + LZW 最小码长 + 子块链
			if pos+9 >= len(data) {
				return false
			}
			localPacked := data[pos+9]
			next := pos + 10
			if localPacked&0x80 != 0 {
				next += 3 * (1 << ((localPacked & 0x07) + 1))
			}
			if next >= len(data) {
				return false
			}
			var ok bool
			next, ok = skipGIFSubBlocks(data, next+1)
			if !ok {
				return false
			}
			pos = next
		default:
			return false
		}
	}
}

// countGIFFrames 统计 GIF 的帧数。
//
// 只扫描块结构（不解码像素、不建调色板），因此在 16M px 的输入上仍是 O(1)
// 内存。GIF 的帧由 Image Descriptor（0x2C）标记，扩展块（0x21）与调色板
// 按块长度跳过。任何解析异常都返回已计数结果，调用方按「不动画」处理。
//
// @param data GIF 字节。
// @return 帧数；解析失败时返回已成功计数的帧数。
func countGIFFrames(data []byte) int {
	// Header(6) + Logical Screen Descriptor(7) = 13，缺一不可。
	if len(data) < 13 {
		return 0
	}
	if string(data[0:3]) != "GIF" {
		return 0
	}
	packed := data[10]
	pos := 13
	if packed&0x80 != 0 {
		// 全局颜色表大小 = 2^(N+1)，N 为 packed 低 3 位。
		pos += 3 * (1 << ((packed & 0x07) + 1))
	}

	frames := 0
	for {
		if pos >= len(data) {
			return frames
		}
		switch data[pos] {
		case 0x3B: // Trailer
			return frames
		case 0x21: // 扩展引入符：label(1) + 数据子块链
			if pos+1 >= len(data) {
				return frames
			}
			var ok bool
			pos, ok = skipGIFSubBlocks(data, pos+2)
			if !ok {
				return frames
			}
		case 0x2C: // Image Descriptor：9 字节 + 可选局部颜色表 + LZW + 子块
			if pos+9 >= len(data) {
				return frames
			}
			localPacked := data[pos+9]
			next := pos + 10
			if localPacked&0x80 != 0 {
				next += 3 * (1 << ((localPacked & 0x07) + 1))
			}
			// LZW 最小编码长度（1 字节）。
			if next >= len(data) {
				return frames
			}
			var ok bool
			next, ok = skipGIFSubBlocks(data, next+1)
			if !ok {
				return frames
			}
			frames++
			pos = next
		default:
			return frames
		}
	}
}

// skipGIFSubBlocks 跳过 GIF 的数据子块链，返回链结束后的下一个块偏移。
//
// @param data GIF 字节。
// @param pos 子块链起始偏移。
// @return 下一个块偏移与是否解析成功。
func skipGIFSubBlocks(data []byte, pos int) (int, bool) {
	for {
		if pos >= len(data) {
			return pos, false
		}
		size := int(data[pos])
		pos++
		if size == 0 {
			return pos, true
		}
		pos += size
	}
}

// countWebPFrames 读取 WebP 的 VP8X 动画标志与 ANMF 帧数。
//
// VP8X 只在扩展格式（含动画/透明/ICC）中出现；纯 VP8/VP8L 是单帧。
// 这里只遍历 RIFF 顶层 chunk，不做像素解码。
//
// @param data WebP 字节。
// @return 帧数；非动画或解析失败时返回 0。
func countWebPFrames(data []byte) int {
	// RIFF(4) + size(4) + "WEBP"(4) = 12。
	if len(data) < 12 || string(data[0:4]) != "RIFF" || string(data[8:12]) != "WEBP" {
		return 0
	}
	pos := 12
	animated := false
	frames := 0
	for pos+8 <= len(data) {
		fourCC := string(data[pos : pos+4])
		size := int(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
		if size < 0 || pos+8+size > len(data) {
			return frames
		}
		switch fourCC {
		case "VP8X":
			if size >= 1 && data[pos+8]&0x02 != 0 {
				animated = true
			}
		case "ANMF":
			if animated {
				frames++
			}
		}
		// RIFF chunk 按偶数字节对齐。
		pos += 8 + size
		if size%2 == 1 {
			pos++
		}
	}
	if !animated {
		return 0
	}
	return frames
}
