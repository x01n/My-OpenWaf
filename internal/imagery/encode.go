package imagery

import (
	"bytes"
	"fmt"
	"image/gif"
	"image/jpeg"
	"image/png"

	"github.com/gen2brain/webp"
	"golang.org/x/image/bmp"
	"golang.org/x/image/tiff"
)

// EncodingOptions 是编码参数。
type EncodingOptions struct {
	// Format 是目标格式；空串表示保持输入格式。
	Format Format
	// Quality 是质量（1-100）。
	//
	// 对 JPEG/WebP 映射到编码器质量；对 PNG 映射到压缩等级（质量越高压缩越
	// 弱）；对 GIF/BMP/TIFF 无影响（他们的编码器没有质量维度）。
	// 0 表示各编码器的默认值。
	Quality int
	// Lossless 仅在 Format=webp 时生效，切换 WebP 无损模式（忽略 Quality）。
	Lossless bool
}

// clampQuality 把质量参数钳制到 [1, 100]。
//
// @param q 输入质量。
// @return 钳制后的质量；输入 <=0 时返回 0（表示使用编码器默认值）。
func clampQuality(q int) int {
	if q <= 0 {
		return 0
	}
	if q > 100 {
		return 100
	}
	return q
}

// Encode 按目标格式编码图片。
//
// 目标格式无法识别时返回错误，调用方应原图直通。所有编码器都写入同一个
// bytes.Buffer，编码失败时缓冲区被丢弃，不会把半截数据交给上游。
//
// @param img 待编码像素。
// @param opts 编码参数；Format 为空时返回错误。
// @return 编码后的字节与格式；失败时返回错误。
func Encode(img imageLike, opts EncodingOptions) ([]byte, Format, error) {
	format := opts.Format
	if format == "" {
		return nil, "", fmt.Errorf("%w: empty target format", ErrUnsupported)
	}
	quality := clampQuality(opts.Quality)

	var buf bytes.Buffer
	var err error
	switch format {
	case FormatJPEG:
		o := &jpeg.Options{Quality: jpeg.DefaultQuality}
		if quality > 0 {
			o.Quality = quality
		}
		err = jpeg.Encode(&buf, img, o)
	case FormatPNG:
		enc := png.Encoder{CompressionLevel: png.DefaultCompression}
		if quality > 0 {
			// PNG 的「质量」语义是压缩等级：质量越高压缩越弱（保真优先）。
			enc.CompressionLevel = qualityToPNGLevel(quality)
		}
		err = enc.Encode(&buf, img)
	case FormatGIF:
		// GIF 是 256 色调色板格式，逐像素量化无法保留真彩细节；配合
		// NumColors=256 + Floyd-Steinberg 抖动在视觉上接近原图。
		//
		// 注意：与旧实现「GIF 一律转 PNG」不同，这里输出的字节确实是 GIF，
		// 调用方据此设置 Content-Type 才能与字节一致。
		err = gif.Encode(&buf, img, &gif.Options{NumColors: 256})
	case FormatBMP:
		err = bmp.Encode(&buf, img)
	case FormatTIFF:
		// 默认 deflate + predictor：相比无压缩显著减小体积，且 decoder 侧
		// 的兼容性足够（libtiff/ImageMagick 均支持）。
		err = tiff.Encode(&buf, img, &tiff.Options{Compression: tiff.Deflate, Predictor: true})
	case FormatWebP:
		if opts.Lossless {
			err = webp.Encode(&buf, img, webp.Options{Lossless: true})
		} else {
			o := webp.Options{Quality: webp.DefaultQuality}
			if quality > 0 {
				o.Quality = quality
			}
			err = webp.Encode(&buf, img, o)
		}
	default:
		return nil, "", fmt.Errorf("%w: %s", ErrUnsupported, format)
	}
	if err != nil {
		return nil, "", fmt.Errorf("imagery: encode %s: %w", format, err)
	}
	if buf.Len() == 0 {
		return nil, "", fmt.Errorf("imagery: encode %s: empty output", format)
	}
	return buf.Bytes(), format, nil
}

// qualityToPNGLevel 把 1-100 的质量映射到 PNG 压缩等级。
//
// @param quality 质量（1-100）。
// @return 对应的 png.CompressionLevel。
func qualityToPNGLevel(quality int) png.CompressionLevel {
	switch {
	case quality >= 90:
		return png.BestCompression
	case quality >= 70:
		return png.DefaultCompression
	case quality >= 40:
		return png.BestSpeed + 1
	default:
		return png.BestSpeed
	}
}
