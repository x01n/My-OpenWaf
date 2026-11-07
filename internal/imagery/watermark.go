package imagery

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

// Watermark 为图片添加右下角文字水印与居中半透明文字。
//
// 该函数由 internal/waf/dynamic/watermark.go 整体迁入：对 PNG 与 JPEG 输入，
// 输出与迁移前的 addWatermark 逐字节一致（同一画布构造、同一字体绘制、同一
// 编码器与参数）。迁移带来的差异只有两处，均为修复：
//
//   - GIF 输入现在真的会被处理。旧实现依赖 image.Decode 却从未 import
//     image/gif，解码必然失败并原样返回；本包已注册 gif 解码器。
//   - 返回实际输出格式。GIF 无法承载半透明水印，输出统一转为 PNG；旧实现不
//     回报格式，调用方仍按 image/gif 下发响应头，导致「GIF 头 + PNG 字节」。
//     调用方必须用返回的 Format 设置 Content-Type。
//
// BMP/TIFF/WebP 输入原样返回（与迁移前一致：旧实现的 switch 只覆盖
// png/jpeg/gif，其余落到 default 分支返回原图）。这些格式的转换由
// Transform 承担，不由水印承担。
//
// @param imgData 原始图片字节。
// @param text 水印文字。
// @return 处理后的字节、实际输出格式；任何失败都返回原图与原格式，不报错。
func Watermark(imgData []byte, text string) ([]byte, Format, error) {
	if len(imgData) == 0 {
		return imgData, "", nil
	}

	decoded, err := Decode(imgData, DecodeLimits{})
	if err != nil {
		return imgData, "", nil
	}
	switch decoded.Format {
	case FormatPNG, FormatJPEG, FormatGIF:
	default:
		return imgData, decoded.Format, nil
	}

	img := decoded.Image
	bounds := img.Bounds()
	if bounds.Dx() <= 0 || bounds.Dy() <= 0 {
		return imgData, decoded.Format, nil
	}

	// 创建新画布（支持透明通道）。与旧实现完全一致：以解码后的 bounds 建
	// RGBA，再用 draw.Src 拷贝。
	watermarked := image.NewRGBA(bounds)
	draw.Draw(watermarked, bounds, img, bounds.Min, draw.Src)

	addTextWatermark(watermarked, text)

	var buf bytes.Buffer
	switch decoded.Format {
	case FormatPNG:
		if err := png.Encode(&buf, watermarked); err != nil {
			return imgData, decoded.Format, nil
		}
		return buf.Bytes(), FormatPNG, nil
	case FormatJPEG:
		if err := jpeg.Encode(&buf, watermarked, &jpeg.Options{Quality: 90}); err != nil {
			return imgData, decoded.Format, nil
		}
		return buf.Bytes(), FormatJPEG, nil
	default:
		// GIF：不支持半透明文字，统一转为 PNG。
		if err := png.Encode(&buf, watermarked); err != nil {
			return imgData, decoded.Format, nil
		}
		return buf.Bytes(), FormatPNG, nil
	}
}

// addTextWatermark 在图片上添加文字水印。
//
// 与旧实现逐字节一致：右下角带半透明黑底条的白字，以及居中的浅灰半透明大字。
//
// @param img 目标画布（就地修改）。
// @param text 水印文字。
func addTextWatermark(img *image.RGBA, text string) {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	if width <= 0 || height <= 0 {
		return
	}

	// 使用基本字体
	face := basicfont.Face7x13

	// 在图片右下角添加水印，带半透明背景
	d := font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(color.RGBA{R: 255, G: 255, B: 255, A: 180}),
		Face: face,
	}

	// 测量文字大小
	textWidth := font.MeasureString(face, text).Round()
	textHeight := face.Metrics().Height.Round()

	// 位置：右下角，留边距
	margin := 20
	x := width - textWidth - margin
	y := height - margin

	if x < margin {
		x = margin
	}
	if y < textHeight+margin {
		y = textHeight + margin
	}

	// 绘制半透明背景条
	bgColor := color.RGBA{R: 0, G: 0, B: 0, A: 100}
	bgRect := image.Rect(x-5, y-textHeight-2, x+textWidth+5, y+2)
	draw.Draw(img, bgRect, image.NewUniform(bgColor), bgRect.Min, draw.Over)

	// 绘制文字
	d.Dot = fixed.Point26_6{
		X: fixed.Int26_6(x << 6),
		Y: fixed.Int26_6(y << 6),
	}
	d.DrawString(text)

	// 在图片中央也添加一个半透明的大水印
	centerText := text
	if len(centerText) > 20 {
		centerText = centerText[:20]
	}

	centerColor := color.RGBA{R: 200, G: 200, B: 200, A: 40}
	centerD := font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(centerColor),
		Face: face,
	}

	centerTextWidth := font.MeasureString(face, centerText).Round()
	centerX := (width - centerTextWidth) / 2
	centerY := height / 2

	centerD.Dot = fixed.Point26_6{
		X: fixed.Int26_6(centerX << 6),
		Y: fixed.Int26_6(centerY << 6),
	}
	centerD.DrawString(centerText)
}
