package dynamic

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"strings"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

// addWatermark 为图片添加文字水印。
// 支持 PNG、JPEG、GIF 格式。
func addWatermark(imgData []byte, text string) ([]byte, error) {
	if len(imgData) == 0 {
		return imgData, nil
	}

	// 根据 magic bytes 判断图片格式
	format := detectImageFormat(imgData)
	if format == "" {
		// 无法识别格式，返回原图
		return imgData, nil
	}

	// 解码图片
	img, _, err := image.Decode(bytes.NewReader(imgData))
	if err != nil {
		return imgData, nil // 解码失败则返回原图
	}

	// 创建新画布（支持透明通道）
	bounds := img.Bounds()
	watermarked := image.NewRGBA(bounds)
	draw.Draw(watermarked, bounds, img, bounds.Min, draw.Src)

	// 添加水印文字
	addTextWatermark(watermarked, text)

	// 编码输出
	var buf bytes.Buffer
	switch format {
	case "png":
		err = png.Encode(&buf, watermarked)
	case "jpeg", "jpg":
		err = jpeg.Encode(&buf, watermarked, &jpeg.Options{Quality: 90})
	case "gif":
		// GIF 需要特殊处理，转为 PNG（GIF 不支持半透明文字）
		err = png.Encode(&buf, watermarked)
		if err == nil {
			return buf.Bytes(), nil
		}
		err = jpeg.Encode(&buf, watermarked, &jpeg.Options{Quality: 90})
	default:
		return imgData, nil
	}

	if err != nil {
		return imgData, nil
	}
	return buf.Bytes(), nil
}

// detectImageFormat 根据 magic bytes 检测图片格式。
func detectImageFormat(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	switch {
	case data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47:
		return "png"
	case data[0] == 0xFF && data[1] == 0xD8:
		return "jpeg"
	case data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46:
		return "gif"
	case data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46:
		// WebP (RIFF header)
		if len(data) >= 12 && data[8] == 0x57 && data[9] == 0x45 && data[10] == 0x42 && data[11] == 0x50 {
			return "webp"
		}
	}
	return ""
}

// addTextWatermark 在图片上添加文字水印。
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

// formatFromContentType 从 Content-Type 推断图片格式。
func formatFromContentType(ct string) string {
	ct = strings.ToLower(strings.TrimSpace(ct))
	switch {
	case strings.Contains(ct, "image/png"):
		return "png"
	case strings.Contains(ct, "image/jpeg") || strings.Contains(ct, "image/jpg"):
		return "jpeg"
	case strings.Contains(ct, "image/gif"):
		return "gif"
	case strings.Contains(ct, "image/webp"):
		return "webp"
	}
	return ""
}
