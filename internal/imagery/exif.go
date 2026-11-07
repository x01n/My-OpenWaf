package imagery

import (
	"encoding/binary"
)

// applyOrientation 按 EXIF Orientation 把像素旋转/镜像到正确朝向。
//
// 只实现「无损朝向修正」所需的 8 个取值，不做任意角度插值：
//
//	1 不处理   2 水平镜像   3 旋转 180°   4 垂直镜像
//	5 转置     6 旋转 90°   7 转置+180°   8 旋转 270°
//
// 其中「顺时针旋转」的语义与 rotate 参数一致，便于两者共用。
//
// @param img 输入像素。
// @param orientation EXIF Orientation 值（1-8）。
// @return 朝向修正后的像素；orientation 不在 2-8 时原样返回 img。
func applyOrientation(img imageLike, orientation int) imageLike {
	if img == nil || orientation <= 1 || orientation > 8 {
		return img
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= 0 || h <= 0 {
		return img
	}

	// 5-8 会交换宽高。
	swap := orientation >= 5
	dstW, dstH := w, h
	if swap {
		dstW, dstH = h, w
	}
	dst := newRGBA(dstW, dstH)

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var dx, dy int
			switch orientation {
			case 2:
				dx, dy = w-1-x, y
			case 3:
				dx, dy = w-1-x, h-1-y
			case 4:
				dx, dy = x, h-1-y
			case 5:
				dx, dy = y, x
			case 6:
				dx, dy = h-1-y, x
			case 7:
				dx, dy = h-1-y, w-1-x
			case 8:
				dx, dy = y, w-1-x
			default:
				dx, dy = x, y
			}
			dst.Set(dx, dy, img.At(b.Min.X+x, b.Min.Y+y))
		}
	}
	return dst
}

// exifOrientation 从图片字节中解析 EXIF Orientation。
//
// 支持三种容器布局：
//
//   - JPEG：APP1 段（0xFFE1）内的 "Exif\x00\x00" + TIFF 头；
//   - WebP：RIFF 顶层 "EXIF" chunk 内的 TIFF 头；
//   - PNG：eXIf chunk 内的 TIFF 头。
//
// 只读取第一个 IFD 的 0x0112 标签，不遍历其余 IFD，避免为朝向解析引入完整
// EXIF 依赖。任何结构异常都返回 0，由调用方按「无朝向信息」处理。
//
// @param data 图片原始字节。
// @return EXIF Orientation（1-8）；不存在或解析失败时为 0。
func exifOrientation(data []byte) int {
	tiff := findTIFFHeader(data)
	if tiff == nil {
		return 0
	}
	return readOrientationTag(tiff)
}

// findTIFFHeader 定位 EXIF 中 TIFF 头的起点。
//
// @param data 图片原始字节。
// @return TIFF 头切片（不含自身偏移语义之外的拷贝）；未找到时为 nil。
func findTIFFHeader(data []byte) []byte {
	if len(data) < 12 {
		return nil
	}
	switch {
	case data[0] == 0xFF && data[1] == 0xD8:
		return findJPEGExif(data)
	case string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return findWebPChunk(data, "EXIF")
	case data[0] == 0x89 && string(data[1:4]) == "PNG":
		return findPNGChunk(data, "eXIf")
	default:
		return nil
	}
}

// findJPEGExif 在 JPEG 段链中查找 APP1/Exif 段并返回其 TIFF 头。
//
// @param data JPEG 字节。
// @return TIFF 头；未找到时为 nil。
func findJPEGExif(data []byte) []byte {
	pos := 2
	for pos+4 <= len(data) {
		if data[pos] != 0xFF {
			return nil
		}
		marker := data[pos+1]
		// 填充字节：连续 0xFF 时继续前进。
		if marker == 0xFF {
			pos++
			continue
		}
		// 无长度字段的独立标记。
		if marker == 0x01 || (marker >= 0xD0 && marker <= 0xD9) {
			pos += 2
			continue
		}
		segLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		if segLen < 2 || pos+2+segLen > len(data) {
			return nil
		}
		if marker == 0xE1 {
			seg := data[pos+4 : pos+2+segLen]
			const prefix = "Exif\x00\x00"
			if len(seg) >= len(prefix) && string(seg[:len(prefix)]) == prefix {
				return seg[len(prefix):]
			}
		}
		// SOS（0xDA）之后是熵编码数据，不再有段结构。
		if marker == 0xDA {
			return nil
		}
		pos += 2 + segLen
	}
	return nil
}

// findWebPChunk 返回 RIFF 顶层指定 chunk 的内容。
//
// @param data WebP 字节。
// @param fourCC 目标 chunk 标识。
// @return chunk 内容；未找到时为 nil。
func findWebPChunk(data []byte, fourCC string) []byte {
	pos := 12
	for pos+8 <= len(data) {
		cc := string(data[pos : pos+4])
		size := int(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
		if size < 0 || pos+8+size > len(data) {
			return nil
		}
		if cc == fourCC {
			return data[pos+8 : pos+8+size]
		}
		pos += 8 + size
		if size%2 == 1 {
			pos++
		}
	}
	return nil
}

// findPNGChunk 返回 PNG 中指定 chunk 的内容。
//
// @param data PNG 字节。
// @param chunkType 目标 chunk 类型（4 字节 ASCII）。
// @return chunk 内容；未找到时为 nil。
func findPNGChunk(data []byte, chunkType string) []byte {
	pos := 8 // PNG signature
	for pos+12 <= len(data) {
		size := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		if size < 0 || pos+12+size > len(data) {
			return nil
		}
		if string(data[pos+4:pos+8]) == chunkType {
			return data[pos+8 : pos+8+size]
		}
		pos += 12 + size
	}
	return nil
}

// readOrientationTag 从 TIFF 头中读出第一个 IFD 的 Orientation 标签值。
//
// @param tiff TIFF 头起始处（"II"/"MM" 字节序标记）。
// @return Orientation（1-8）；不存在时为 0。
func readOrientationTag(tiff []byte) int {
	if len(tiff) < 8 {
		return 0
	}
	var order binary.ByteOrder
	switch string(tiff[0:2]) {
	case "II":
		order = binary.LittleEndian
	case "MM":
		order = binary.BigEndian
	default:
		return 0
	}
	if order.Uint16(tiff[2:4]) != 42 {
		return 0
	}
	ifdOffset := int(order.Uint32(tiff[4:8]))
	if ifdOffset < 8 || ifdOffset+2 > len(tiff) {
		return 0
	}
	count := int(order.Uint16(tiff[ifdOffset : ifdOffset+2]))
	entry := ifdOffset + 2
	for i := 0; i < count; i++ {
		if entry+12 > len(tiff) {
			return 0
		}
		tag := order.Uint16(tiff[entry : entry+2])
		if tag == 0x0112 {
			typ := order.Uint16(tiff[entry+2 : entry+4])
			// Orientation 的 TIFF 类型应为 SHORT(3)，值内联在 4 字节字段的前 2 字节。
			if typ != 3 {
				return 0
			}
			value := int(order.Uint16(tiff[entry+8 : entry+10]))
			if value >= 1 && value <= 8 {
				return value
			}
			return 0
		}
		entry += 12
	}
	return 0
}
