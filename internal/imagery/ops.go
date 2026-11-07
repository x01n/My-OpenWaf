package imagery

import (
	"image"
	"image/color"
	"image/draw"

	xdraw "golang.org/x/image/draw"
)

// imageLike 是本次变换流水线使用的像素类型占位别名。
//
// 统一用 *image.RGBA（而非 image.Image 接口）承载中间结果，理由是后续每个
// 操作都要逐像素读写，接口的 At/Set 抽象会带来可观的接口调用开销。
type imageLike = *image.RGBA

// newRGBA 分配一张 RGBA 画布。
//
// @param w、h 目标尺寸。
// @return 归零边界的 RGBA 画布；尺寸非正时返回 1x1 空画布。
func newRGBA(w, h int) *image.RGBA {
	if w <= 0 || h <= 0 {
		return image.NewRGBA(image.Rect(0, 0, 1, 1))
	}
	return image.NewRGBA(image.Rect(0, 0, w, h))
}

// toRGBA 把任意 image.Image 拷贝成归零边界的 *image.RGBA。
//
// @param src 输入像素。
// @return RGBA 副本。
func toRGBA(src image.Image) *image.RGBA {
	if src == nil {
		return newRGBA(1, 1)
	}
	if rgba, ok := src.(*image.RGBA); ok && rgba.Bounds().Min == (image.Point{}) {
		return rgba
	}
	b := src.Bounds()
	if b.Dx() <= 0 || b.Dy() <= 0 {
		return newRGBA(1, 1)
	}
	dst := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(dst, dst.Bounds(), src, b.Min, draw.Src)
	return dst
}

// Resize 按目标宽高缩放。
//
// 语义与 ESA 的 resize 参数对齐：**只缩小，不放大**。任一目标尺寸大于原图时
// 该维度按原图取值；两个目标都为空（0）时不缩放。
//
// 缩放算法用 CatmullRom：对缩小场景的细节保留优于双线性，代价是可接受的
// 单次开销（图像转换本身已按并发闸门限流）。
//
// @param src 输入像素。
// @param targetW 目标宽度（<=0 表示不约束）。
// @param targetH 目标高度（<=0 表示不约束）。
// @return 缩放后的像素。
func Resize(src imageLike, targetW, targetH int) imageLike {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= 0 || h <= 0 {
		return src
	}
	if targetW <= 0 && targetH <= 0 {
		return src
	}

	dw, dh := w, h
	if targetW > 0 {
		dw = targetW
	}
	if targetH > 0 {
		dh = targetH
	}
	// 只缩不放：超过原图的维度回退到原图尺寸。
	if dw > w {
		dw = w
	}
	if dh > h {
		dh = h
	}
	if dw == w && dh == h {
		return src
	}

	dst := newRGBA(dw, dh)
	xdraw.CatmullRom.Scale(dst, dst.Bounds(), src, b, draw.Over, nil)
	return dst
}

// ResizeByLongSide 按最长边等比缩放。
//
// @param src 输入像素。
// @param target 目标最长边（<=0 时不缩放）。
// @return 缩放后的像素。
func ResizeByLongSide(src imageLike, target int) imageLike {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if target <= 0 || w <= 0 || h <= 0 {
		return src
	}
	long := w
	if h > long {
		long = h
	}
	if target >= long {
		return src
	}
	return scaleToLong(src, target, long, w, h)
}

// ResizeByShortSide 按最短边等比缩放。
//
// @param src 输入像素。
// @param target 目标最短边（<=0 时不缩放）。
// @return 缩放后的像素。
func ResizeByShortSide(src imageLike, target int) imageLike {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if target <= 0 || w <= 0 || h <= 0 {
		return src
	}
	short := w
	if h < short {
		short = h
	}
	if target >= short {
		return src
	}
	return scaleToLong(src, target, short, w, h)
}

// scaleToLong 按「驱动边 : 当前值」的同一比例缩放。
//
// @param src 输入像素。
// @param target 驱动边的目标长度。
// @param current 驱动边的当前长度。
// @param w、h 原图宽高。
// @return 缩放后的像素。
func scaleToLong(src imageLike, target, current, w, h int) imageLike {
	dw := w * target / current
	dh := h * target / current
	if dw < 1 {
		dw = 1
	}
	if dh < 1 {
		dh = 1
	}
	dst := newRGBA(dw, dh)
	xdraw.CatmullRom.Scale(dst, dst.Bounds(), src, src.Bounds(), draw.Over, nil)
	return dst
}

// Crop 按矩形裁剪。
//
// 矩形的原点与尺寸都会被钳制到原图范围内：越界不报错，而是取交集，
// 避免畸形参数直接把请求打成失败。
//
// @param src 输入像素。
// @param r 裁剪矩形（以 src.Bounds().Min 为参照的绝对坐标）。
// @return 裁剪后的像素；矩形与原图无交集时返回原图。
func Crop(src imageLike, r image.Rectangle) imageLike {
	b := src.Bounds()
	inter := r.Intersect(b)
	if inter.Dx() <= 0 || inter.Dy() <= 0 {
		return src
	}
	if inter == b {
		return src
	}
	dst := newRGBA(inter.Dx(), inter.Dy())
	draw.Draw(dst, dst.Bounds(), src, inter.Min, draw.Src)
	return dst
}

// CropCenter 从中心裁剪指定宽高。
//
// @param src 输入像素。
// @param w、h 目标宽高（<=0 时该维度取原图长度）。
// @return 裁剪后的像素。
func CropCenter(src imageLike, w, h int) imageLike {
	b := src.Bounds()
	bw, bh := b.Dx(), b.Dy()
	if w <= 0 || w > bw {
		w = bw
	}
	if h <= 0 || h > bh {
		h = bh
	}
	x := b.Min.X + (bw-w)/2
	y := b.Min.Y + (bh-h)/2
	return Crop(src, image.Rect(x, y, x+w, y+h))
}

// Rotate 顺时针旋转 90° 的整数倍。
//
// 只接受 0/90/180/270（对 360 取模）；其余角度原样返回，不做插值旋转——
// ESA 的 rotate 参数同样只支持这三档。
//
// @param src 输入像素。
// @param degrees 顺时针角度。
// @return 旋转后的像素。
func Rotate(src imageLike, degrees int) imageLike {
	deg := ((degrees % 360) + 360) % 360
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= 0 || h <= 0 {
		return src
	}
	switch deg {
	case 90:
		dst := newRGBA(h, w)
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				dst.Set(h-1-y, x, src.At(b.Min.X+x, b.Min.Y+y))
			}
		}
		return dst
	case 180:
		dst := newRGBA(w, h)
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				dst.Set(w-1-x, h-1-y, src.At(b.Min.X+x, b.Min.Y+y))
			}
		}
		return dst
	case 270:
		dst := newRGBA(h, w)
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				dst.Set(y, w-1-x, src.At(b.Min.X+x, b.Min.Y+y))
			}
		}
		return dst
	default:
		return src
	}
}

// AdjustBrightness 调整亮度。
//
// amount 取 [-100, 100]，与 ESA bright 参数同区间：正值提亮、负值压暗、0 不变。
// 变换按线性偏移实现（映射到 [-255, 255]），保持黑点/白点的单调性。
//
// @param src 输入像素。
// @param amount 亮度增量。
// @return 调整后的像素；amount 为 0 时返回原像素。
func AdjustBrightness(src imageLike, amount int) imageLike {
	if amount == 0 {
		return src
	}
	if amount > 100 {
		amount = 100
	}
	if amount < -100 {
		amount = -100
	}
	shift := amount * 255 / 100
	return mapPixels(src, func(r, g, b, a uint8) (uint8, uint8, uint8) {
		return clamp8(int(r) + shift), clamp8(int(g) + shift), clamp8(int(b) + shift)
	})
}

// AdjustContrast 调整对比度。
//
// amount 取 [-100, 100]，与 ESA contrast 参数同区间。以 128 为中心按比例
// 拉伸/压缩：amount=100 时增益 2.0，amount=-100 时增益 0（全图变中灰）。
//
// @param src 输入像素。
// @param amount 对比度增量。
// @return 调整后的像素；amount 为 0 时返回原像素。
func AdjustContrast(src imageLike, amount int) imageLike {
	if amount == 0 {
		return src
	}
	if amount > 100 {
		amount = 100
	}
	if amount < -100 {
		amount = -100
	}
	// gain = 1 + amount/100（amount=100 → 2.0；amount=-100 → 0.0）
	gain := 1 + float64(amount)/100
	return mapPixels(src, func(r, g, b, a uint8) (uint8, uint8, uint8) {
		return contrastChannel(r, gain), contrastChannel(g, gain), contrastChannel(b, gain)
	})
}

// contrastChannel 对单通道施加对比度增益。
//
// @param v 输入通道值。
// @param gain 增益系数。
// @return 调整后的通道值。
func contrastChannel(v uint8, gain float64) uint8 {
	centered := float64(v) - 128
	return clamp8(int(centered*gain + 128 + 0.5))
}

// Sharpen 锐化。
//
// amount 取 [50, 399]（与 ESA sharpen 参数同区间），内部映射到 [0, 1] 的
// 强度系数。实现为 3x3 反锐化掩模：中心加强、四邻削弱，边界像素原样保留。
//
// @param src 输入像素。
// @param amount 锐化强度。
// @return 锐化后的像素。
func Sharpen(src imageLike, amount int) imageLike {
	if amount <= 0 {
		return src
	}
	if amount < 50 {
		amount = 50
	}
	if amount > 399 {
		amount = 399
	}
	strength := float64(amount) / 399

	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w < 3 || h < 3 {
		return src
	}
	dst := newRGBA(w, h)
	// 先整体拷贝，再只对内部像素重算——边界不参与卷积，保持原值。
	copy(dst.Pix, src.Pix)

	// 反锐化掩模：out = center*(1+4k) - (up+down+left+right)*k
	center := 1 + 4*strength
	for y := 1; y < h-1; y++ {
		row := y * dst.Stride
		for x := 1; x < w-1; x++ {
			i := row + x*4
			for c := 0; c < 3; c++ {
				cv := float64(src.Pix[i+c])
				nv := float64(src.Pix[i-4+c]) + float64(src.Pix[i+4+c]) +
					float64(src.Pix[i-dst.Stride+c]) + float64(src.Pix[i+dst.Stride+c])
				v := cv*center - nv*strength
				dst.Pix[i+c] = clamp8(int(v + 0.5))
			}
		}
	}
	return dst
}

// mapPixels 对每像素的 RGB 施加同一映射，Alpha 保持不变。
//
// @param src 输入像素。
// @param fn 通道映射函数。
// @return 映射后的像素。
func mapPixels(src imageLike, fn func(r, g, b, a uint8) (uint8, uint8, uint8)) imageLike {
	b := src.Bounds()
	dst := newRGBA(b.Dx(), b.Dy())
	for y := 0; y < b.Dy(); y++ {
		sRow := y * src.Stride
		dRow := y * dst.Stride
		for x := 0; x < b.Dx(); x++ {
			si := sRow + x*4
			di := dRow + x*4
			r, g, bl := fn(src.Pix[si], src.Pix[si+1], src.Pix[si+2], src.Pix[si+3])
			dst.Pix[di] = r
			dst.Pix[di+1] = g
			dst.Pix[di+2] = bl
			dst.Pix[di+3] = src.Pix[si+3]
		}
	}
	return dst
}

// clamp8 把整数钳制到 uint8 值域。
//
// @param v 输入值。
// @return [0, 255] 范围内的 uint8。
func clamp8(v int) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}

// 编译期断言：RGBA 与 RGBAModel 的接口实现关系（供像素运算的静态检查）。
var (
	_ image.Image = (*image.RGBA)(nil)
	_ color.Model = color.RGBAModel
)
