package adminweb

import (
	"bytes"
	"compress/gzip"
	"strings"
	"sync"
)

/** 压缩收益阈值：小于该体积的资源压缩后收益不足，直接下发原文。 */
const gzipMinSize = 1024

/** cache-control 值：带内容哈希的构建产物可长期缓存。 */
const immutableCacheControl = "public,max-age=31536000,immutable"

/**
 * 可压缩类型判定。
 *
 * 只对文本类资源压缩：JPEG/PNG/WOFF2 本身已压缩，重复压缩纯粹浪费 CPU。
 */
func isCompressible(name string) bool {
	switch {
	case strings.HasSuffix(name, ".js"), strings.HasSuffix(name, ".mjs"):
		return true
	case strings.HasSuffix(name, ".css"):
		return true
	case strings.HasSuffix(name, ".html"):
		return true
	case strings.HasSuffix(name, ".json"), strings.HasSuffix(name, ".txt"):
		return true
	case strings.HasSuffix(name, ".svg"), strings.HasSuffix(name, ".map"):
		return true
	default:
		return false
	}
}

/**
 * 内容哈希资源判定。
 *
 * Next.js 导出把内容哈希编入 `_next/static/` 下的文件名，因此该目录可安全
 * 使用 immutable 缓存；路由 HTML 与 RSC 数据每次可能变化，必须每次回源校验。
 */
func isImmutableAsset(name string) bool {
	return strings.HasPrefix(name, "_next/static/")
}

/**
 * 静态资源压缩缓存。
 *
 * 构建产物在一份进程内不可变，因此 gzip 结果按资源名缓存一次即可；
 * 用 sync.Map 而非加锁 map，让并发首访不同资源互不阻塞。
 */
var gzipCache sync.Map // map[string][]byte

/** gzipCompress 以 BestCompression 压缩数据，与 PoW 资产的处理保持一致。 */
func gzipCompress(data []byte) []byte {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil
	}
	if _, err := w.Write(data); err != nil {
		return nil
	}
	if err := w.Close(); err != nil {
		return nil
	}
	return buf.Bytes()
}

/**
 * CompressedBody 返回资源可下发的字节与对应 Content-Encoding。
 *
 * 传入的 name 是 FS 内的已解析路径（判断缓存与压缩策略都用它）；
 * 返回空 encoding 表示按原文下发。压缩失败时回退原文，保证功能不退化。
 */
func CompressedBody(name string, data []byte) (body []byte, encoding string) {
	if !isCompressible(name) || len(data) < gzipMinSize {
		return data, ""
	}
	if cached, ok := gzipCache.Load(name); ok {
		if packed, typeOK := cached.([]byte); typeOK {
			return packed, "gzip"
		}
	}
	packed := gzipCompress(data)
	if packed == nil {
		return data, ""
	}
	gzipCache.Store(name, packed)
	return packed, "gzip"
}

/** CacheControl 返回静态资源的缓存策略。 */
func CacheControl(name string) string {
	if isImmutableAsset(name) {
		return immutableCacheControl
	}
	return "no-cache"
}