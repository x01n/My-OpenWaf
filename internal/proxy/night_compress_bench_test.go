package proxy

import (
	"bytes"
	stdg "compress/gzip"
	stdz "compress/zlib"
	"testing"

	kfl "github.com/klauspost/compress/flate"
	kgz "github.com/klauspost/compress/gzip"
	kzl "github.com/klauspost/compress/zlib"
)

// nightCompressBenchBody 生成确定性的可压缩文本，保证 A/B 两侧压缩比一致。
func nightCompressBenchBody(size int) []byte {
	const unit = `<html><body><h1>My-OpenWaf benchmark page</h1><table><tr><td class="cell">row 000000 item alpha beta gamma delta epsilon</td></tr></table></body></html>`
	buf := make([]byte, 0, size)
	for len(buf) < size {
		buf = append(buf, unit...)
	}
	return buf[:size]
}

func nightCompressStdGzip(b *testing.B, body []byte) {
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w, _ := stdg.NewWriterLevel(&buf, stdg.BestSpeed)
		_, _ = w.Write(body)
		_ = w.Close()
		if buf.Len() == 0 {
			b.Fatal("empty output")
		}
	}
}

func nightCompressKlausGzip(b *testing.B, body []byte) {
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w, _ := kgz.NewWriterLevel(&buf, kgz.BestSpeed)
		_, _ = w.Write(body)
		_ = w.Close()
		if buf.Len() == 0 {
			b.Fatal("empty output")
		}
	}
}

func nightCompressStdZlib(b *testing.B, body []byte) {
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w, _ := stdz.NewWriterLevel(&buf, stdz.BestSpeed)
		_, _ = w.Write(body)
		_ = w.Close()
		if buf.Len() == 0 {
			b.Fatal("empty output")
		}
	}
}

func nightCompressKlausZlib(b *testing.B, body []byte) {
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w, _ := kzl.NewWriterLevel(&buf, kzl.BestSpeed)
		_, _ = w.Write(body)
		_ = w.Close()
		if buf.Len() == 0 {
			b.Fatal("empty output")
		}
	}
}

func BenchmarkNightCompressGzipStdSmall(b *testing.B) {
	nightCompressStdGzip(b, nightCompressBenchBody(4<<10))
}
func BenchmarkNightCompressGzipKlausSmall(b *testing.B) {
	nightCompressKlausGzip(b, nightCompressBenchBody(4<<10))
}
func BenchmarkNightCompressZlibStdSmall(b *testing.B) {
	nightCompressStdZlib(b, nightCompressBenchBody(4<<10))
}
func BenchmarkNightCompressZlibKlausSmall(b *testing.B) {
	nightCompressKlausZlib(b, nightCompressBenchBody(4<<10))
}

func BenchmarkNightCompressGzipStdMedium(b *testing.B) {
	nightCompressStdGzip(b, nightCompressBenchBody(64<<10))
}
func BenchmarkNightCompressGzipKlausMedium(b *testing.B) {
	nightCompressKlausGzip(b, nightCompressBenchBody(64<<10))
}
func BenchmarkNightCompressZlibStdMedium(b *testing.B) {
	nightCompressStdZlib(b, nightCompressBenchBody(64<<10))
}
func BenchmarkNightCompressZlibKlausMedium(b *testing.B) {
	nightCompressKlausZlib(b, nightCompressBenchBody(64<<10))
}

func BenchmarkNightCompressGzipStdLarge(b *testing.B) {
	nightCompressStdGzip(b, nightCompressBenchBody(512<<10))
}
func BenchmarkNightCompressGzipKlausLarge(b *testing.B) {
	nightCompressKlausGzip(b, nightCompressBenchBody(512<<10))
}
func BenchmarkNightCompressZlibStdLarge(b *testing.B) {
	nightCompressStdZlib(b, nightCompressBenchBody(512<<10))
}
func BenchmarkNightCompressZlibKlausLarge(b *testing.B) {
	nightCompressKlausZlib(b, nightCompressBenchBody(512<<10))
}

// 生产路径入口（当前实现，替换后会被复用为回归对照）。
func BenchmarkNightCompressResponseBodyGzipSmall(b *testing.B) {
	body := nightCompressBenchBody(4 << 10)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := compressResponseBody(body, responseEncodingGzip); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNightCompressResponseBodyDeflateMedium(b *testing.B) {
	body := nightCompressBenchBody(64 << 10)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := compressResponseBody(body, responseEncodingDeflate); err != nil {
			b.Fatal(err)
		}
	}
}

// 静态资产一次性压缩（PoW WASM 同款 209KB 载荷，BestCompression 即第 9 级）。
func BenchmarkNightCompressStaticAssetStdBestCompression(b *testing.B) {
	body := nightCompressBenchBody(209 << 10)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w, _ := stdg.NewWriterLevel(&buf, stdg.BestCompression)
		_, _ = w.Write(body)
		_ = w.Close()
		if buf.Len() == 0 {
			b.Fatal("empty output")
		}
	}
}

func BenchmarkNightCompressStaticAssetKlausGzipBest(b *testing.B) {
	body := nightCompressBenchBody(209 << 10)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w, _ := kgz.NewWriterLevel(&buf, kgz.BestCompression)
		_, _ = w.Write(body)
		_ = w.Close()
		if buf.Len() == 0 {
			b.Fatal("empty output")
		}
	}
}

func BenchmarkNightCompressStaticAssetKlausFlate9(b *testing.B) {
	body := nightCompressBenchBody(209 << 10)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w, _ := kfl.NewWriter(&buf, 9)
		_, _ = w.Write(body)
		_ = w.Close()
		if buf.Len() == 0 {
			b.Fatal("empty output")
		}
	}
}
