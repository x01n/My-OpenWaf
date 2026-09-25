package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"testing"

	kgzip "github.com/klauspost/compress/gzip"
)

var nightStreamCompressChunk = nightCompressBenchBody(32 << 10)

func nightRunStreamCompressWriter(b *testing.B, encoding responseEncoding) {
	b.ReportAllocs()
	b.SetBytes(int64(len(nightStreamCompressChunk)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w, closeComp := newStreamCompressWriter(io.Discard, encoding)
		if _, err := w.Write(nightStreamCompressChunk); err != nil {
			b.Fatal(err)
		}
		if fw, ok := w.(interface{ Flush() error }); ok {
			_ = fw.Flush()
		}
		closeComp()
	}
}

// nightRunStdGzipWriter 是同进程对照：模拟池化前的 std gzip 每请求构造路径。
func nightRunStdGzipWriter(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(int64(len(nightStreamCompressChunk)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gw, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
		_, _ = gw.Write(nightStreamCompressChunk)
		_ = gw.Flush()
		_ = gw.Close()
	}
}

// nightRunStdZlibWriter 是同进程对照：模拟池化前的 std zlib 每请求构造路径。
func nightRunStdZlibWriter(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(int64(len(nightStreamCompressChunk)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dw, _ := zlib.NewWriterLevel(io.Discard, zlib.BestSpeed)
		_, _ = dw.Write(nightStreamCompressChunk)
		_ = dw.Flush()
		_ = dw.Close()
	}
}

func BenchmarkNightStreamCompressWriterGzip(b *testing.B) {
	nightRunStreamCompressWriter(b, responseEncodingGzip)
}

func BenchmarkNightStreamCompressWriterDeflate(b *testing.B) {
	nightRunStreamCompressWriter(b, responseEncodingDeflate)
}

func BenchmarkNightStreamCompressWriterBrotli(b *testing.B) {
	nightRunStreamCompressWriter(b, responseEncodingBrotli)
}

func BenchmarkNightStreamCompressWriterZstd(b *testing.B) {
	nightRunStreamCompressWriter(b, responseEncodingZstd)
}

func BenchmarkNightStreamCompressWriterStdGzip(b *testing.B) {
	nightRunStdGzipWriter(b)
}

func BenchmarkNightStreamCompressWriterStdZlib(b *testing.B) {
	nightRunStdZlibWriter(b)
}

// TestNightStreamWriterPoolReuse 验证池化 writer 跨多次复用仍产出可解码输出。
//
// 每轮 GET → Reset(w) → Write → Flush → Close → PUT，连续 50 轮，
// 每轮输出必须能被标准库解码器完整解回，且 Contents 前后一致。
func TestNightStreamWriterPoolReuse(t *testing.T) {
	encodings := []struct {
		name      string
		encoding  responseEncoding
		roundtrip func([]byte) ([]byte, error)
	}{
		{"gzip", responseEncodingGzip, func(in []byte) ([]byte, error) {
			r, err := gzip.NewReader(bytes.NewReader(in))
			if err != nil {
				return nil, err
			}
			defer r.Close()
			return io.ReadAll(r)
		}},
		{"deflate", responseEncodingDeflate, func(in []byte) ([]byte, error) {
			r, err := zlib.NewReader(bytes.NewReader(in))
			if err != nil {
				return nil, err
			}
			defer r.Close()
			return io.ReadAll(r)
		}},
	}
	chunk := nightStreamCompressChunk
	for _, enc := range encodings {
		for round := 0; round < 50; round++ {
			var out bytes.Buffer
			w, closeComp := newStreamCompressWriter(&out, enc.encoding)
			if _, err := w.Write(chunk); err != nil {
				t.Fatalf("%s round %d: write: %v", enc.name, round, err)
			}
			if fw, ok := w.(interface{ Flush() error }); ok {
				_ = fw.Flush()
			}
			closeComp()

			decoded, err := enc.roundtrip(out.Bytes())
			if err != nil {
				t.Fatalf("%s round %d: decode: %v", enc.name, round, err)
			}
			if len(decoded) != len(chunk) {
				t.Fatalf("%s round %d: len %d != %d", enc.name, round, len(decoded), len(chunk))
			}
			for i := range chunk {
				if decoded[i] != chunk[i] {
					t.Fatalf("%s round %d: byte %d mismatch", enc.name, round, i)
				}
			}
			if len(out.Bytes()) >= len(chunk) {
				t.Fatalf("%s round %d: output len %d not compressed", enc.name, round, out.Len())
			}
		}
	}
}

// TestNightStreamWriterPoolClosureSafety 验证同 goroutine 内归还后下一轮 GET 会拿到复用对象而非新鲜对象。
func TestNightStreamWriterPoolClosureSafety(t *testing.T) {
	w1, c1 := newStreamCompressWriter(io.Discard, responseEncodingGzip)
	p1, _ := w1.(*kgzip.Writer)
	_, _ = w1.Write(nightStreamCompressChunk)
	c1()

	w2, c2 := newStreamCompressWriter(io.Discard, responseEncodingGzip)
	p2, _ := w2.(*kgzip.Writer)
	if p1 != p2 {
		t.Fatalf("pool did not reuse the returned writer (p1=%p p2=%p)", p1, p2)
	}
	_, _ = w2.Write(nightStreamCompressChunk)
	c2()
}
