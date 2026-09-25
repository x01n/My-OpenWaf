package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"testing"
)

// TestApplyPoolRoundtrip 验证池化后的 compressResponseBody 在 gzip/deflate
// 交替调用下每轮输出都能被标准库解码器完整解回且逐字节一致。
func TestApplyPoolRoundtrip(t *testing.T) {
	for _, enc := range []responseEncoding{responseEncodingGzip, responseEncodingDeflate} {
		dec := func(in []byte) ([]byte, error) {
			if enc == responseEncodingGzip {
				r, err := gzip.NewReader(bytes.NewReader(in))
				if err != nil {
					return nil, err
				}
				defer r.Close()
				return io.ReadAll(r)
			}
			r, err := zlib.NewReader(bytes.NewReader(in))
			if err != nil {
				return nil, err
			}
			defer r.Close()
			return io.ReadAll(r)
		}
		for round := 0; round < 50; round++ {
			plain := nightCompressBenchBody(4096 + round*1024)
			got, err := compressResponseBody(plain, enc)
			if err != nil {
				t.Fatalf("%s round %d: %v", enc, round, err)
			}
			decoded, err := dec(got)
			if err != nil {
				t.Fatalf("%s round %d: decode: %v", enc, round, err)
			}
			if !bytes.Equal(decoded, plain) {
				t.Fatalf("%s round %d: decoded mismatch", enc, round)
			}
			if len(got) >= len(plain) {
				t.Fatalf("%s round %d: output not compressed", enc, round)
			}
		}
	}
}

// TestApplyPoolErrorPathReuse 覆盖 Close 失败分支后又复用同一池单元。
// gzip Writer 内部先攒 4KiB，Close 时才 flush 到下游；受控 writer 在
// 接受 N 字节后报错即可让 Close 失败（closeErr 分支），随后归还的
// 单元必须能被正常复用。
func TestApplyPoolErrorPathReuse(t *testing.T) {
	u := applyGzipUnitPool.Get().(*applyGzipUnit)

	// 写入量远小于 gzip 内部缓冲，Close 时 flush 才触达受控 writer。
	limited := &limitThenFailWriter{limit: 32}
	u.gz.Reset(limited)
	if _, err := u.gz.Write(nightCompressBenchBody(512)); err != nil {
		t.Fatalf("buffered write: %v", err)
	}
	if err := u.gz.Close(); err == nil {
		t.Fatal("close should fail after limit exceeded")
	}
	applyGzipUnitPool.Put(u)

	// 复用同一单元走正常路径（不做指针相等断言：两次 Get 之间
	// 若恰好发生一次 GC，sync.Pool 会合法地归还新对象，指针断言
	// 在整包 race 下偶发翻车；功能等价才是本测试的契约）。
	u2 := applyGzipUnitPool.Get().(*applyGzipUnit)
	u2.buf.Reset()
	u2.gz.Reset(u2.buf)
	plain := nightCompressBenchBody(32 << 10)
	if _, err := u2.gz.Write(plain); err != nil {
		t.Fatalf("reused write: %v", err)
	}
	if err := u2.gz.Close(); err != nil {
		t.Fatalf("reused close: %v", err)
	}
	out := append([]byte(nil), u2.buf.Bytes()...)
	applyGzipUnitPool.Put(u2)
	r, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	decoded, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, plain) {
		t.Fatal("reused unit output mismatch")
	}
}

// limitThenFailWriter 前 limit 字节正常接受，之后每次 Write 报错。
type limitThenFailWriter struct {
	written int
	limit   int
}

func (w *limitThenFailWriter) Write(p []byte) (int, error) {
	w.written += len(p)
	if w.written > w.limit {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}
