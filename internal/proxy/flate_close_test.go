package proxy

import (
	"bytes"
	"compress/flate"
	"io"
	"testing"
)

// TestRawDeflateDecoderClosePairing 锁定 newContentDecoderReader 裸 deflate
// 探测回退分支的 reader/closer 成对性：
//   - closer 必须非 nil，保证 upstreamResponseReader 会把它并入 closers、
//     closeFn 会执行 closeContentDecoderClosers；
//   - Close 是纯状态回放（std inflate.decompressor.Close 只回放 f.err），
//     不会触碰已包装的底层 reader（zlib 同款文档语义）。
func TestRawDeflateDecoderClosePairing(t *testing.T) {
	raw, err := rawDeflateTestData(64 << 10)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("pairing", func(t *testing.T) {
		r, closer, used, err := newContentDecoderReader(bytes.NewReader(raw), "deflate")
		if err != nil {
			t.Fatal(err)
		}
		if !used {
			t.Fatal("deflate should be decoded")
		}
		if closer == nil {
			t.Fatal("raw deflate branch must return a non-nil closer")
		}
		_ = r
	})

	t.Run("unconsumed-close-is-nil", func(t *testing.T) {
		_, closer, _, err := newContentDecoderReader(bytes.NewReader(raw), "deflate")
		if err != nil {
			t.Fatal(err)
		}
		// 从未 Read：flate 解压器 f.err 仍为零值，Close 按 std 语义
		// 只回放状态、不主动读流（inflate.decompressor.Close 三行
		// 实现），此处应当返回 nil。
		if closeErr := closer.Close(); closeErr != nil {
			t.Fatalf("close before consume: got %v, want nil", closeErr)
		}
	})

	t.Run("consumed-close-is-nil", func(t *testing.T) {
		plain := rawDeflateBenchBody(64 << 10)
		r, closer, _, err := newContentDecoderReader(bytes.NewReader(raw), "deflate")
		if err != nil {
			t.Fatal(err)
		}
		got, readErr := io.ReadAll(r)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(got, plain) {
			t.Fatal("decoded plaintext mismatch")
		}
		if closeErr := closer.Close(); closeErr != nil {
			t.Fatalf("close after full consume: %v", closeErr)
		}
	})
}

// rawDeflateBenchBody 生成确定性的可压缩文本，与压缩基准同构，
// 保证压缩比稳定且首两字节判定为裸 flate 而非 zlib 流。
func rawDeflateBenchBody(size int) []byte {
	const unit = `<html><body><h1>My-OpenWaf benchmark page</h1><table><tr><td class="cell">row 000000 item alpha beta gamma delta epsilon</td></tr></table></body></html>`
	buf := make([]byte, 0, size)
	for len(buf) < size {
		buf = append(buf, unit...)
	}
	return buf[:size]
}

// rawDeflateTestData 生成裸 deflate 流（RFC 1951：无 zlib 头、无
// Adler-32），专供探测回退分支使用。
func rawDeflateTestData(size int) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(rawDeflateBenchBody(size)); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
