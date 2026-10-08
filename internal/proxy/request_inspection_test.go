package proxy

import (
	"bytes"
	"testing"
)

/**
 * DecodeRequestBodyBytesForInspection 是数据面 WAF 采样使用的解压入口，
 * 本文件锁定它的对外契约：支持集、产出上限、不完整压缩体的降级语义。
 */
func TestDecodeRequestBodyBytesForInspectionContract(t *testing.T) {
	payload := []byte(`{"note":"<script>alert(1)</script>"}`)

	t.Run("未压缩与空编码直接透传", func(t *testing.T) {
		got, didDecode, truncated := DecodeRequestBodyBytesForInspection(payload, nil, 1024)
		if didDecode || truncated {
			t.Fatalf("didDecode=%v truncated=%v, want false/false", didDecode, truncated)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("decoded = %q, want %q", got, payload)
		}
	})

	t.Run("不支持的编码不进入解压路径", func(t *testing.T) {
		got, didDecode, truncated := DecodeRequestBodyBytesForInspection(payload, []byte("koi8-r"), 1024)
		if didDecode || truncated {
			t.Fatalf("didDecode=%v truncated=%v, want false/false", didDecode, truncated)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("unsupported encoding must return the input untouched")
		}
	})

	t.Run("支持的编码解出明文", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			encoding string
			encoded  []byte
		}{
			{name: "gzip", encoding: "gzip", encoded: mustGzipBytes(t, payload)},
			{name: "x-gzip", encoding: "x-gzip", encoded: mustGzipBytes(t, payload)},
			{name: "deflate", encoding: "deflate", encoded: mustDeflateBytes(t, payload)},
			{name: "br", encoding: "br", encoded: mustBrotliBytes(t, payload)},
			{name: "zstd", encoding: "zstd", encoded: mustZstdBytes(t, payload)},
		} {
			got, didDecode, truncated := DecodeRequestBodyBytesForInspection(tc.encoded, []byte(tc.encoding), 1024)
			if !didDecode {
				t.Fatalf("%s: didDecode = false", tc.name)
			}
			if truncated {
				t.Fatalf("%s: unexpectedly truncated", tc.name)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("%s: decoded = %q, want %q", tc.name, got, payload)
			}
		}
	})

	t.Run("产出上限截断并标记", func(t *testing.T) {
		plain := bytes.Repeat([]byte("A"), 4096)
		encoded := mustGzipBytes(t, plain)
		got, didDecode, truncated := DecodeRequestBodyBytesForInspection(encoded, []byte("gzip"), 512)
		if !didDecode || !truncated {
			t.Fatalf("didDecode=%v truncated=%v, want true/true", didDecode, truncated)
		}
		if len(got) != 512 {
			t.Fatalf("decoded length = %d, want 512", len(got))
		}
	})

	t.Run("压缩体不完整时保留已解出的明文", func(t *testing.T) {
		plain := bytes.Repeat([]byte("A"), 4096)
		encoded := mustGzipBytes(t, plain)
		got, didDecode, truncated := DecodeRequestBodyBytesForInspection(encoded[:len(encoded)-8], []byte("gzip"), 4096)
		if !didDecode {
			t.Fatal("didDecode = false, want true for a truncated gzip stream")
		}
		if !truncated {
			t.Fatal("truncated = false, want true for an incomplete compressed body")
		}
		if len(got) == 0 {
			t.Fatal("plaintext decoded before the truncation point must be preserved")
		}
		if !bytes.Equal(got, plain[:len(got)]) {
			t.Fatal("decoded prefix does not match the plaintext")
		}
	})

	t.Run("声明 gzip 而无魔数时回退到未压缩", func(t *testing.T) {
		got, didDecode, truncated := DecodeRequestBodyBytesForInspection(payload, []byte("gzip"), 1024)
		if didDecode || truncated {
			t.Fatalf("didDecode=%v truncated=%v, want false/false", didDecode, truncated)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("failed decoder construction must return the input untouched")
		}
	})
}
