package dataplane

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeReadConn 是可被 FixURIConn 包裹的最小 net.Conn 桩：Read 返回固定字节，
// 其余接口方法为空实现。
type fakeReadConn struct {
	data []byte
	off  int
}

func (c *fakeReadConn) Read(b []byte) (int, error) {
	if c.off >= len(c.data) {
		return 0, io.EOF
	}
	n := copy(b, c.data[c.off:])
	c.off += n
	return n, nil
}

func (c *fakeReadConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *fakeReadConn) Close() error                { return nil }
func (c *fakeReadConn) LocalAddr() net.Addr         { return nil }
func (c *fakeReadConn) RemoteAddr() net.Addr        { return nil }
func (c *fakeReadConn) SetDeadline(t time.Time) error {
	return nil
}
func (c *fakeReadConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (c *fakeReadConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// readAllFixed 用 FixURIConn 读出桩连接的全部字节。
func readAllFixed(c net.Conn) string {
	var sb strings.Builder
	buf := make([]byte, 256)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
		if sb.Len() > 8192 {
			break
		}
	}
	return sb.String()
}

/**
 * TestFixURIConnInsertsLeadingSlashForAbsoluteForm 锁定 absolute-form 请求行的
 * 字节层改写：请求行第二 token 以 scheme:// 开头（不以 '/' 或 '*' 开头）时，
 * FixURIConn 在 method 后插入一个 '/'，使 WAF 侧的 path 变成 "/http://host/path"。
 * 这是数据修正路径的既成事实：判据必须在 WAF 侧以 "/scheme://" 形态判别。
 */
func TestFixURIConnInsertsLeadingSlashForAbsoluteForm(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "absolute-form http",
			raw:  "GET http://gfs270n447.userstorage.mega.co.nz/dl/abc/0-0 HTTP/1.1\r\nHost: gfs270n447.userstorage.mega.co.nz\r\nUser-Agent: probe\r\n\r\n",
			want: "GET /http://gfs270n447.userstorage.mega.co.nz/dl/abc/0-0 HTTP/1.1\r\nHost: gfs270n447.userstorage.mega.co.nz\r\nUser-Agent: probe\r\n\r\n",
		},
		{
			name: "absolute-form https",
			raw:  "GET https://query.cleaning/v4/headers.php HTTP/1.1\r\nHost: query.cleaning\r\n\r\n",
			want: "GET /https://query.cleaning/v4/headers.php HTTP/1.1\r\nHost: query.cleaning\r\n\r\n",
		},
		{
			name: "absolute-form with port and root",
			raw:  "GET http://supstandards.com:80/feed/ HTTP/1.1\r\nHost: supstandards.com\r\n\r\n",
			want: "GET /http://supstandards.com:80/feed/ HTTP/1.1\r\nHost: supstandards.com\r\n\r\n",
		},
		{
			name: "origin-form stays untouched",
			raw:  "GET /normal/path/x.php?a=1 HTTP/1.1\r\nHost: example.test\r\n\r\n",
			want: "GET /normal/path/x.php?a=1 HTTP/1.1\r\nHost: example.test\r\n\r\n",
		},
		{
			name: "asterisk-form stays untouched",
			raw:  "OPTIONS * HTTP/1.1\r\nHost: example.test\r\n\r\n",
			want: "OPTIONS * HTTP/1.1\r\nHost: example.test\r\n\r\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := NewFixURIConn(&fakeReadConn{data: []byte(tc.raw)})
			got := readAllFixed(conn)
			if got != tc.want {
				t.Fatalf("FixURIConn 改写结果:\n got=%q\nwant=%q", got, tc.want)
			}
		})
	}
}

/**
 * TestFixURIConnKeepsOriginFormSchemeRelative 覆盖 scheme-relative（//host/path）
 * 与以斜杠开头的畸形 target：这些不触发插入，保证判据只认真正的 absolute-form。
 */
func TestFixURIConnKeepsOriginFormSchemeRelative(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "scheme-relative //host/path",
			raw:  "GET //filefuns.php HTTP/1.1\r\nHost: example.test\r\n\r\n",
			want: "GET //filefuns.php HTTP/1.1\r\nHost: example.test\r\n\r\n",
		},
		{
			name: "double slash origin",
			raw:  "GET ///etc.children.json/FNZ.css HTTP/1.1\r\nHost: example.test\r\n\r\n",
			want: "GET ///etc.children.json/FNZ.css HTTP/1.1\r\nHost: example.test\r\n\r\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := NewFixURIConn(&fakeReadConn{data: []byte(tc.raw)})
			got := readAllFixed(conn)
			if got != tc.want {
				t.Fatalf("FixURIConn 改写结果:\n got=%q\nwant=%q", got, tc.want)
			}
		})
	}
}
