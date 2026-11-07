module My-OpenWaf

go 1.27.3

require (
	github.com/JohannesKaufmann/html-to-markdown/v2 v2.5.2
	github.com/andybalholm/brotli v1.2.8
	github.com/buke/quickjs-go v0.7.8
	github.com/cloudwego/gopkg v0.2.1
	github.com/cloudwego/hertz v0.10.6
	github.com/dgraph-io/ristretto v1.0.1
	github.com/emmansun/gmsm v0.45.2
	github.com/gen2brain/webp v0.6.4
	github.com/glebarez/sqlite v1.11.0
	github.com/go-sql-driver/mysql v1.10.1
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/klauspost/compress v1.20.3
	github.com/oschwald/maxminddb-golang v1.13.1
	github.com/quic-go/quic-go v0.65.0
	github.com/redis/rueidis v1.0.79
	github.com/refraction-networking/utls v1.8.2
	github.com/tdewolff/parse/v2 v2.8.20
	github.com/wenlng/go-captcha-assets v1.0.7
	github.com/wenlng/go-captcha/v2 v2.0.5
	github.com/wu238121-a11y/go-ja4 v1.0.0
	github.com/x01n/http2 v0.3.0
	github.com/yuin/gopher-lua v1.1.2
	golang.org/x/crypto v0.58.0
	golang.org/x/image v0.47.0
	golang.org/x/net v0.62.0
	golang.org/x/sync v0.24.0
	gorm.io/driver/mysql v1.6.0
	gorm.io/driver/postgres v1.6.3
	gorm.io/gorm v1.31.2
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/JohannesKaufmann/dom v0.3.1 // indirect
	github.com/bytedance/gopkg v0.1.4 // indirect
	github.com/bytedance/sonic v1.15.5 // indirect
	github.com/bytedance/sonic/loader v0.5.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudwego/base64x v0.1.7 // indirect
	github.com/cloudwego/netpoll v0.7.5 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/ebitengine/purego v0.11.3 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/glebarez/go-sqlite v1.23.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.12.0 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/klauspost/cpuid/v2 v2.4.2 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/tidwall/gjson v1.20.0 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.2 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	golang.org/x/arch v0.32.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	modernc.org/libc v1.80.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
	modernc.org/sqlite v1.61.1 // indirect
)

// 用 modernc.org/sqlite 的缓存语句实现替换 glebarez 驱动（仅保留其 Error 类型兼容层）。
replace github.com/glebarez/go-sqlite => ./third_party/go-sqlite-shim
