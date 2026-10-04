package adminweb

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// Dist 是 Next.js 静态导出产物树（默认由 scripts/build.ps1|sh 把 frontend/out 复制到 dist/）。
//
//go:embed all:dist
var Dist embed.FS

// SubFS 返回 dist/ 作为 Web 根目录（URL 映射到 dist/ 下的文件）。
func SubFS() (fs.FS, error) {
	return fs.Sub(Dist, "dist")
}

// FileServer 服务管理端 UI。diskDir 非空时从磁盘读取（开发期覆盖）；否则使用 embed.FS。
func FileServer(diskDir string) (http.Handler, error) {
	diskDir = strings.TrimSpace(diskDir)
	if diskDir != "" {
		return http.FileServer(http.Dir(diskDir)), nil
	}
	sub, err := SubFS()
	if err != nil {
		return nil, err
	}
	return http.FileServer(http.FS(sub)), nil
}
