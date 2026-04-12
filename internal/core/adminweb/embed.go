package adminweb

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// Dist is the Next.js static export tree (default: frontend/out copied into dist/ by scripts/build.ps1|sh).
//
//go:embed all:dist
var Dist embed.FS

// SubFS returns dist/ as the web root (URLs map to files under dist/).
func SubFS() (fs.FS, error) {
	return fs.Sub(Dist, "dist")
}

// FileServer serves the admin UI. If diskDir is non-empty, serves from disk (dev override); otherwise embed.FS.
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
