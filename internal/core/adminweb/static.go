package adminweb

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// ResolveFS returns either the on-disk override or the embedded dist tree.
func ResolveFS(diskDir string) (fs.FS, error) {
	diskDir = strings.TrimSpace(diskDir)
	if diskDir != "" {
		return osDir(diskDir), nil
	}
	return SubFS()
}

// ReadRouteFile resolves an exported Next.js route or asset from the given FS.
func ReadRouteFile(webFS fs.FS, requestPath string) ([]byte, string, error) {
	for _, candidate := range routeCandidates(requestPath) {
		data, err := fs.ReadFile(webFS, candidate)
		if err == nil {
			return data, candidate, nil
		}
	}
	return nil, "", fs.ErrNotExist
}

// ContentType maps exported asset names to their response content-type.
func ContentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "application/javascript"
	case strings.HasSuffix(name, ".css"):
		return "text/css"
	case strings.HasSuffix(name, ".json"):
		return "application/json"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(name, ".png"):
		return "image/png"
	case strings.HasSuffix(name, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(name, ".woff2"):
		return "font/woff2"
	default:
		return "application/octet-stream"
	}
}

func routeCandidates(requestPath string) []string {
	requestPath = strings.TrimSpace(requestPath)
	if requestPath == "" || requestPath == "/" {
		return []string{"index.html"}
	}

	clean := strings.TrimPrefix(path.Clean("/"+requestPath), "/")
	if clean == "" || clean == "." {
		return []string{"index.html"}
	}

	var candidates []string
	if strings.HasSuffix(requestPath, "/") {
		candidates = append(candidates, clean+"/index.html")
	}

	candidates = append(candidates, clean)

	if !strings.Contains(path.Base(clean), ".") {
		candidates = append(candidates, clean+"/index.html", clean+".html", "index.html")
	}

	return uniqueStrings(candidates)
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

type osDir string

func (d osDir) Open(name string) (fs.File, error) {
	return http.Dir(string(d)).Open(name)
}
