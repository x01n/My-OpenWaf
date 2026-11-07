package imagery

import (
	"os"
	"path/filepath"
	"testing"
)

// mustReadTestdata 读取 testdata 下的文件，失败即终止测试。
//
// @param t 测试上下文。
// @param name testdata 中的文件名。
// @return 文件内容。
func mustReadTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return data
}
