package luaplugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docExamplesDir 是文档里那组「可直接复制使用」的示例脚本。
const docExamplesDir = "../../../docs/扩展与插件系统/lua-examples"

// stageFromDocHeader 从示例头部注释里读出声明的阶段。
//
// 每个示例的块注释都有一行形如「阶段：pre（...）」或「阶段：post —— ...」。
// 先判 post 再判 pre，避免前缀误配。
func stageFromDocHeader(src string) (Stage, bool) {
	idx := strings.Index(src, "阶段：")
	if idx < 0 {
		return "", false
	}
	rest := src[idx+len("阶段："):]
	switch {
	case strings.HasPrefix(rest, string(StagePost)):
		return StagePost, true
	case strings.HasPrefix(rest, string(StagePre)):
		return StagePre, true
	}
	return "", false
}

// TestDocExamplesCompileAndRun 保证文档示例始终可用。
//
// 这些脚本在文档里是「复制粘贴就能用」的定位，用户不会先去编译验证。
// 一旦 ctx 字段改名、kv 接口调整或沙箱收紧了某个函数，示例会静默失效，
// 而失效的表现是用户保存时报错——问题出在我们这边，却由用户先撞上。
//
// 断言两件事：能编译，以及在 Redis 缺失（kv 为 nil）时能跑完不报运行时错。
// 后者尤其重要——示例注释明确承诺「Redis 未配置时降级为不判定」，
// 若脚本实际在 kv 不可用时报错，那句承诺就是假的。
func TestDocExamplesCompileAndRun(t *testing.T) {
	entries, err := os.ReadDir(docExamplesDir)
	if err != nil {
		t.Fatalf("读取示例目录失败（文档示例是仓库的一部分，路径变动需同步本测试）: %v", err)
	}

	var checked int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".lua") {
			continue
		}
		name := e.Name()
		raw, err := os.ReadFile(filepath.Join(docExamplesDir, name))
		if err != nil {
			t.Errorf("%s: 读取失败: %v", name, err)
			continue
		}
		src := string(raw)

		stage, ok := stageFromDocHeader(src)
		if !ok {
			t.Errorf("%s: 头部注释缺少可识别的「阶段：pre|post」声明，"+
				"用户照抄时无从知道该选哪个阶段", name)
			continue
		}
		checked++

		if err := Validate(stage, src); err != nil {
			t.Errorf("%s: 编译失败: %v", name, err)
			continue
		}

		// kv 传 nil 模拟未配置 Redis 的部署，这是默认形态。
		res := DryRun(stage, src, docSampleRequest(stage), nil, 0)
		if res.CompileError != "" {
			t.Errorf("%s: DryRun 编译失败: %s", name, res.CompileError)
		}
		if res.RuntimeError != "" {
			t.Errorf("%s: 无 Redis 时运行出错，与示例承诺的降级行为不符: %s",
				name, res.RuntimeError)
		}
	}

	if checked == 0 {
		t.Fatal("一个示例都没检查到——目录为空或后缀不匹配，本测试已失去意义")
	}
	t.Logf("已验证 %d 个文档示例", checked)
}

// docSampleRequest 构造一个字段齐备的普通请求。
//
// 刻意用不含攻击特征的取值：这里验证的是「脚本能跑通」，不是「判定对不对」，
// 断言判定结果就得预设每个示例的触发条件，那是在猜测示例意图。
func docSampleRequest(stage Stage) RequestView {
	req := RequestView{
		RequestID:   "doc-example",
		ClientIP:    "203.0.113.10",
		Method:      "GET",
		Path:        "/api/orders",
		RawQuery:    "page=1",
		Host:        "app.example.com",
		UserAgent:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
		SiteID:      1,
		ContentType: "application/json",
		Headers: map[string]string{
			"accept":          "application/json",
			"accept-language": "zh-CN,zh;q=0.9",
			"x-forwarded-for": "203.0.113.10",
		},
		QueryParams: map[string]string{"page": "1"},
		Body:        `{"id":1}`,
		TLSVersion:  "TLS13",
		TLSJA3:      "e7d705a3286e19ea42f587b344ee6865",
		TLSJA4:      "t13d1516h2_8daaf6152771_02713d6af862",
		TLSSNI:      "app.example.com",
	}
	// post 阶段脚本会读内置判定，给一个非终止的取值，避免示例误以为已被拦截。
	if stage == StagePost {
		req.Phase = "owasp"
		req.Action = "observe"
	}
	return req
}
