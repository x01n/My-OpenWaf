package logredact

import (
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
)

/**
 * TestIsDynamicProtectionKeyPathMatchesContextPath 覆盖 loggedPath 为空时
 * 回退到 Hertz 上下文的 c.Path() 分支。
 *
 * 该分支是父包 requestBodyPreview 的调用形态（第二实参传空串），切包前它由
 * 父包测试的组合路径覆盖；符号移入本包后，只有本用例直接打它。
 *
 * 返回 true 意味着「这是取密钥端点」，调用方据此把请求体整段替换为
 * "[redacted]"；漏判会把动态保护密钥写进访问日志。
 */
func TestIsDynamicProtectionKeyPathMatchesContextPath(t *testing.T) {
	mk := func(path string) *app.RequestContext {
		c := app.NewContext(0)
		c.Request.SetRequestURI(path)
		return c
	}

	if !IsDynamicProtectionKeyPath(mk(GroupKeyPath), "") {
		t.Fatalf("上下文路径等于 GroupKeyPath 时必须判定为密钥端点")
	}
	if IsDynamicProtectionKeyPath(mk("/index.html"), "") {
		t.Fatalf("普通路径不得判定为密钥端点")
	}
	if IsDynamicProtectionKeyPath(mk(GroupKeyPath+"/extra"), "") {
		t.Fatalf("GroupKeyPath 的子路径不得判定为密钥端点")
	}
	// 上下文的 Path() 与 GroupKeyPath 差一个查询串时必须仍然命中：
	// RequestURI 带查询串时，Hertz 的 Path() 只返回路径部分。
	if !IsDynamicProtectionKeyPath(mk(GroupKeyPath+"?token=x"), "") {
		t.Fatalf("带查询串的密钥端点请求必须判定为密钥端点")
	}
	if IsDynamicProtectionKeyPath(nil, "") {
		t.Fatalf("nil 上下文且无 loggedPath 时必须返回 false")
	}
}
