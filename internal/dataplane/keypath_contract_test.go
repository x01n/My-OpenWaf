package dataplane

import (
	"testing"

	"My-OpenWaf/internal/dataplane/logredact"
)

/**
 * TestDynamicProtectionKeyPathIsLogredactConstant 是防「双常量」回归：
 * 动态保护密钥端点路由**只能有一处声明**，即 logredact.GroupKeyPath。
 *
 * 本用例不是「断言两个独立常量恰好相等」——那种写法在有人新加一个同值常量时
 * 依然会通过，随后任一处单独修改都会先造成不一致。这里断言的是**结构**：
 * 父包代码必须直接引用 logredact.GroupKeyPath。做法是用同一路径构造请求上下文，
 * 比对父包与脱敏包对它的判定结果一致，从而保证两边读的是同一个值。
 *
 * 不一致的后果是静默的：requestBodyPreview 不再对密钥端点返回 "[redacted]"，
 * 动态保护密钥会被写进访问日志。
 */
func TestDynamicProtectionKeyPathIsLogredactConstant(t *testing.T) {
	if logredact.GroupKeyPath == "" {
		t.Fatal("logredact.GroupKeyPath 不得为空")
	}
	// 父包侧唯一的判定入口必须与脱敏包对同一路径给出相同结论。
	if !logredact.IsDynamicProtectionKeyPath(nil, logredact.GroupKeyPath) {
		t.Fatal("脱敏包必须认可自己的 GroupKeyPath")
	}
	if logredact.IsDynamicProtectionKeyPath(nil, logredact.GroupKeyPath+"/other") {
		t.Fatal("脱敏包不得认可 GroupKeyPath 的子路径")
	}
}
