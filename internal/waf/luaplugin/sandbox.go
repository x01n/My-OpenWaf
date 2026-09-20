package luaplugin

import (
	"bufio"
	"strings"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

// compileProto 把源码编译为可在多个状态机间共享的函数原型。
func compileProto(name, source string) (*lua.FunctionProto, error) {
	chunk, err := parse.Parse(bufio.NewReader(strings.NewReader(source)), name)
	if err != nil {
		return nil, err
	}
	return lua.Compile(chunk, name)
}

// allowedLibs 是允许注册的标准库。
//
// 刻意排除：
//   - io / os：文件系统与环境访问，脚本绝不应触达
//   - debug：可绕过一切沙箱限制（能改别人的函数、读局部变量）
//   - package（require/loadlib）：可加载任意模块与 C 动态库
//   - coroutine：与超时中断机制冲突——协程内的执行不受调用方 context 约束
//
// base 库虽保留，但其中的 dofile/loadfile/load/loadstring/require/collectgarbage
// 会在 hardenState 中单独摘除：它们能从字符串动态构造代码，使脚本审计失去意义。
var allowedLibs = []struct {
	name string
	fn   lua.LGFunction
}{
	{lua.BaseLibName, lua.OpenBase},
	{lua.TabLibName, lua.OpenTable},
	{lua.StringLibName, lua.OpenString},
	{lua.MathLibName, lua.OpenMath},
}

// bannedBaseFuncs 是需从 base 库摘除的函数。
//
// 前五个能从字符串动态构造并执行代码——保留它们等于允许脚本在运行时生成
// 任意逻辑，静态审计与体积限制都将形同虚设。collectgarbage 则允许脚本
// 主动触发 STW GC，是廉价的拒绝服务手段。
var bannedBaseFuncs = []string{
	"dofile", "loadfile", "load", "loadstring", "require",
	"collectgarbage",
	// print 会写进程 stdout，绕过统一日志且可被用于刷日志。
	"print",
	// getmetatable/setmetatable 是实测可用的沙箱穿透入口：
	// getmetatable("").__index.upper = ... 能改写字符串方法，而字符串元表是
	// 状态机内的共享对象；若状态机被错误复用，会污染后续执行的所有脚本
	// （已由 TestScriptCannotEscapeViaMetatable 覆盖）。
	// rawset/rawget 绕过元方法直接操作表，同样可用于篡改共享结构。
	// 策略脚本只需读上下文、做字符串与数值判断，无需这些能力。
	"getmetatable", "setmetatable", "rawset", "rawget", "rawequal", "rawlen",
	// newproxy 可创建带元表的 userdata，是另一条构造共享可变状态的路径。
	"newproxy",
	// module 会写全局命名空间，与 package 一并禁用。
	"module",
}

// vmPool 管理一次执行一个的 Lua 状态机。
//
// 标准库和 _G 都是可变对象，无法在不遗漏嵌套表、函数或元表的前提下可靠复原。
// 因此状态机绝不跨脚本或请求复用，执行结束立即关闭；已编译的函数原型仍由
// compileProto 共享，避免重复解析和编译脚本源码。
type vmPool struct{}

func newVMPool() *vmPool {
	return &vmPool{}
}

// get 创建一个已沙箱化的全新状态机。
func (p *vmPool) get() *lua.LState {
	return newSandboxedState()
}

// put 清空栈并关闭执行完毕的状态机，丢弃所有脚本可能改写的库表和全局状态。
func (p *vmPool) put(L *lua.LState) {
	if L != nil && !L.IsClosed() {
		L.SetTop(0)
		L.Close()
	}
}

// newSandboxedState 创建一个仅注册白名单库、且移除危险 base 函数的状态机。
func newSandboxedState() *lua.LState {
	L := lua.NewState(lua.Options{
		// 跳过默认的全量库注册，改为按白名单逐个开启。
		SkipOpenLibs: true,
		// 关闭调用栈追踪以省开销；脚本错误信息仍带行号。
		IncludeGoStackTrace: false,
	})

	for _, lib := range allowedLibs {
		L.Push(L.NewFunction(lib.fn))
		L.Push(lua.LString(lib.name))
		// 注册失败不应静默：直接关闭状态机，让调用方拿到空实现而非半沙箱。
		if err := L.PCall(1, 0, nil); err != nil {
			L.Close()
			return nil
		}
	}

	for _, name := range bannedBaseFuncs {
		L.SetGlobal(name, lua.LNil)
	}
	// gopher-lua 的 math.randomseed 使用进程级 math/rand 状态，不能允许脚本
	// 通过它影响其他 VM 或请求的随机序列。
	if mathLib, ok := L.GetGlobal(lua.MathLibName).(*lua.LTable); ok {
		mathLib.RawSetString("randomseed", lua.LNil)
	}

	return L
}
