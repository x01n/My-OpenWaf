package luaplugin

import (
	"bufio"
	"strings"
	"sync"

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
	// 状态机级共享对象，池化复用下会污染同一状态机上后续执行的所有脚本
	// （已由 TestScriptCannotEscapeViaMetatable 覆盖）。
	// rawset/rawget 绕过元方法直接操作表，同样可用于篡改共享结构。
	// 策略脚本只需读上下文、做字符串与数值判断，无需这些能力。
	"getmetatable", "setmetatable", "rawset", "rawget", "rawequal", "rawlen",
	// newproxy 可创建带元表的 userdata，是另一条构造共享可变状态的路径。
	"newproxy",
	// module 会写全局命名空间，与 package 一并禁用。
	"module",
}

// vmPool 复用 Lua 状态机。
//
// 创建状态机需注册标准库并分配栈，实测约几十微秒；数据面每请求都新建会直接
// 压垮吞吐。池化后单次调用只需重置栈顶与清理全局变量。
type vmPool struct {
	pool sync.Pool
}

func newVMPool() *vmPool {
	p := &vmPool{}
	p.pool.New = func() any { return newSandboxedState() }
	return p
}

// get 取出一个已沙箱化的状态机。
func (p *vmPool) get() *lua.LState {
	L, _ := p.pool.Get().(*lua.LState)
	if L == nil {
		L = newSandboxedState()
	}
	return L
}

// put 归还状态机。
//
// 已关闭的状态机不再复用。归还前不清理全局表——脚本间的全局污染由
// 每次执行前的 resetGlobals 处理，放在取用侧更不易漏。
func (p *vmPool) put(L *lua.LState) {
	if L == nil || L.IsClosed() {
		return
	}
	p.pool.Put(L)
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

	return L
}

// scriptGlobalWhitelist 是执行前后允许存在的全局名。
//
// 脚本可能定义 handle 之外的辅助全局；为避免同一状态机上前后两次执行相互
// 污染（尤其是恶意脚本借全局变量在请求间传递状态），每次执行前清掉不在
// 白名单里的全局名。
// 注意：此处不含 bannedBaseFuncs 里的任何名字（getmetatable/rawset/load 等），
// 它们已被置为 nil；若误列入白名单，resetGlobals 就不会清掉脚本重新定义的同名
// 全局，等于把穿透入口还给脚本。
var scriptGlobalWhitelist = map[string]bool{
	"_G": true, "_VERSION": true,
	"assert": true, "error": true, "ipairs": true, "next": true, "pairs": true,
	"pcall": true, "xpcall": true, "select": true,
	"tonumber": true, "tostring": true, "type": true, "unpack": true,
	"table": true, "string": true, "math": true,
}

// resetGlobals 清除脚本此前留下的全局变量。
func resetGlobals(L *lua.LState) {
	globals := L.Get(lua.GlobalsIndex)
	tbl, ok := globals.(*lua.LTable)
	if !ok {
		return
	}
	var stale []lua.LValue
	tbl.ForEach(func(k, _ lua.LValue) {
		name, isStr := k.(lua.LString)
		if !isStr {
			stale = append(stale, k)
			return
		}
		if !scriptGlobalWhitelist[string(name)] {
			stale = append(stale, k)
		}
	})
	for _, k := range stale {
		tbl.RawSet(k, lua.LNil)
	}
}
