//go:build cgo && quickjs

package challenge

import (
	"errors"
	goruntime "runtime"
	"strings"
	"testing"

	quickjs "github.com/buke/quickjs-go"

	"My-OpenWaf/internal/waf/challenge/pow"
)

// shardCaptureFn 是在引擎内注册的全局捕获函数标识符；shardCaptureProp
// 是该函数把装配结果写回的 window 属性键。
// 捕获函数由 JS 引导代码定义在引擎内部：quickjs-go v0.7.7 中 JS 调用
// Go 回调后仍可能释放入参，回调内 ToString 存在 TOCTOU，实测可触发
// 堆损坏，因此对拍不注入任何 Go 函数。
const (
	shardCaptureFn   = "_owaf_shard_capture"
	shardCaptureProp = "_owaf_shard_capture_result"
)

// runShardAssembler 在真实 QuickJS 运行时里执行 PageScript：
// window 注入为空对象，脚本中 (0,eval).call(window, code) 被替换为
// 与线上完全同构的 (0,捕获函数).call(window, code)：捕获函数是引擎内
// 定义的 JS 函数，把 code 原样写到 window 属性后返回 null，Go 侧
// 执行完毕后读回该属性与完整 body 逐字节对照。
func runShardAssembler(pageScript string) (captured string, err error) {
	var result error
	var caught string
	runOnOwnedLockedThread(func() {
		rt := quickjs.NewRuntime()
		if rt == nil {
			result = errors.New("quickjs runtime creation failed")
			return
		}
		defer rt.Close()
		ctx := rt.NewBareContext()
		if ctx == nil {
			result = errors.New("quickjs context creation failed")
			return
		}
		defer ctx.Close()

		globals := ctx.Globals()
		window := ctx.NewObject()
		globals.Set("window", window)

		// 引导代码注册捕获函数：this 在 (0,capturer).call(window,…)
		// 调用形态下就是 window 空对象，直接写属性即可被 Go 侧读回。
		bootstrap := "(function(g){g['" + shardCaptureFn +
			"']=function(s){this['" + shardCaptureProp + "']=s;return null}})(this)"
		if boo := ctx.Eval(bootstrap, quickjs.EvalFileName("<pow-shard-bootstrap>")); boo == nil {
			result = errors.New("bootstrap eval failed")
			return
		}

		// eval 调用点替换为捕获函数标识符：保持 (0,x).call(window, code)
		// 语法同构，避免赋值语句对以函数表达式开头的 code 产生歧义。
		instrumented := strings.Replace(pageScript, "(0,eval).call(window,", "(0,"+shardCaptureFn+").call(window,", 1)
		if instrumented == pageScript {
			result = errors.New("eval site not found in page script")
			return
		}

		if page := ctx.Eval(instrumented, quickjs.EvalFileName("<pow-shard>")); page == nil {
			result = errors.New("quickjs eval failed")
			return
		}

		prop := window.Get(shardCaptureProp)
		if prop == nil {
			result = errors.New("capture property missing after assembly")
			return
		}
		caught = prop.ToString()
	})
	if result != nil {
		return "", result
	}
	return caught, nil
}

/**
 * runOnOwnedLockedThread 在自持的独立 OS 线程上运行回调。
 * PageScript 每次运行都会新建 QuickJS 运行时，不需要像 jsplugin 的
 * 执行槽那样长期钉住同一条线程。
 *
 * 对本夹具的生命周期约定（由二分定位 crash 得出，勿改）：
 * quickjs-go v0.7.7 反复创建/回收 runtime 时，对 Eval 返回值、
 * 手建 window 对象调用 Free() 会触发 glibc "unaligned tcache chunk"
 * 崩溃；本夹具一律不手动 Free，交给 ctx.Close() 统一回收（Close
 * 内部会 Free 持有的 globals），24 轮实测稳定。
 */
func runOnOwnedLockedThread(fn func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		goruntime.LockOSThread()
		defer goruntime.UnlockOSThread()
		fn()
	}()
	<-done
}

// TestPowShardPageScriptAssemblesInJS 用真实 QuickJS 引擎运行 PageScript：
// window 设为引擎空对象，eval 语义映射为「把 code 字符串捕获」，
// 断言引擎装配出的 code 与完整 body 逐字节相等（黄金等价锁）。
func TestPowShardPageScriptAssemblesInJS(t *testing.T) {
	const rounds = 24
	for i := 0; i < rounds; i++ {
		nonce := randNonceForTest(t, false)
		difficulty := 1 + pow.RandIntN(7)
		replayRandFromStart(t)
		body := pow.GeneratePoWScriptBody(difficulty, nonce)
		replayRandFromStart(t)
		sharded := GeneratePoWShardedScript(difficulty, nonce)

		captured, err := runShardAssembler(sharded.PageScript)
		if err != nil {
			t.Fatalf("JS assembly failed: difficulty=%d nonce=%q err=%v", difficulty, nonce, err)
		}
		if captured != body {
			t.Fatalf("JS assembled code mismatch: difficulty=%d gotLen=%d wantLen=%d", difficulty, len(captured), len(body))
		}
	}
}
