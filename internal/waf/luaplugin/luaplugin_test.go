package luaplugin

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func silentEngine(kv KVBackend) *Engine {
	return NewEngine(kv, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func mustCompile(t *testing.T, stage Stage, src string) *Script {
	t.Helper()
	s, err := Compile("test", stage, src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return s
}

func evalOne(t *testing.T, src string, req RequestView, kv KVBackend) Decision {
	t.Helper()
	e := silentEngine(kv)
	e.Reload([]*Script{mustCompile(t, StagePre, src)})
	return e.Evaluate(context.Background(), StagePre, req)
}

// ---- 沙箱：死循环必须被中断 ----

// TestInfiniteLoopIsInterrupted 是沙箱最关键的一条断言。
//
// 脚本在数据面同步执行，一个 while true 就能挂死整个站点。
// 若本用例挂住不返回，说明超时机制根本没生效。
func TestInfiniteLoopIsInterrupted(t *testing.T) {
	script := mustCompile(t, StagePre, `function handle(ctx) while true do end end`)
	script.SetTimeout(80 * time.Millisecond)

	e := silentEngine(nil)
	e.Reload([]*Script{script})

	done := make(chan Decision, 1)
	go func() {
		done <- e.Evaluate(context.Background(), StagePre, RequestView{})
	}()

	select {
	case dec := <-done:
		if dec.HasAction() {
			t.Fatalf("超时脚本不应产生判定，得到 %+v", dec)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("死循环未被中断——超时机制失效，数据面会被单个脚本挂死")
	}

	if _, _, timeouts, _ := script.Stats(); timeouts == 0 {
		t.Error("超时应被计入 timeouts 统计")
	}
}

// TestCallerContextCancelStopsScript 验证调用方取消能中断脚本，
// 使请求断开时不再继续消耗 CPU。
func TestCallerContextCancelStopsScript(t *testing.T) {
	script := mustCompile(t, StagePre, `function handle(ctx) while true do end end`)
	script.SetTimeout(10 * time.Second) // 故意设长，确保中断来自 ctx 取消

	e := silentEngine(nil)
	e.Reload([]*Script{script})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.Evaluate(ctx, StagePre, RequestView{})
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("调用方取消未能中断脚本")
	}
}

// ---- 沙箱：危险能力必须不可达 ----

// TestDangerousGlobalsUnavailable 验证能触达文件系统、动态求值与运行时内部的
// 全局名一律不可用。任一项可用都意味着沙箱被穿透。
func TestDangerousGlobalsUnavailable(t *testing.T) {
	for _, name := range []string{
		"io", "os", "debug", "package", "coroutine",
		"dofile", "loadfile", "load", "loadstring", "require",
		"collectgarbage", "print",
		// 元表与 raw 系列是实测可用的穿透入口，必须不可达。
		"getmetatable", "setmetatable", "rawset", "rawget", "newproxy", "module",
	} {
		src := `function handle(ctx) if ` + name + ` ~= nil then return "intercept" end return nil end`
		dec := evalOne(t, src, RequestView{}, nil)
		if dec.HasAction() {
			t.Errorf("危险全局 %q 仍可访问——沙箱被穿透", name)
		}
	}
}

// TestScriptCannotEscapeViaMetatable 验证脚本无法借元表改写字符串方法。
//
// 曾实测可穿透：getmetatable("").__index.upper = ... 能改写字符串方法，
// 而字符串元表是状态机级共享对象，池化复用下会污染后续所有脚本。
// 现已移除 getmetatable，脚本连入口都拿不到。
func TestScriptCannotEscapeViaMetatable(t *testing.T) {
	src := `
function handle(ctx)
  pcall(function()
    local mt = getmetatable("")
    mt.__index.upper = function() return "hacked" end
  end)
  if ("x"):upper() == "hacked" then return "intercept" end
  return nil
end`
	if dec := evalOne(t, src, RequestView{}, nil); dec.HasAction() {
		t.Error("脚本成功改写了字符串元表")
	}
}

// TestMetatablePollutionDoesNotCrossScripts 是池化复用的安全前提。
//
// 状态机在脚本间复用，若一个脚本能污染共享的元表，同池后续脚本的行为
// 都会被改写——单个恶意/出错脚本即可影响整个策略体系。
func TestMetatablePollutionDoesNotCrossScripts(t *testing.T) {
	e := silentEngine(nil)

	// 先让"投毒"脚本尽力污染。
	e.Reload([]*Script{mustCompile(t, StagePre, `
function handle(ctx)
  pcall(function()
    local mt = getmetatable("")
    mt.__index.upper = function() return "hacked" end
  end)
  pcall(function() rawset(string, "upper", function() return "hacked" end) end)
  return nil
end`)})
	for i := 0; i < 3; i++ {
		e.Evaluate(context.Background(), StagePre, RequestView{})
	}

	// 再用同一个 Engine（同一状态机池）跑受害脚本。
	e.Reload([]*Script{mustCompile(t, StagePre, `
function handle(ctx)
  if ("x"):upper() ~= "X" then return "intercept" end
  if string.upper("y") ~= "Y" then return "intercept" end
  return nil
end`)})
	if dec := e.Evaluate(context.Background(), StagePre, RequestView{}); dec.HasAction() {
		t.Fatal("污染跨脚本残留——同池后续脚本的字符串方法已被改写")
	}
}

// ---- panic 隔离 ----

// TestScriptErrorDoesNotPropagate 验证脚本报错只被记录，不影响判定流程。
func TestScriptErrorDoesNotPropagate(t *testing.T) {
	e := silentEngine(nil)
	e.Reload([]*Script{
		mustCompile(t, StagePre, `function handle(ctx) error("boom") end`),
		// 第二个脚本必须仍被执行——单个脚本故障不应中断整条链。
		mustCompile(t, StagePre, `function handle(ctx) return "observe" end`),
	})

	dec := e.Evaluate(context.Background(), StagePre, RequestView{})
	if dec.Action != "observe" {
		t.Fatalf("前一个脚本报错后应继续执行后续脚本，得到 %+v", dec)
	}
}

// TestMissingHandlerIsError 验证未定义 handle 的脚本被视为失败而非静默放行。
func TestMissingHandlerIsError(t *testing.T) {
	script := mustCompile(t, StagePre, `local x = 1`)
	e := silentEngine(nil)
	e.Reload([]*Script{script})

	if dec := e.Evaluate(context.Background(), StagePre, RequestView{}); dec.HasAction() {
		t.Error("缺少 handle 的脚本不应产生判定")
	}
	if _, failures, _, _ := script.Stats(); failures == 0 {
		t.Error("缺少 handle 应计入 failures")
	}
}

// ---- 请求上下文可读性 ----

func TestScriptReadsRequestFields(t *testing.T) {
	req := RequestView{
		RequestID: "req-1", ClientIP: "1.2.3.4", Method: "POST",
		Path: "/admin/login", RawQuery: "next=%2F", Host: "a.example.com",
		UserAgent: "curl/8.0", SiteID: 7, ContentType: "application/json",
		Body:        `{"u":"admin"}`,
		Headers:     map[string]string{"x-real-ip": "5.6.7.8"},
		QueryParams: map[string]string{"next": "/"},
		TLSVersion:  "TLS13", TLSJA4: "t13d1516h2",
	}
	src := `
function handle(ctx)
  if ctx.request_id ~= "req-1" then return "intercept" end
  if ctx.client_ip ~= "1.2.3.4" then return "intercept" end
  if ctx.method ~= "POST" then return "intercept" end
  if ctx.path ~= "/admin/login" then return "intercept" end
  if ctx.host ~= "a.example.com" then return "intercept" end
  if ctx.site_id ~= 7 then return "intercept" end
  if ctx.headers["x-real-ip"] ~= "5.6.7.8" then return "intercept" end
  if ctx.query_params["next"] ~= "/" then return "intercept" end
  if ctx.tls.version ~= "TLS13" then return "intercept" end
  if ctx.tls.ja4 ~= "t13d1516h2" then return "intercept" end
  if not string.find(ctx.body, "admin", 1, true) then return "intercept" end
  return "observe"
end`
	if dec := evalOne(t, src, req, nil); dec.Action != "observe" {
		t.Fatalf("某个字段读取不符预期（脚本以 intercept 表示失配），得到 %+v", dec)
	}
}

// TestPostStageSeesBuiltinVerdict 验证后置脚本能读到内置阶段的判定，
// 这是「对特定误报放行」这类场景的前提。
func TestPostStageSeesBuiltinVerdict(t *testing.T) {
	e := silentEngine(nil)
	e.Reload([]*Script{mustCompile(t, StagePost, `
function handle(ctx)
  if ctx.phase == "owasp" and ctx.action == "intercept" then return "allow" end
  return nil
end`)})

	dec := e.Evaluate(context.Background(), StagePost, RequestView{Phase: "owasp", Action: "intercept"})
	if dec.Action != "allow" {
		t.Fatalf("后置脚本未读到内置判定，得到 %+v", dec)
	}
}

// ---- 返回值形态 ----

func TestDecisionReturnForms(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want Decision
	}{
		{"nil 不判定", `function handle(ctx) return nil end`, Decision{}},
		{"false 不判定", `function handle(ctx) return false end`, Decision{}},
		{"无返回值", `function handle(ctx) end`, Decision{}},
		{"字符串即 action", `function handle(ctx) return "drop" end`, Decision{Action: "drop"}},
		{
			"表携带完整字段",
			`function handle(ctx) return {action="redirect", message="m", redirect_to="/x", status_code=302} end`,
			Decision{Action: "redirect", Message: "m", RedirectTo: "/x", StatusCode: 302},
		},
	}
	for _, tt := range cases {
		got := evalOne(t, tt.src, RequestView{}, nil)
		if got.Action != tt.want.Action || got.Message != tt.want.Message ||
			got.RedirectTo != tt.want.RedirectTo || got.StatusCode != tt.want.StatusCode {
			t.Errorf("%s: 得到 %+v, want %+v", tt.name, got, tt.want)
		}
	}
}

func TestDecisionHeadersAndTags(t *testing.T) {
	src := `
function handle(ctx)
  return {action="observe", headers={["x-owaf-tag"]="bot"}, tags={"suspicious","scripted"}}
end`
	dec := evalOne(t, src, RequestView{}, nil)
	if dec.SetHeaders["x-owaf-tag"] != "bot" {
		t.Errorf("headers 未解析：%+v", dec.SetHeaders)
	}
	if len(dec.Tags) != 2 {
		t.Errorf("tags 未解析：%+v", dec.Tags)
	}
}

// ---- 编译期校验 ----

func TestCompileRejectsBadInput(t *testing.T) {
	if _, err := Compile("x", StagePre, `function handle( end`); err == nil {
		t.Error("语法错误应在编译期被拒绝")
	}
	if _, err := Compile("x", "middle", `function handle(ctx) end`); err == nil {
		t.Error("非法 stage 应被拒绝")
	}
	if _, err := Compile("x", StagePre, strings.Repeat("-", maxScriptBytes+1)); err == nil {
		t.Error("超限脚本应被拒绝")
	}
}

// ---- 阶段隔离与零开销 ----

func TestStageIsolation(t *testing.T) {
	e := silentEngine(nil)
	e.Reload([]*Script{mustCompile(t, StagePre, `function handle(ctx) return "drop" end`)})

	if !e.HasScripts(StagePre) {
		t.Error("pre 阶段应有脚本")
	}
	if e.HasScripts(StagePost) {
		t.Error("post 阶段不应有脚本")
	}
	if dec := e.Evaluate(context.Background(), StagePost, RequestView{}); dec.HasAction() {
		t.Error("post 阶段无脚本时不应产生判定")
	}
}

func TestNilEngineSafe(t *testing.T) {
	var e *Engine
	if e.HasScripts(StagePre) {
		t.Error("nil 引擎应报告无脚本")
	}
	if dec := e.Evaluate(context.Background(), StagePre, RequestView{}); dec.HasAction() {
		t.Error("nil 引擎不应产生判定")
	}
	if e.Stats() != nil {
		t.Error("nil 引擎的统计应为 nil")
	}
}

// ---- 全局隔离 ----

// TestGlobalsDoNotLeakBetweenRuns 验证脚本无法借全局变量在请求间传递状态。
//
// 状态机是池化复用的，若不清理全局表，恶意脚本可借此累积跨请求状态，
// 或不同脚本相互干扰。
func TestGlobalsDoNotLeakBetweenRuns(t *testing.T) {
	e := silentEngine(nil)
	e.Reload([]*Script{mustCompile(t, StagePre, `
function handle(ctx)
  if leaked ~= nil then return "intercept" end
  leaked = "state"
  return nil
end`)})

	for i := 0; i < 5; i++ {
		if dec := e.Evaluate(context.Background(), StagePre, RequestView{}); dec.HasAction() {
			t.Fatalf("第 %d 次执行看到了上次遗留的全局变量", i+1)
		}
	}
}

// ---- 并发安全 ----

func TestConcurrentEvaluate(t *testing.T) {
	e := silentEngine(nil)
	script := mustCompile(t, StagePre, `
function handle(ctx)
  local n = 0
  for i = 1, 50 do n = n + i end
  if ctx.path == "/block" then return "intercept" end
  return nil
end`)
	// 必须显式设置宽裕的超时。本用例断言的是并发安全（判定不串号、不丢失），
	// 而非超时预算：默认 50ms 在高负载机器上会被 goroutine 调度延迟打穿，
	// 超时后 Evaluate 跳过脚本并返回空判定，测试就退化成了对机器负载的断言。
	script.SetTimeout(5 * time.Second)
	e.Reload([]*Script{script})

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				path := "/ok"
				want := ""
				if (id+i)%3 == 0 {
					path, want = "/block", "intercept"
				}
				dec := e.Evaluate(context.Background(), StagePre, RequestView{Path: path})
				if dec.Action != want {
					runs, failures, timeouts, _ := script.Stats()
					t.Errorf("path=%s: 得到 %q, want %q (runs=%d failures=%d timeouts=%d)",
						path, dec.Action, want, runs, failures, timeouts)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestStatsAccumulate 验证统计随执行累加。
func TestStatsAccumulate(t *testing.T) {
	e := silentEngine(nil)
	e.Reload([]*Script{mustCompile(t, StagePre, `function handle(ctx) return nil end`)})

	for i := 0; i < 3; i++ {
		e.Evaluate(context.Background(), StagePre, RequestView{})
	}
	stats := e.Stats()
	if len(stats) != 1 {
		t.Fatalf("应有 1 条统计，得到 %d", len(stats))
	}
	if stats[0].Runs != 3 {
		t.Errorf("Runs = %d, want 3", stats[0].Runs)
	}
	if stats[0].Stage != string(StagePre) {
		t.Errorf("Stage = %q", stats[0].Stage)
	}
}
