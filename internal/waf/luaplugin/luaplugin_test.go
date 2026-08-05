package luaplugin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	lua "github.com/yuin/gopher-lua"
)

type testKV struct {
	available bool
}

func (k testKV) Available() bool { return k.available }

func (testKV) Get(string) ([]byte, bool) { return nil, false }

func (testKV) Set(string, []byte, time.Duration) error { return nil }

func (testKV) Delete(string) {}

func (testKV) Incr(string, time.Duration) (int64, error) { return 1, nil }

func newSilentEngine(kv KVBackend) *Engine {
	return NewEngine(kv, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func silentEngine(kv KVBackend) *Engine {
	if kv == nil {
		kv = testKV{available: true}
	}
	return newSilentEngine(kv)
}

type recordingKV struct {
	setTTL  time.Duration
	incrTTL time.Duration
}

func (*recordingKV) Available() bool { return true }

func (*recordingKV) Get(string) ([]byte, bool) { return nil, false }

func (k *recordingKV) Set(_ string, _ []byte, ttl time.Duration) error {
	k.setTTL = ttl
	return nil
}

func (*recordingKV) Delete(string) {}

func (k *recordingKV) Incr(_ string, ttl time.Duration) (int64, error) {
	k.incrTTL = ttl
	return 1, nil
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

func TestKVTTLAlwaysExpires(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want time.Duration
	}{
		{"超时上限", `function handle(ctx) ctx.kv.set("key", "value", 86401) return nil end`, kvMaxTTL},
		{"巨大有限数", `function handle(ctx) ctx.kv.set("key", "value", 1e12) return nil end`, kvMaxTTL},
		{"Lua 最大数", `function handle(ctx) ctx.kv.set("key", "value", math.huge) return nil end`, kvMaxTTL},
		{"NaN", `function handle(ctx) ctx.kv.set("key", "value", 0 / 0) return nil end`, kvDefaultTTL},
		{"负无穷", `function handle(ctx) ctx.kv.incr("key", -math.huge) return nil end`, kvDefaultTTL},
		{"亚秒截断", `function handle(ctx) ctx.kv.incr("key", 0.5) return nil end`, kvDefaultTTL},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			kv := &recordingKV{}
			evalOne(t, tt.src, RequestView{}, kv)
			got := kv.setTTL
			if strings.Contains(tt.src, "ctx.kv.incr") {
				got = kv.incrTTL
			}
			if got != tt.want {
				t.Fatalf("TTL = %s, want %s", got, tt.want)
			}
			if got <= 0 {
				t.Fatal("KV TTL must always expire")
			}
		})
	}
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

// TestCanceledContextNeverAdoptsLuaDecision 验证调用方取消后即使脚本快速返回，
// 也不会采纳 Lua 判定。
func TestCanceledContextNeverAdoptsLuaDecision(t *testing.T) {
	e := silentEngine(nil)
	e.Reload([]*Script{mustCompile(t, StagePre, `function handle(ctx) return "intercept" end`)})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if got := e.Evaluate(ctx, StagePre, RequestView{}); got.HasAction() {
		t.Fatalf("cancelled context must not return a Lua decision, got %+v", got)
	}
}

// ---- 沙箱：危险能力必须不可达 ----

// TestDangerousGlobalsUnavailable 验证能触达文件系统、动态求值与运行时内部的
// 全局名一律不可用。任一项可用都意味着沙箱被穿透。
func TestDangerousGlobalsUnavailable(t *testing.T) {
	for _, name := range []string{
		"io", "os", "debug",
		"dofile", "loadfile", "load", "loadstring", "require",
		"collectgarbage", "print",
		// 元表与 raw 系列是实测可用的穿透入口，必须不可达。
		"getmetatable", "setmetatable", "rawset", "rawget", "newproxy", "module",
		"math.randomseed"} {
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

// TestMetatablePollutionDoesNotCrossScripts 验证状态机隔离阻止元表污染跨运行传播。
//
// 若状态机被复用，脚本改写共享元表后会影响后续脚本；单个恶意/出错脚本
// 不应影响整个策略体系。
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

	// 再用同一个 Engine 跑受害脚本，验证 Reload 后仍获得 pristine VM。
	e.Reload([]*Script{mustCompile(t, StagePre, `
function handle(ctx)
  if ("x"):upper() ~= "X" then return "intercept" end
  if string.upper("y") ~= "Y" then return "intercept" end
  return nil
end`)})
	if dec := e.Evaluate(context.Background(), StagePre, RequestView{}); dec.HasAction() {
		t.Fatal("污染跨脚本残留——Reload 后的受害脚本未获得干净状态机")
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
		QueryValues: map[string][]string{"next": {"/", "/fallback"}},
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
  if ctx.query_values["next"][1] ~= "/" or ctx.query_values["next"][2] ~= "/fallback" then return "intercept" end
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

func TestDecisionRejectsUnsafeRedirectTargets(t *testing.T) {
	unsafeTargets := []string{"javascript:alert(1)", "//evil.example", "relative/path"}
	for _, target := range unsafeTargets {
		src := `function handle(ctx) return {action="redirect", redirect_to="` + target + `"} end`
		dec := evalOne(t, src, RequestView{}, nil)
		if dec.RedirectTo != "" {
			t.Fatalf("unsafe redirect target %q was accepted as %q", target, dec.RedirectTo)
		}
	}
	L := lua.NewState()
	t.Cleanup(L.Close)
	table := L.NewTable()
	table.RawSetString("action", lua.LString("redirect"))
	table.RawSetString("redirect_to", lua.LString("/ok\r\nX-Test: injected"))
	dec, err := decisionFromTable(table)
	if err != nil {
		t.Fatalf("decisionFromTable: %v", err)
	}
	if dec.RedirectTo != "" {
		t.Fatalf("CRLF redirect target was accepted as %q", dec.RedirectTo)
	}
	for _, target := range []string{"/safe/path", "https://example.test/path"} {
		src := `function handle(ctx) return {action="redirect", redirect_to="` + target + `"} end`
		dec := evalOne(t, src, RequestView{}, nil)
		if dec.RedirectTo != target {
			t.Fatalf("safe redirect target %q became %q", target, dec.RedirectTo)
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

func TestDecisionHeadersRejectUnsafeValues(t *testing.T) {
	src := `
function handle(ctx)
  return {
    action="observe",
    headers={
      ["x-safe"]="accepted",
      ["authorization"]="secret",
      ["set-cookie"]="session=secret",
      ["connection"]="close",
      ["content-length"]="999",
      ["bad header"]="invalid",
      ["x-crlf"]="ok\r\nX: y"
    }
  }
end`
	dec := evalOne(t, src, RequestView{}, nil)
	if len(dec.SetHeaders) != 1 || dec.SetHeaders["x-safe"] != "accepted" {
		t.Fatalf("不安全响应头未被完整过滤：%+v", dec.SetHeaders)
	}
	for _, name := range []string{
		"authorization", "set-cookie", "connection", "content-length", "bad header", "x-crlf",
	} {
		if _, ok := dec.SetHeaders[name]; ok {
			t.Errorf("响应头 %q 不应被 Lua 判定接受", name)
		}
	}
}

func TestDecisionOutputRedactsSensitiveText(t *testing.T) {
	req := RequestView{
		Headers: map[string]string{"authorization": "Bearer request-token", "cookie": "session=request-cookie"},
		Body:    "request body remains visible",
	}
	src := `
function handle(ctx)
  if ctx.headers["authorization"] ~= "Bearer request-token" then return "intercept" end
  if ctx.headers["cookie"] ~= "session=request-cookie" then return "intercept" end
  if ctx.body ~= "request body remains visible" then return "intercept" end
  return {
    action="observe",
    message="Authorization: Bearer decision-token",
    response_body="Cookie: response-cookie",
    headers={ ["x-safe"]="accepted", ["x-token"]="Bearer header-token", ["set-cookie"]="session=forbidden" },
    tags={"safe", "Cookie: tag-token", "Bearer tag-token"}
  }
end`

	dec := evalOne(t, src, req, nil)
	if dec.Action != "observe" {
		t.Fatalf("请求上下文应保持可读，得到 %+v", dec)
	}
	if dec.Message != "" || dec.ResponseBody != "" {
		t.Fatalf("敏感输出未被丢弃：%+v", dec)
	}
	if len(dec.SetHeaders) != 1 || dec.SetHeaders["x-safe"] != "accepted" {
		t.Fatalf("敏感响应头未被丢弃：%+v", dec.SetHeaders)
	}
	if len(dec.Tags) != 1 || dec.Tags[0] != "safe" {
		t.Fatalf("敏感标签未被丢弃：%+v", dec.Tags)
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

// TestSiteScopedScriptsExecuteInIsolation 验证站点脚本不会泄漏到其他站点，
// 同时全局脚本在每个站点继续执行。
// TestSiteScopedScriptsExecuteInIsolation verifies scoped scripts only execute for their site while global scripts continue to run.
func TestSiteScopedScriptsExecuteInIsolation(t *testing.T) {
	global := mustCompile(t, StagePre, `function handle(ctx) return nil end`)
	site1 := mustCompile(t, StagePre, `function handle(ctx) return "intercept" end`)
	site2 := mustCompile(t, StagePre, `function handle(ctx) return "drop" end`)
	site1ID, site2ID := uint(1), uint(2)
	site1.SetSiteID(&site1ID)
	site2.SetSiteID(&site2ID)

	e := silentEngine(nil)
	e.Reload([]*Script{global, site1, site2})

	for _, tt := range []struct {
		name   string
		siteID uint
		want   string
	}{
		{name: "site1", siteID: 1, want: "intercept"},
		{name: "site2", siteID: 2, want: "drop"},
		{name: "other-site", siteID: 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dec := e.Evaluate(context.Background(), StagePre, RequestView{SiteID: tt.siteID})
			if dec.Action != tt.want {
				t.Fatalf("SiteID=%d action = %q, want %q", tt.siteID, dec.Action, tt.want)
			}
		})
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
// 每次执行都创建新状态机；此用例防止未来改回复用时重新引入跨请求全局污染。
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

// TestStandardLibraryAndGlobalsDoNotLeak 验证脚本直接改写允许库和 _G 后，
// 同一脚本的下一次运行以及同一引擎的下一脚本都只能看到干净状态。
func TestStandardLibraryAndGlobalsDoNotLeak(t *testing.T) {
	e := silentEngine(nil)
	poison := mustCompile(t, StagePre, `
function handle(ctx)
  if _G.request_leak ~= nil then return "intercept" end
  if string.upper("x") ~= "X" then return "intercept" end
  if table.concat({"a", "b"}, ":") ~= "a:b" then return "intercept" end
  if math.abs(-7) ~= 7 then return "intercept" end
  _G = {request_leak = true}
  string.upper = function(_) return "poisoned" end
  table.concat = function(_) return "poisoned" end
  math.abs = function(_) return 0 end
  return nil
end`)
	e.Reload([]*Script{poison})

	for i := 0; i < 2; i++ {
		if dec := e.Evaluate(context.Background(), StagePre, RequestView{}); dec.HasAction() {
			t.Fatalf("第 %d 次运行看到了上一运行污染的库表或全局状态: %+v", i+1, dec)
		}
	}

	e.Reload([]*Script{mustCompile(t, StagePre, `
function handle(ctx)
  if _G.request_leak ~= nil then return "intercept" end
  if string.upper("x") ~= "X" then return "intercept" end
  if table.concat({"a", "b"}, ":") ~= "a:b" then return "intercept" end
  if math.abs(-7) ~= 7 then return "intercept" end
  if type(assert) ~= "function" or type(pairs) ~= "function" then return "intercept" end
  return nil
end`)})
	if dec := e.Evaluate(context.Background(), StagePre, RequestView{}); dec.HasAction() {
		t.Fatalf("下一脚本看到了前一脚本污染，或允许标准库不可用: %+v", dec)
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

func TestControlledContextExtensions(t *testing.T) {
	var logs []string
	var debugs []string
	req := RequestView{
		Response: ResponseView{
			StatusCode:  502,
			ContentType: "application/json",
			Headers:     map[string]string{"content-type": "application/json", "authorization": "secret"},
			Body:        "upstream error",
		},
		Config:  map[string]string{"mode": "safe"},
		Runtime: map[string]string{"instance": "node-1"},
		Metrics: map[string]float64{"requests": 12},
	}
	req.SetRuntimeHooks(func(level, message string) { logs = append(logs, level+":"+message) }, func(message string) { debugs = append(debugs, message) })
	src := `
function handle(ctx)
  if ctx.response.status_code ~= 502 or ctx.response.content_type ~= "application/json" then return "intercept" end
  if ctx.response.headers["authorization"] ~= "[redacted]" then return "intercept" end
  if ctx.response.body ~= "upstream error" then return "intercept" end
  if ctx.config.mode ~= "safe" or ctx.runtime.instance ~= "node-1" then return "intercept" end
  if ctx.metrics.requests ~= 12 then return "intercept" end
  ctx.log("warn", "seen")
  ctx.debug("trace")
  return "observe"
end`
	if dec := evalOne(t, src, req, nil); dec.Action != "observe" {
		t.Fatalf("受控上下文读取失败：%+v", dec)
	}
	if len(logs) != 1 || logs[0] != "warn:seen" {
		t.Fatalf("log 回调 = %v", logs)
	}
	if len(debugs) != 1 || debugs[0] != "trace" {
		t.Fatalf("debug 回调 = %v", debugs)
	}
}

func TestUnavailableKVAlwaysFailsOpen(t *testing.T) {
	for _, backend := range []struct {
		name string
		kv   KVBackend
	}{
		{name: "nil KV"},
		{name: "不可用 KV", kv: testKV{}},
	} {
		for _, verdict := range []string{"intercept", "drop"} {
			t.Run(backend.name+"/"+verdict, func(t *testing.T) {
				e := newSilentEngine(backend.kv)
				e.Reload([]*Script{mustCompile(t, StagePre, `function handle(ctx) return "`+verdict+`" end`)})
				if dec := e.Evaluate(context.Background(), StagePre, RequestView{}); dec.HasAction() {
					t.Fatalf("KV 不可用时脚本 %q 必须无判定，得到 %+v", verdict, dec)
				}
			})
		}
	}
}

func TestEvaluateDiscardsDecisionWhenKVFailsDuringScript(t *testing.T) {
	kv := &failingDuringRunKV{available: true}
	e := newSilentEngine(kv)
	e.Reload([]*Script{mustCompile(t, StagePre, `
function handle(ctx)
  ctx.kv.set("x", "y")
  return "intercept"
end`)})

	if dec := e.Evaluate(context.Background(), StagePre, RequestView{}); dec.HasAction() {
		t.Fatalf("KV 执行期间失效时必须丢弃终止判定：%+v", dec)
	}
}

type failingDuringRunKV struct {
	available bool
}

func (k *failingDuringRunKV) Available() bool         { return k != nil && k.available }
func (*failingDuringRunKV) Get(string) ([]byte, bool) { return nil, false }
func (k *failingDuringRunKV) Set(string, []byte, time.Duration) error {
	k.available = false
	return errors.New("kv unavailable")
}
func (*failingDuringRunKV) Delete(string)                             {}
func (*failingDuringRunKV) Incr(string, time.Duration) (int64, error) { return 0, nil }

func TestLuaAPIOutputLimits(t *testing.T) {
	src := `
function handle(ctx)
  local tags = {}
  for i = 1, 40 do tags[i] = string.rep("t", 2000) end
  local headers = {}
  for i = 1, 300 do headers["x-" .. tostring(i)] = string.rep("h", 5000) end
  return {action="observe", message=string.rep("m", 30000), response_body=string.rep("b", 30000), headers=headers, tags=tags}
end`
	dec := evalOne(t, src, RequestView{}, nil)
	if len(dec.Message) != maxAPIStringBytes || len(dec.ResponseBody) != maxResponseBody {
		t.Fatalf("输出字符串未截断：message=%d body=%d", len(dec.Message), len(dec.ResponseBody))
	}
	if len(dec.SetHeaders) != maxAPIMapEntries || len(dec.Tags) != maxDecisionTags {
		t.Fatalf("输出表项未限流：headers=%d tags=%d", len(dec.SetHeaders), len(dec.Tags))
	}
	for key, value := range dec.SetHeaders {
		if len(value) != maxHeaderValue {
			t.Fatalf("header %q 未截断：%d", key, len(value))
		}
	}
}

func TestTruncateStringPreservesUTF8Boundary(t *testing.T) {
	value := "abc世界"
	got := truncateString(value, 5)
	if got != "abc" {
		t.Fatalf("truncateString split UTF-8 boundary: %q", got)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("truncateString returned invalid UTF-8: %x", []byte(got))
	}
}

func TestLuaAPICallBudget(t *testing.T) {
	calls := 0
	req := RequestView{}
	req.SetRuntimeHooks(func(string, string) { calls++ }, nil)
	src := `
function handle(ctx)
  for i = 1, 256 do ctx.log("info", "x") end
  return "observe"
end`
	if dec := evalOne(t, src, req, nil); dec.Action != "observe" {
		t.Fatalf("API 调用预算不应改变合法判定：%+v", dec)
	}
	if calls != maxAPICalls {
		t.Fatalf("API 调用次数 = %d, want %d", calls, maxAPICalls)
	}
}
