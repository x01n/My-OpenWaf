package pipeline

import (
	"testing"
)

// TestRequestMutationAppliesToContext 锁定 Lua pre 请求改写在管道上下文内的
// 生效语义：后续阶段看到的必须是改写后的值。
func TestRequestMutationAppliesToContext(t *testing.T) {
	ctx := &RequestCtx{
		Method: "GET", Path: "/original", RawQuery: "keep=1",
		Headers: map[string]string{"x-remove": "gone", "x-keep": "kept"},
		Body:    []byte("old-body"),
	}
	method, path, query, body := "POST", "/rewritten", "debug=1", "new-body"
	if err := ctx.ApplyRequestMutation(RequestMutator{
		Method:        &method,
		Path:          &path,
		RawQuery:      &query,
		Body:          &body,
		SetHeaders:    map[string]string{"X-New": "1", "User-Agent": "rewritten-agent"},
		DeleteHeaders: []string{"X-Remove"},
	}); err != nil {
		t.Fatalf("ApplyRequestMutation error = %v", err)
	}
	if ctx.Method != "POST" || ctx.Path != "/rewritten" || ctx.RawQuery != "debug=1" {
		t.Fatalf("mutation not applied: %#v", ctx)
	}
	if string(ctx.Body) != "new-body" {
		t.Fatalf("body = %q, want new-body", ctx.Body)
	}
	if ctx.Headers["x-new"] != "1" {
		t.Fatalf("headers = %#v, want x-new", ctx.Headers)
	}
	if _, exists := ctx.Headers["x-remove"]; exists {
		t.Fatalf("headers = %#v, want x-remove deleted", ctx.Headers)
	}
	if ctx.Headers["x-keep"] != "kept" {
		t.Fatalf("headers = %#v, want x-keep untouched", ctx.Headers)
	}
	if ctx.UserAgent != "rewritten-agent" {
		t.Fatalf("user agent = %q, want rewritten-agent", ctx.UserAgent)
	}
}

// TestRequestMutationIsAllOrNothing 锁定「整体校验、整体应用」：任一项非法
// 时上下文保持原状，不会留下部分改写。
func TestRequestMutationIsAllOrNothing(t *testing.T) {
	method := "POST"
	path := "//evil.example/x"
	ctx := &RequestCtx{Method: "GET", Path: "/original", Headers: map[string]string{"x-keep": "kept"}}
	if err := ctx.ApplyRequestMutation(RequestMutator{Method: &method, Path: &path}); err == nil {
		t.Fatal("invalid path was accepted")
	}
	if ctx.Method != "GET" || ctx.Path != "/original" {
		t.Fatalf("partial mutation applied: %#v", ctx)
	}
}

// TestRequestMutationRejectsReservedHeaders 锁定保留头不可被脚本增删。
func TestRequestMutationRejectsReservedHeaders(t *testing.T) {
	for _, mutation := range []RequestMutator{
		{SetHeaders: map[string]string{"Host": "evil.example"}},
		{DeleteHeaders: []string{"host"}},
		{SetHeaders: map[string]string{"X-Bad": "a\r\nb"}},
		{SetHeaders: map[string]string{"Bad Header": "v"}},
	} {
		ctx := &RequestCtx{Headers: map[string]string{}}
		if err := ctx.ApplyRequestMutation(mutation); err == nil {
			t.Fatalf("mutation %#v was accepted", mutation)
		}
	}
}

// TestDrainRequestMutationClears 锁定取出即清空，避免同一份改写被应用两次。
func TestDrainRequestMutationClears(t *testing.T) {
	ctx := &RequestCtx{Headers: map[string]string{}}
	path := "/x"
	ctx.SetRequestMutation(RequestMutator{Path: &path})
	if _, ok := ctx.DrainRequestMutation(); !ok {
		t.Fatal("first drain = false")
	}
	if _, ok := ctx.DrainRequestMutation(); ok {
		t.Fatal("second drain = true, want cleared")
	}
}

// TestResponseMutationsKeepOrder 锁定多条响应改写按脚本顺序累积。
func TestResponseMutationsKeepOrder(t *testing.T) {
	ctx := &RequestCtx{}
	first, second := "first", "second"
	ctx.AppendResponseMutation(ResponseMutator{ScriptName: "a", Body: &first})
	ctx.AppendResponseMutation(ResponseMutator{ScriptName: "b", Body: &second})
	mutations := ctx.DrainResponseMutations()
	if len(mutations) != 2 || mutations[0].ScriptName != "a" || mutations[1].ScriptName != "b" {
		t.Fatalf("mutations = %#v, want [a b]", mutations)
	}
	if again := ctx.DrainResponseMutations(); again != nil {
		t.Fatalf("second drain = %#v, want nil", again)
	}
}

// TestReleaseCtxClearsMutations 锁定池化复用的清零：上一请求的改写不能泄漏
// 到下一个请求。
func TestReleaseCtxClearsMutations(t *testing.T) {
	ctx := AcquireCtx()
	path := "/leaked"
	body := "leaked"
	ctx.SetRequestMutation(RequestMutator{Path: &path})
	ctx.AppendResponseMutation(ResponseMutator{ScriptName: "leak", Body: &body})
	ReleaseCtx(ctx)

	if _, ok := ctx.DrainRequestMutation(); ok {
		t.Fatal("request mutation survived ReleaseCtx")
	}
	if mutations := ctx.DrainResponseMutations(); mutations != nil {
		t.Fatalf("response mutations survived ReleaseCtx: %#v", mutations)
	}
	ReleaseCtx(ctx)
}
