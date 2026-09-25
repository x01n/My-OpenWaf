package dataplane

import (
	"context"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/waf/jsplugin"
)

// fakeResponseExecutorForRuntimeTest 给出固定的失败结果，验证存取值而不触发执行。
type fakeResponseExecutorForRuntimeTest struct{}

func (fakeResponseExecutorForRuntimeTest) ExecuteResponse(context.Context, *jsplugin.Script, jsplugin.ResponseSnapshot) (jsplugin.ResponseMutationPlan, error) {
	return jsplugin.ResponseMutationPlan{}, nil
}

// TestJSResponseRuntimeContextRoundTrip 固定执行器与脚本快照经由 hertz
// 上下文存取往返，未挂接与空请求上下文都返回零值。
func TestJSResponseRuntimeContextRoundTrip(t *testing.T) {
	c := &app.RequestContext{}
	if executor, scripts := JSResponseRuntimeFromRequestContext(c); executor != nil || scripts != nil {
		t.Fatalf("empty request context = %v/%v, want nil", executor, scripts)
	}

	script := &jsplugin.Script{}
	executor := fakeResponseExecutorForRuntimeTest{}
	ContextWithJSResponseRuntime(c, executor, []*jsplugin.Script{script})
	gotExecutor, gotScripts := JSResponseRuntimeFromRequestContext(c)
	if gotExecutor == nil || gotExecutor != executor {
		t.Fatalf("round-trip executor = %v, want %v", gotExecutor, executor)
	}
	if len(gotScripts) != 1 || gotScripts[0] != script {
		t.Fatalf("round-trip scripts = %#v", gotScripts)
	}

	ContextWithJSResponseRuntime(nil, executor, nil)
	if executor, scripts := JSResponseRuntimeFromRequestContext(nil); executor != nil || scripts != nil {
		t.Fatalf("nil request context = %v/%v, want nil", executor, scripts)
	}
}

// TestJSPluginEngineAsResponseExecutor 固定接口视图转换的 nil 语义。
func TestJSPluginEngineAsResponseExecutor(t *testing.T) {
	if got := jspluginEngineAsResponseExecutor(nil); got != nil {
		t.Fatalf("nil executor view = %v, want nil", got)
	}
}
