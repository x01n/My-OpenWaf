package observability

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// errTestReload 是各用例中模拟 reload 失败时统一返回的错误。
var errTestReload = errors.New("reload boom")

/**
 * requireErrorMessage 断言响应体是 {"error": "..."} 形式且消息完全匹配。
 *
 * @param body 处理器写入的原始响应体
 * @param want 期望的 error 字段值
 */
func requireErrorMessage(t *testing.T, body []byte, want string) {
	t.Helper()
	var resp map[string]string
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode error response: %v (body=%s)", err, body)
	}
	if resp["error"] != want {
		t.Fatalf("error = %q, want %q", resp["error"], want)
	}
}

func newSiteRepoForTest(t *testing.T) *repository.SiteRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}); err != nil {
		t.Fatalf("migrate sites: %v", err)
	}
	return repository.NewSiteRepo(db)
}

func invokeSiteGetHandler(t *testing.T, handler app.HandlerFunc, siteID uint, path string, query url.Values) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("GET")
	uri := path
	if encoded := query.Encode(); encoded != "" {
		uri += "?" + encoded
	}
	req.SetRequestURI(uri)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: strconv.FormatUint(uint64(siteID), 10)}}
	handler(context.Background(), ctx)
	return ctx
}

func invokeSiteRouteHandler(t *testing.T, handler app.HandlerFunc, method, uri string, params param.Params, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(payload)
	}

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = params
	handler(context.Background(), ctx)
	return ctx
}

func idParams(id string) param.Params {
	return param.Params{{Key: "id", Value: id}}
}
