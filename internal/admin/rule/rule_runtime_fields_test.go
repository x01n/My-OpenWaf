package rule

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/store"
)

/**
 * TestUpdateRuleCannotRewriteCreatedAt 锁定运行态字段在更新路径上的不可写性。
 *
 * `UpdateRule` 采用「先 Get 再用 c.BindJSON(existing) 直接绑定 store 模型」的
 * 写法，store.Rule 的 CreatedAt/UpdatedAt 都带可写 json tag，请求体只要带上
 * `created_at` 就会覆盖数据库中的原始创建时间。审计与排序都依赖该字段，
 * 必须只允许白名单字段进入绑定。
 */
func TestUpdateRuleCannotRewriteCreatedAt(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)
	seed := store.Rule{Name: "orig", PolicyID: 1, Phase: store.PhaseCustom,
		Pattern: "block_path:/orig", Action: store.ActionIntercept, Priority: 3, Enabled: true}
	if err := repo.Create(&seed); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	before, err := repo.Get(seed.ID)
	if err != nil {
		t.Fatalf("load rule: %v", err)
	}
	forged := before.CreatedAt.Add(-48 * time.Hour)

	payload, err := json.Marshal(map[string]any{
		"name":       "renamed",
		"created_at": forged.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	ctx := invokePersistedRuleHandler(t, UpdateRule(repo, func() error { return nil }),
		"/api/v1/rules/1/update", payload)
	ctx.Params = param.Params{{Key: "id", Value: "1"}}
	UpdateRule(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	after, err := repo.Get(seed.ID)
	if err != nil {
		t.Fatalf("reload rule: %v", err)
	}
	if !after.CreatedAt.Equal(before.CreatedAt) {
		t.Fatalf("created_at 被请求体改写: %s -> %s", before.CreatedAt, after.CreatedAt)
	}
	if after.Name != "renamed" {
		t.Fatalf("name = %q, want renamed（白名单字段必须仍然可写）", after.Name)
	}
	if after.Pattern != "block_path:/orig" {
		t.Fatalf("pattern = %q, want 原值保留（未提交字段不得被清零）", after.Pattern)
	}
}
