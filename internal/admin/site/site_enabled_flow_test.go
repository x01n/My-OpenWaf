package site

import (
	"bytes"
	"testing"

	"My-OpenWaf/internal/store"
)

// TestCreateSiteEnabledFlow 端到端验证「新建站点时的启用状态」在 handler 层的完整流程。
//
// 这里同时钉住两个方向，单靠任何一层都保证不了：
//   - 请求体显式传 "enabled": false，站点必须停用。Site.Enabled 带 gorm default:true，
//     若 handler 不预填默认值、repository 又直接 db.Create，GORM 会把这个 false 当成
//     「没设过」而套用默认值——用户建了个以为不会生效的站点，它却立刻接受流量并代理到上游。
//   - 请求体压根不带 enabled 字段时，仍要沿用默认值 true。修零值不能把默认值机制废掉，
//     否则新建的站点默认不工作，是另一个方向的事故。
//
// Go 的值类型区分不了「没传」与「传了 false」，只有 handler 能从原始 JSON 看出差别，
// 所以这条流程必须在 handler 层验证，repository 层的测试覆盖不到。
func TestCreateSiteEnabledFlow(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantEnabled bool
	}{
		{
			name: "显式停用",
			body: `{
				"host":"staged.example.com",
				"bind":":18450",
				"upstream_urls":["http://127.0.0.1:8800"],
				"enabled":false
			}`,
			wantEnabled: false,
		},
		{
			name: "显式启用",
			body: `{
				"host":"live.example.com",
				"bind":":18451",
				"upstream_urls":["http://127.0.0.1:8800"],
				"enabled":true
			}`,
			wantEnabled: true,
		},
		{
			name: "未提供 enabled 字段时沿用默认值",
			body: `{
				"host":"default.example.com",
				"bind":":18452",
				"upstream_urls":["http://127.0.0.1:8800"]
			}`,
			wantEnabled: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo, _ := newSiteRepoWithDB(t)
			ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), []byte(tc.body))
			if ctx.Response.StatusCode() != 201 {
				t.Fatalf("status = %d, body=%s", ctx.Response.StatusCode(),
					bytes.TrimSpace(ctx.Response.Body()))
			}

			items, total, err := repo.List(0, 10)
			if err != nil {
				t.Fatalf("list sites: %v", err)
			}
			if total != 1 || len(items) != 1 {
				t.Fatalf("expected one site, total=%d items=%d", total, len(items))
			}
			if items[0].Enabled != tc.wantEnabled {
				t.Errorf("Enabled = %v, want %v", items[0].Enabled, tc.wantEnabled)
			}
		})
	}
}

// TestCreateSiteAppliesModelDefaults 验证未提供的字段拿到模型声明的默认值。
//
// 默认值来自模型标签而不是 handler 里另抄一份，这条用例守住这一点：
// 一旦有人在 handler 里手写默认值、又与模型标签不一致，这里就会失配。
func TestCreateSiteAppliesModelDefaults(t *testing.T) {
	repo, _ := newSiteRepoWithDB(t)
	body := []byte(`{
		"host":"defaults.example.com",
		"bind":":18453",
		"upstream_urls":["http://127.0.0.1:8800"]
	}`)
	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("status = %d, body=%s", ctx.Response.StatusCode(),
			bytes.TrimSpace(ctx.Response.Body()))
	}

	items, _, err := repo.List(0, 10)
	if err != nil {
		t.Fatalf("list sites: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one site, got %d", len(items))
	}
	got := items[0]

	// 期望值直接取自模型标签，避免在测试里写死另一份常量。
	var want store.Site
	if err := store.ApplyModelDefaults(&want); err != nil {
		t.Fatalf("apply model defaults: %v", err)
	}
	if got.Network != want.Network {
		t.Errorf("Network = %q, want %q", got.Network, want.Network)
	}
	if got.MaxBodyBytes != want.MaxBodyBytes {
		t.Errorf("MaxBodyBytes = %d, want %d", got.MaxBodyBytes, want.MaxBodyBytes)
	}
	if got.BlockStatus != want.BlockStatus {
		t.Errorf("BlockStatus = %d, want %d", got.BlockStatus, want.BlockStatus)
	}
	if got.XFFMode != want.XFFMode {
		t.Errorf("XFFMode = %q, want %q", got.XFFMode, want.XFFMode)
	}
}
