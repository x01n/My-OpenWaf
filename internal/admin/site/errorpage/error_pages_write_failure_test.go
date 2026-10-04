package errorpage

import (
	"bytes"
	"testing"
)

func TestUpdateSiteErrorPagesReturns500WhenPersistFails(t *testing.T) {
	repo, db := newSiteRepoWithDB(t)
	item := seedSiteWithErrorPages(t, repo, `{}`)
	failSubsequentUpdates(t, db)

	body := []byte(`{"error_pages":{"503":{"status_code":503,"title":"Down","html":"<p>down</p>","content_type":"text/html"}}}`)
	ctx := invokeSiteErrorPagesHandler(t, UpdateSiteErrorPages(repo, func() error { return nil }), item.ID, body)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), errTestWrite.Error())
}
