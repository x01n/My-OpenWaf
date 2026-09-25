package challenge

import (
	"strings"
	"testing"
)

// TestBrowserSignTemplateCarriesTicketSig 断言 GM 票据签名的注入位已进入
// 混淆后的注入模板（TicketSigPub/TicketSigB64 占位与请求签名管线并存）。
func TestBrowserSignTemplateCarriesTicketSig(t *testing.T) {
	SetChallengeSecret([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	ticket := IssueBrowserSignTicket(1, 60)
	if ticket.TicketSigPub == "" || ticket.TicketSigB64 == "" {
		t.Fatal("issued ticket must carry the SM2 signature material")
	}
	html := string(InjectBrowserSignIntoHTML([]byte("<html><body></body></html>"), ticket))

	// 混淆后只知道占位会被改名，但 gm_sm3_hmac 请求签名管线与新验证材料必须存在。
	if !strings.Contains(html, "gm_sm3_hmac") {
		t.Fatal("injected script lost the GM request-sign pipeline")
	}
	if !strings.Contains(html, ticket.TicketSigB64) {
		t.Fatal("injected script lost the ticket SM2 signature")
	}
}
