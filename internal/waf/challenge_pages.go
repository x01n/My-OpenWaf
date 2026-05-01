package waf

import (
	"fmt"

	"github.com/cloudwego/hertz/pkg/app"
)

// WriteCaptchaChallengeResponse renders a standalone CAPTCHA challenge page.
func WriteCaptchaChallengeResponse(c *app.RequestContext, reqID string, cm *CaptchaManager) {
	challenge, err := cm.Generate(CaptchaTypeMath)
	if err != nil {
		c.String(500, "captcha generation failed")
		return
	}
	html := fmt.Sprintf(captchaPageHTML, challenge.MasterImg, challenge.SessionID, challenge.Prompt, reqID)
	c.Data(403, "text/html; charset=utf-8", []byte(html))
}

const captchaPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CAPTCHA Verification</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.ct{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.1);padding:40px;max-width:400px;width:90%%;text-align:center}
.icon{font-size:42px;margin-bottom:12px}
h1{font-size:20px;color:#1a1a2e;margin-bottom:8px}
.sub{color:#666;font-size:14px;margin-bottom:24px}
img{max-width:100%%;border-radius:8px;border:1px solid #e0e0e0}
input[type=text]{width:100%%;padding:12px;border:2px solid #e0e0e0;border-radius:8px;font-size:16px;margin-top:14px;outline:none}
input[type=text]:focus{border-color:#4a90d9}
.btn{width:100%%;padding:12px;background:#4a90d9;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;margin-top:16px}
.btn:hover{background:#357abd}
.rid{color:#aaa;font-size:11px;margin-top:16px}
</style>
</head>
<body>
<div class="ct">
<div class="icon">&#128272;</div>
<h1>Verification Required</h1>
<p class="sub">Please solve the challenge below to continue</p>
<img src="%s" alt="CAPTCHA">
<form method="POST" action="/__owaf/captcha/verify">
<input type="hidden" name="__waf_captcha_session" value="%s">
<input type="text" name="__waf_captcha_answer" placeholder="%s" autocomplete="off" autofocus>
<button type="submit" class="btn">Submit</button>
</form>
<p class="rid">Request ID: %s</p>
</div>
</body>
</html>`

// WriteChainChallengeResponse starts a chain challenge and renders the first step.
func WriteChainChallengeResponse(c *app.RequestContext, reqID string, cm *ChainChallengeManager) {
	originalURL := string(c.Request.URI().RequestURI())
	_, html := cm.StartChain(originalURL)
	c.Data(403, "text/html; charset=utf-8", []byte(html))
}
