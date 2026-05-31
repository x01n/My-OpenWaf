package challenge

import (
	"fmt"

	"github.com/cloudwego/hertz/pkg/app"
)

func prepareChallengeResponseHeaders(c *app.RequestContext, reqID string) {
	c.Response.Header.Set("X-Request-ID", reqID)
	c.Response.Header.Del("Server")
	c.Response.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")
}

// WriteCaptchaChallengeResponse renders a standalone CAPTCHA challenge page.
func WriteCaptchaChallengeResponse(c *app.RequestContext, reqID string, cm *CaptchaManager, captchaType CaptchaType, statusCode int) {
	prepareChallengeResponseHeaders(c, reqID)
	challenge, err := cm.Generate(captchaType)
	if err != nil {
		c.String(500, "captcha generation failed")
		return
	}
	html := fmt.Sprintf(captchaPageHTML, renderCaptchaHTML(challenge), challenge.SessionID, challenge.Prompt, inputModeForCaptcha(challenge.Type), reqID)
	c.Data(statusCode, "text/html; charset=utf-8", []byte(html))
}

func renderCaptchaHTML(challenge *CaptchaChallenge) string {
	if challenge == nil {
		return ""
	}
	switch CaptchaType(challenge.Type) {
	case CaptchaTypeClick:
		return fmt.Sprintf(`<div class="captcha-stack"><img src="%s" alt="CAPTCHA"><img class="thumb" src="%s" alt="target"></div>`, challenge.MasterImg, challenge.ThumbImg)
	case CaptchaTypeSlide:
		return fmt.Sprintf(`<div class="captcha-stack"><img src="%s" alt="CAPTCHA"><img class="thumb slide-thumb" src="%s" alt="slider"></div>`, challenge.MasterImg, challenge.ThumbImg)
	case CaptchaTypeRotate:
		return fmt.Sprintf(`<div class="captcha-stack rotate-captcha"><img src="%s" alt="CAPTCHA"><img class="thumb" src="%s" alt="target"></div>`, challenge.MasterImg, challenge.ThumbImg)
	default:
		return fmt.Sprintf(`<img src="%s" alt="CAPTCHA">`, challenge.MasterImg)
	}
}

func inputModeForCaptcha(captchaType string) string {
	switch CaptchaType(captchaType) {
	case CaptchaTypeClick:
		return "按顺序输入点击坐标 JSON"
	case CaptchaTypeSlide:
		return "输入滑块偏移量 JSON"
	case CaptchaTypeRotate:
		return "输入旋转角度 JSON"
	default:
		return "输入计算结果"
	}
}

const captchaPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Verification</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,"Helvetica Neue",sans-serif;background:linear-gradient(160deg,#f0fdfa 0%%,#f8fafc 40%%,#f1f5f9 100%%);display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:16px;box-shadow:0 4px 32px rgba(0,0,0,.08),0 1px 4px rgba(0,0,0,.04);padding:48px 40px;max-width:440px;width:92%%;text-align:center}
.icon{font-size:48px;margin-bottom:12px;line-height:1.2}
h1{font-size:1.2rem;font-weight:600;color:#334155;margin-bottom:4px}
.sub{color:#64748b;font-size:.875rem;margin-bottom:6px}
.divider{width:48px;height:3px;background:#14b8a6;border-radius:2px;margin:16px auto 24px}
.captcha-box{background:#f8fafc;border-radius:12px;padding:16px;margin-bottom:4px;border:1px solid #e2e8f0}
.captcha-box img{max-width:100%%;border-radius:8px;display:block;margin:0 auto}
.captcha-stack{display:grid;gap:10px}.captcha-stack .thumb{max-height:84px;object-fit:contain}.slide-thumb{background:#e2e8f0;padding:6px}.rotate-captcha .thumb{max-height:120px}
input[type=text]{width:100%%;padding:14px 16px;border:2px solid #e2e8f0;border-radius:10px;font-size:1rem;margin-top:16px;outline:none;transition:border-color .2s,box-shadow .2s;background:#f8fafc}
input[type=text]:focus{border-color:#14b8a6;box-shadow:0 0 0 3px rgba(20,184,166,.12);background:#fff}
.btn{width:100%%;padding:14px;background:linear-gradient(135deg,#14b8a6,#0d9488);color:#fff;border:none;border-radius:10px;font-size:1rem;font-weight:500;cursor:pointer;margin-top:16px;transition:opacity .2s,transform .1s}
.btn:hover{opacity:.92}.btn:active{transform:scale(.98)}
.rid{color:#94a3b8;font-size:.7rem;margin-top:20px}
.footer{margin-top:20px;padding-top:14px;border-top:1px solid #f1f5f9;font-size:.7rem;color:#94a3b8}
</style>
</head>
<body>
<div class="card">
<div class="icon">&#128274;</div>
<h1>Security Verification / 安全验证</h1>
<p class="sub">Please solve the challenge to continue</p>
<p class="sub">请完成安全验证以继续访问</p>
<div class="divider"></div>
<div class="captcha-box">%s</div>
<form method="POST" action="/__owaf/captcha/verify">
<input type="hidden" name="__waf_captcha_session" value="%s">
<input type="text" name="__waf_captcha_answer" placeholder="%s" aria-label="%s" autocomplete="off" autofocus>
<button type="submit" class="btn">Submit / 提交</button>
</form>
<p class="rid">Request ID: %s</p>
<div class="footer">Protected by My-OpenWAF</div>
</div>
</body>
</html>`

// WriteChainChallengeResponse starts a chain challenge and renders the first step.
func WriteChainChallengeResponse(c *app.RequestContext, reqID string, cm *ChainChallengeManager, statusCode int) {
	prepareChallengeResponseHeaders(c, reqID)
	originalURL := string(c.Request.URI().RequestURI())
	_, html := cm.StartChain(originalURL)
	c.Data(statusCode, "text/html; charset=utf-8", []byte(html))
}
