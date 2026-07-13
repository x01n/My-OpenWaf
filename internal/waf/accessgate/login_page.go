package accessgate

import (
	"fmt"
	"html/template"
	"strings"
)

// loginPageData 登录页面模板数据。
type loginPageData struct {
	SiteHost          string
	HasSharedPassword bool
	Providers         []ProviderConfig
	ErrorMsg          string
	LoginAction       string
	LogoutAction      string
}

// loginPageTmpl 独立登录页面 HTML 模板。
var loginPageTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>访问验证 - {{.SiteHost}}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%)}
.card{background:#fff;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.3);padding:2.5rem;width:100%;max-width:400px}
.card h1{font-size:1.5rem;color:#1a1a2e;margin-bottom:.5rem;text-align:center}
.card .host{font-size:.875rem;color:#666;text-align:center;margin-bottom:1.5rem}
.error{background:#fee;border:1px solid #fcc;color:#c33;padding:.75rem;border-radius:8px;margin-bottom:1rem;font-size:.875rem}
.section{margin-bottom:1.5rem;padding-bottom:1.5rem;border-bottom:1px solid #eee}
.section:last-child{border-bottom:none;margin-bottom:0;padding-bottom:0}
.section h2{font-size:.875rem;color:#888;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.75rem}
label{display:block;font-size:.875rem;color:#333;margin-bottom:.25rem}
input[type="text"],input[type="password"]{width:100%;padding:.625rem .75rem;border:1px solid #ddd;border-radius:8px;font-size:.9375rem;transition:border-color .2s}
input:focus{outline:none;border-color:#667eea}
button{width:100%;padding:.75rem;border:none;border-radius:8px;font-size:1rem;font-weight:500;cursor:pointer;transition:transform .1s,box-shadow .2s}
button:active{transform:scale(.98)}
.btn-primary{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;box-shadow:0 4px 15px rgba(102,126,234,.4)}
.btn-primary:hover{box-shadow:0 6px 20px rgba(102,126,234,.6)}
.btn-oauth{background:#f8f9fa;color:#333;border:1px solid #ddd;margin-bottom:.5rem}
.btn-oauth:hover{background:#e9ecef}
.form-group{margin-bottom:.75rem}
.divider{text-align:center;color:#999;font-size:.8125rem;margin:1rem 0;position:relative}
.divider::before,.divider::after{content:"";position:absolute;top:50%;width:40%;height:1px;background:#ddd}
.divider::before{left:0}
.divider::after{right:0}
</style>
</head>
<body>
<div class="card">
<h1>访问验证</h1>
<p class="host">{{.SiteHost}}</p>
{{if .ErrorMsg}}<div class="error">{{.ErrorMsg}}</div>{{end}}
{{if .HasSharedPassword}}
<div class="section">
<h2>访问密码</h2>
<form method="POST" action="{{.LoginAction}}">
<input type="hidden" name="auth_type" value="shared_password">
<div class="form-group">
<input type="password" name="password" placeholder="输入访问密码" required autocomplete="current-password">
</div>
<button type="submit" class="btn-primary">验证</button>
</form>
</div>
{{end}}
{{range .Providers}}
{{if eq .Type "password"}}
<div class="section">
<h2>用户登录</h2>
<form method="POST" action="{{$.LoginAction}}">
<input type="hidden" name="auth_type" value="user_password">
<input type="hidden" name="provider_id" value="{{.ID}}">
<div class="form-group">
<input type="text" name="username" placeholder="用户名" required autocomplete="username">
</div>
<div class="form-group">
<input type="password" name="password" placeholder="密码" required autocomplete="current-password">
</div>
<button type="submit" class="btn-primary">登录</button>
</form>
</div>
{{else}}
<div class="section">
<button type="button" class="btn-oauth" onclick="location.href='/__owaf/access/oauth/start/{{.ID}}'">通过 {{.Name}} 登录</button>
</div>
{{end}}
{{end}}
</div>
</body>
</html>`))

// RenderLoginPage 渲染站点访问控制登录页面。
func RenderLoginPage(siteHost string, cfg Config, errorMsg string) []byte {
	data := loginPageData{
		SiteHost:          siteHost,
		HasSharedPassword: cfg.SharedPasswordHash != "",
		Providers:         cfg.Providers,
		ErrorMsg:          errorMsg,
		LoginAction:       "/__owaf/access/verify",
		LogoutAction:      "/__owaf/access/logout",
	}

	var buf strings.Builder
	if err := loginPageTmpl.Execute(&buf, data); err != nil {
		return []byte(fmt.Sprintf("<!DOCTYPE html><html><body><p>Error rendering login page: %s</p></body></html>", template.HTMLEscapeString(err.Error())))
	}
	return []byte(buf.String())
}
