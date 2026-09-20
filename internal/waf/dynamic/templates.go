package dynamic

import (
	"bytes"
	"embed"
	"html/template"
)

//go:embed templates/html-bootstrap.html
var dynamicTemplateFS embed.FS

var htmlBootstrapTemplate = template.Must(
	template.ParseFS(dynamicTemplateFS, "templates/html-bootstrap.html"),
)

type htmlBootstrapData struct {
	CSPNonce  string
	Data      string
	IV        string
	Wrap      string
	KEK       string
	Ticket    string
	Key       string
	TTL       int
	Bootstrap template.JS
}

func renderHTMLBootstrap(env envelope, cspNonce string) ([]byte, error) {
	var buf bytes.Buffer
	err := htmlBootstrapTemplate.Execute(&buf, htmlBootstrapData{
		CSPNonce:  cspNonce,
		Data:      env.data,
		IV:        env.iv,
		Wrap:      env.wrap,
		KEK:       env.kek,
		Ticket:    env.ticket,
		Key:       env.key,
		TTL:       env.ttl,
		Bootstrap: template.JS(htmlBootstrapScript),
	})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
