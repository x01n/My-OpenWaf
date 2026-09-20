package store

import (
	"crypto/tls"
	"errors"
	"strings"
)

const MaxUpstreamMTLSPEMBytes = 256 << 10

var (
	// ErrSiteUpstreamMTLSUnpaired 上游客户端证书与私钥必须成对配置。
	ErrSiteUpstreamMTLSUnpaired = errors.New("upstream_tls_client_cert_pem and upstream_tls_client_key_pem must be provided together")
)

/**
 * NormalizeSiteUpstreamMTLS 规范化并校验站点级上游 mTLS 客户端证书字段。
 *
 * 返回 canonical 证书对（nil 证书 = 未配置），以及（certPEM、keyPEM、配置是否变化、错误）：
 *
 *   - 两字段均空白：视为未配置并规范化为一对 nil（消除空串残留）；
 *   - 仅其一非空白：错误（成对约束）；
 *   - 成对非空白：tls.X509KeyPair 解析必须成功，并规范化空白边缘（TrimSpace）；
 *   - 字段原值本就未配置且内容未变时 changed=false，便于写路径温存判断；
 *   - exceeded=false：两字段均受 256 KiB 约束（调用方决定执行 total 上限）。
 *
 * 热路径零成本：每次取配置只用 changed=false 的快速分支（纯空白检查），
 * 不做任何 X509KeyPair / SHA-256 / 大字符串分配。
 */
func NormalizeSiteUpstreamMTLS(certPEM, keyPEM string) (cert tls.Certificate, canonCert, canonKey string, configured, changed, exceeded bool, err error) {
	certTrim := strings.TrimSpace(certPEM)
	keyTrim := strings.TrimSpace(keyPEM)
	if len(certTrim) > MaxUpstreamMTLSPEMBytes {
		return cert, "", "", true, false, true, nil
	}
	if len(keyTrim) > MaxUpstreamMTLSPEMBytes {
		return cert, "", "", true, false, true, nil
	}
	plain := certTrim == "" && keyTrim == ""
	paired := certTrim != "" && keyTrim != ""
	if !plain && !paired {
		return cert, "", "", true, false, false, ErrSiteUpstreamMTLSUnpaired
	}
	if plain {
		return cert, "", "", false, certPEM != "" || keyPEM != "", false, nil
	}
	changed = certTrim != certPEM || keyTrim != keyPEM
	pair, err := tls.X509KeyPair([]byte(certTrim), []byte(keyTrim))
	if err != nil {
		return cert, "", "", true, changed, false, err
	}
	return pair, certTrim, keyTrim, true, changed, false, nil
}
