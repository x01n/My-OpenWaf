package security

import (
	"errors"
	"strings"

	"golang.org/x/net/http/httpguts"
)

var errInvalidHostHeaderValue = errors.New("invalid host header")

// NormalizeHostHeaderValue 对 Host 头取值做去空白、punycode 与合法性校验。
func NormalizeHostHeaderValue(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}

	normalized, err := httpguts.PunycodeHostPort(raw)
	if err != nil {
		return "", errInvalidHostHeaderValue
	}
	if !httpguts.ValidHostHeader(normalized) {
		return "", errInvalidHostHeaderValue
	}
	return normalized, nil
}
