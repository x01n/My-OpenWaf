package security

import (
	"errors"
	"strings"

	"golang.org/x/net/http/httpguts"
)

var errInvalidHostHeaderValue = errors.New("invalid host header")

// NormalizeHostHeaderValue trims, punycodes, and validates a Host header value.
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

