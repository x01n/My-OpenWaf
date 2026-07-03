package repository

import "My-OpenWaf/internal/tlsmeta"

func normalizeTLSVersionFilter(raw string) string {
	if normalized := tlsmeta.NormalizeVersionToken(raw); normalized != "" {
		return normalized
	}
	return raw
}

func normalizeAccessLogFilter(f AccessLogFilter) AccessLogFilter {
	f.TLSVersion = normalizeTLSVersionFilter(f.TLSVersion)
	return f
}

func normalizeSecurityEventFilter(f SecurityEventFilter) SecurityEventFilter {
	f.TLSVersion = normalizeTLSVersionFilter(f.TLSVersion)
	return f
}

func normalizeFingerprintFilter(f FingerprintFilter) FingerprintFilter {
	f.TLSVersion = normalizeTLSVersionFilter(f.TLSVersion)
	return f
}

func normalizeRecordedResourceFilter(f RecordedResourceFilter) RecordedResourceFilter {
	f.TLSVersion = normalizeTLSVersionFilter(f.TLSVersion)
	return f
}
