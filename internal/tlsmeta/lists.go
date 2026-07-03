package tlsmeta

import (
	"strconv"
	"strings"
)

func FormatExtensions(extensions []uint16) string {
	return formatUint16List(extensions)
}

func FormatCurves(curves []uint16) string {
	return formatUint16List(curves)
}

func FormatPointFormats(pointFormats []uint8) string {
	if len(pointFormats) == 0 {
		return ""
	}
	var b strings.Builder
	for i, pointFormat := range pointFormats {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatUint(uint64(pointFormat), 10))
	}
	return b.String()
}

func formatUint16List(values []uint16) string {
	if len(values) == 0 {
		return ""
	}
	var b strings.Builder
	for i, value := range values {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatUint(uint64(value), 10))
	}
	return b.String()
}
