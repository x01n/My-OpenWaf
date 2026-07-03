package tlsmeta

import "testing"

func TestFormatExtensionsUsesExactDecimalOrder(t *testing.T) {
	got := FormatExtensions([]uint16{0, 16, 43, 65281})
	want := "0,16,43,65281"
	if got != want {
		t.Fatalf("FormatExtensions() = %q, want %q", got, want)
	}
}

func TestFormatCurvesUsesExactDecimalOrder(t *testing.T) {
	got := FormatCurves([]uint16{29, 23, 24})
	want := "29,23,24"
	if got != want {
		t.Fatalf("FormatCurves() = %q, want %q", got, want)
	}
}

func TestFormatPointFormatsUsesExactDecimalOrder(t *testing.T) {
	got := FormatPointFormats([]uint8{0, 1, 2})
	want := "0,1,2"
	if got != want {
		t.Fatalf("FormatPointFormats() = %q, want %q", got, want)
	}
}
