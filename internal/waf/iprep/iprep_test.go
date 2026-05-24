package iprep

import (
	"net"
	"testing"
)

func TestParseIPListEntryCIDR(t *testing.T) {
	e, ok := ParseIPListEntry("10.0.0.0/8", "cidr")
	if !ok || e.CIDR == nil || e.Note != "cidr" {
		t.Fatalf("unexpected parse result: %#v %v", e, ok)
	}
}

func TestParseIPListEntrySingleIP(t *testing.T) {
	e, ok := ParseIPListEntry("192.168.1.1", "single")
	if !ok || e.Single == nil || !e.Single.Equal(net.ParseIP("192.168.1.1")) {
		t.Fatalf("unexpected parse result: %#v %v", e, ok)
	}
}
