package acme

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeCAAResolver map[string]fakeCAAResponse

type fakeCAAResponse struct {
	records []CAARecord
	err     error
}

func (r fakeCAAResolver) LookupCAA(ctx context.Context, domain string) ([]CAARecord, error) {
	resp, ok := r[domain]
	if !ok {
		return nil, errCAANotFound
	}
	return resp.records, resp.err
}

func TestCheckCAAIssuanceAllowsWhenNoCAARecordsExist(t *testing.T) {
	err := CheckCAAIssuance(context.Background(), "www.example.com", CAAPolicy{
		Enabled:        true,
		AllowedIssuers: []string{DefaultCAAAllowedIssuer},
		Resolver:       fakeCAAResolver{},
	})
	if err != nil {
		t.Fatalf("CheckCAAIssuance() error = %v, want nil", err)
	}
}

func TestCheckCAAIssuanceAllowsConfiguredIssuer(t *testing.T) {
	err := CheckCAAIssuance(context.Background(), "www.example.com", CAAPolicy{
		Enabled:        true,
		AllowedIssuers: []string{DefaultCAAAllowedIssuer},
		Resolver: fakeCAAResolver{
			"example.com": {records: []CAARecord{{Tag: "issue", Value: "letsencrypt.org; accounturi=https://example.test/acct"}}},
		},
	})
	if err != nil {
		t.Fatalf("CheckCAAIssuance() error = %v, want nil", err)
	}
}

func TestCheckCAAIssuanceRejectsUnauthorizedIssuer(t *testing.T) {
	err := CheckCAAIssuance(context.Background(), "www.example.com", CAAPolicy{
		Enabled:        true,
		AllowedIssuers: []string{DefaultCAAAllowedIssuer},
		Resolver: fakeCAAResolver{
			"example.com": {records: []CAARecord{{Tag: "issue", Value: "ca.example.test"}}},
		},
	})
	if err == nil {
		t.Fatal("CheckCAAIssuance() error = nil, want reject")
	}
	if !strings.Contains(err.Error(), "does not authorize") {
		t.Fatalf("CheckCAAIssuance() error = %v, want authorization failure", err)
	}
}

func TestCheckCAAIssuanceUsesIssuewildForWildcardDomain(t *testing.T) {
	err := CheckCAAIssuance(context.Background(), "*.example.com", CAAPolicy{
		Enabled:        true,
		AllowedIssuers: []string{DefaultCAAAllowedIssuer},
		Resolver: fakeCAAResolver{
			"example.com": {records: []CAARecord{
				{Tag: "issue", Value: "letsencrypt.org"},
				{Tag: "issuewild", Value: "ca.example.test"},
			}},
		},
	})
	if err == nil {
		t.Fatal("CheckCAAIssuance() error = nil, want issuewild rejection")
	}
	if !strings.Contains(err.Error(), "does not authorize") {
		t.Fatalf("CheckCAAIssuance() error = %v, want authorization failure", err)
	}
}

func TestCheckCAAIssuanceRejectsCriticalUnknownTag(t *testing.T) {
	err := CheckCAAIssuance(context.Background(), "example.com", CAAPolicy{
		Enabled:        true,
		AllowedIssuers: []string{DefaultCAAAllowedIssuer},
		Resolver: fakeCAAResolver{
			"example.com": {records: []CAARecord{{Flags: 0x80, Tag: "future", Value: "required"}}},
		},
	})
	if err == nil {
		t.Fatal("CheckCAAIssuance() error = nil, want critical unknown tag reject")
	}
	if !strings.Contains(err.Error(), "critical unknown tag") {
		t.Fatalf("CheckCAAIssuance() error = %v, want critical unknown tag failure", err)
	}
}

func TestCheckCAAIssuanceRequiresDNSServerWhenNoResolverInjected(t *testing.T) {
	err := CheckCAAIssuance(context.Background(), "example.com", CAAPolicy{
		Enabled:        true,
		AllowedIssuers: []string{DefaultCAAAllowedIssuer},
	})
	if err == nil {
		t.Fatal("CheckCAAIssuance() error = nil, want DNS server requirement")
	}
	if !strings.Contains(err.Error(), "caa_dns_server") {
		t.Fatalf("CheckCAAIssuance() error = %v, want caa_dns_server requirement", err)
	}
}

func TestParseCAARecordData(t *testing.T) {
	rec, err := parseCAARecordData([]byte{0, 5, 'i', 's', 's', 'u', 'e', 'l', 'e', 't', 's', 'e', 'n', 'c', 'r', 'y', 'p', 't', '.', 'o', 'r', 'g'})
	if err != nil {
		t.Fatalf("parseCAARecordData() error = %v", err)
	}
	if rec.Flags != 0 || rec.Tag != "issue" || rec.Value != "letsencrypt.org" {
		t.Fatalf("parseCAARecordData() = %#v, want issue letsencrypt.org", rec)
	}
}

func TestLookupCAARecordSetPropagatesResolverErrors(t *testing.T) {
	wantErr := errors.New("resolver failed")
	_, _, err := lookupCAARecordSet(context.Background(), fakeCAAResolver{
		"example.com": {err: wantErr},
	}, "example.com")
	if !errors.Is(err, wantErr) {
		t.Fatalf("lookupCAARecordSet() error = %v, want %v", err, wantErr)
	}
}
