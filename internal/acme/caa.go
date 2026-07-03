package acme

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	typeCAA                 dnsmessage.Type = 257
	defaultCAAQueryTimeout                  = 3 * time.Second
	DefaultCAAAllowedIssuer                 = "letsencrypt.org"
)

var errCAANotFound = errors.New("caa records not found")

// CAARecord is one DNS Certification Authority Authorization record.
type CAARecord struct {
	Flags uint8
	Tag   string
	Value string
}

// CAAResolver resolves CAA records for one DNS name.
type CAAResolver interface {
	LookupCAA(ctx context.Context, domain string) ([]CAARecord, error)
}

// CAAPolicy controls ACME CAA preflight checks.
type CAAPolicy struct {
	Enabled        bool
	AllowedIssuers []string
	DNSServer      string
	Timeout        time.Duration
	Resolver       CAAResolver
}

// DNSCAAResolver queries a recursive DNS server for CAA records.
type DNSCAAResolver struct {
	Server  string
	Timeout time.Duration
}

// CheckCAAIssuance verifies that the discovered CAA RRSet authorizes the
// configured issuer set for the requested domain.
func CheckCAAIssuance(ctx context.Context, domain string, policy CAAPolicy) error {
	if !policy.Enabled {
		return nil
	}
	domain, wildcard := normalizeCAADomain(domain)
	if domain == "" {
		return errors.New("caa domain is required")
	}
	issuers := normalizeCAAAllowedIssuers(policy.AllowedIssuers)
	if len(issuers) == 0 {
		return errors.New("caa allowed issuers are required")
	}
	resolver := policy.Resolver
	if resolver == nil {
		if strings.TrimSpace(policy.DNSServer) == "" {
			return errors.New("caa_dns_server is required when caa_check_enabled is true")
		}
		resolver = DNSCAAResolver{Server: policy.DNSServer, Timeout: policy.Timeout}
	}
	records, lookupName, err := lookupCAARecordSet(ctx, resolver, domain)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}
	if err := rejectCriticalUnknownCAARecords(records); err != nil {
		return fmt.Errorf("caa record set at %s rejects issuance: %w", lookupName, err)
	}
	if caaRecordsAuthorizeIssuers(records, issuers, wildcard) {
		return nil
	}
	return fmt.Errorf("caa record set at %s does not authorize issuers %s", lookupName, strings.Join(issuers, ","))
}

func lookupCAARecordSet(ctx context.Context, resolver CAAResolver, domain string) ([]CAARecord, string, error) {
	for _, name := range caaLookupNames(domain) {
		records, err := resolver.LookupCAA(ctx, name)
		if err == nil {
			if len(records) > 0 {
				return records, name, nil
			}
			continue
		}
		if errors.Is(err, errCAANotFound) {
			continue
		}
		return nil, name, fmt.Errorf("lookup caa %s: %w", name, err)
	}
	return nil, "", nil
}

func normalizeCAADomain(domain string) (string, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	wildcard := strings.HasPrefix(domain, "*.")
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, ".")
	return domain, wildcard
}

func caaLookupNames(domain string) []string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return nil
	}
	labels := strings.Split(domain, ".")
	out := make([]string, 0, len(labels))
	for i := 0; i < len(labels); i++ {
		name := strings.Join(labels[i:], ".")
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func normalizeCAAAllowedIssuers(issuers []string) []string {
	seen := make(map[string]struct{}, len(issuers))
	out := make([]string, 0, len(issuers))
	for _, raw := range issuers {
		for _, part := range strings.Split(raw, ",") {
			issuer := normalizeCAAIssuer(part)
			if issuer == "" {
				continue
			}
			if _, ok := seen[issuer]; ok {
				continue
			}
			seen[issuer] = struct{}{}
			out = append(out, issuer)
		}
	}
	return out
}

func normalizeCAAIssuer(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.IndexByte(value, ';'); i >= 0 {
		value = strings.TrimSpace(value[:i])
	}
	value = strings.Trim(value, `"`)
	value = strings.TrimSuffix(value, ".")
	return strings.TrimSpace(value)
}

func rejectCriticalUnknownCAARecords(records []CAARecord) error {
	for _, rec := range records {
		tag := strings.ToLower(strings.TrimSpace(rec.Tag))
		if rec.Flags&0x80 == 0 {
			continue
		}
		switch tag {
		case "issue", "issuewild", "iodef", "accounturi", "validationmethods":
		default:
			return fmt.Errorf("critical unknown tag %q", rec.Tag)
		}
	}
	return nil
}

func caaRecordsAuthorizeIssuers(records []CAARecord, issuers []string, wildcard bool) bool {
	applicable := caaIssueRecords(records, wildcard)
	if len(applicable) == 0 {
		return true
	}
	for _, rec := range applicable {
		recordIssuer := normalizeCAAIssuer(rec.Value)
		for _, allowed := range issuers {
			if recordIssuer == allowed {
				return true
			}
		}
	}
	return false
}

func caaIssueRecords(records []CAARecord, wildcard bool) []CAARecord {
	out := make([]CAARecord, 0, len(records))
	if wildcard {
		for _, rec := range records {
			if strings.EqualFold(strings.TrimSpace(rec.Tag), "issuewild") {
				out = append(out, rec)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	for _, rec := range records {
		if strings.EqualFold(strings.TrimSpace(rec.Tag), "issue") {
			out = append(out, rec)
		}
	}
	return out
}

func (r DNSCAAResolver) LookupCAA(ctx context.Context, domain string) ([]CAARecord, error) {
	server := normalizeCAADNSServer(r.Server)
	if server == "" {
		return nil, errors.New("dns server is required")
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = defaultCAAQueryTimeout
	}
	query, err := buildCAAQuery(domain)
	if err != nil {
		return nil, err
	}
	resp, err := exchangeCAAUDP(ctx, server, query, timeout)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		resp, err = exchangeCAATCP(ctx, server, query, timeout)
		if err != nil {
			return nil, err
		}
	}
	return caaRecordsFromDNSMessage(resp)
}

func normalizeCAADNSServer(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw
	}
	return net.JoinHostPort(raw, "53")
}

func buildCAAQuery(domain string) ([]byte, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".") + "."
	name, err := dnsmessage.NewName(domain)
	if err != nil {
		return nil, err
	}
	return (&dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               randomDNSID(),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  typeCAA,
			Class: dnsmessage.ClassINET,
		}},
	}).Pack()
}

func randomDNSID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}

func exchangeCAAUDP(ctx context.Context, server string, query []byte, timeout time.Duration) (*dnsmessage.Message, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(buf[:n]); err != nil {
		return nil, err
	}
	return &msg, nil
}

func exchangeCAATCP(ctx context.Context, server string, query []byte, timeout time.Duration) (*dnsmessage.Message, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(query)))
	if _, err := conn.Write(header[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(header[:])
	if size == 0 {
		return nil, errors.New("empty dns tcp response")
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(buf); err != nil {
		return nil, err
	}
	return &msg, nil
}

func caaRecordsFromDNSMessage(msg *dnsmessage.Message) ([]CAARecord, error) {
	if msg == nil {
		return nil, errCAANotFound
	}
	switch msg.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, errCAANotFound
	default:
		return nil, fmt.Errorf("dns rcode %s", msg.RCode.String())
	}
	records := make([]CAARecord, 0, len(msg.Answers))
	for _, ans := range msg.Answers {
		if ans.Header.Type != typeCAA {
			continue
		}
		unknown, ok := ans.Body.(*dnsmessage.UnknownResource)
		if !ok {
			continue
		}
		rec, err := parseCAARecordData(unknown.Data)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	if len(records) == 0 {
		return nil, errCAANotFound
	}
	return records, nil
}

func parseCAARecordData(data []byte) (CAARecord, error) {
	if len(data) < 2 {
		return CAARecord{}, errors.New("invalid caa record length")
	}
	tagLen := int(data[1])
	if tagLen == 0 || 2+tagLen > len(data) {
		return CAARecord{}, errors.New("invalid caa tag length")
	}
	return CAARecord{
		Flags: data[0],
		Tag:   string(data[2 : 2+tagLen]),
		Value: string(data[2+tagLen:]),
	}, nil
}
