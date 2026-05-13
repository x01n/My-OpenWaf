package waf

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// IPListEntry is an IP or CIDR with metadata.
type IPListEntry struct {
	CIDR     *net.IPNet
	Single   net.IP
	Note     string
	ExpireAt int64  // unix seconds; 0 = permanent
	Action   string // "intercept" or "drop" ("block" accepted as legacy alias)
}

// IPReputation manages blacklist/whitelist + auto-ban.
type IPReputation struct {
	mu        sync.RWMutex
	blacklist []IPListEntry
	whitelist []IPListEntry

	// Violations: ip → count + first seen
	violations sync.Map // map[string]*violationCounter

	// Auto-ban settings
	autoBanEnabled   atomic.Bool
	autoBanThreshold atomic.Int64
	autoBanWindow    atomic.Int64 // seconds
	autoBanDuration  atomic.Int64 // seconds
	autoBanAction    atomic.Value // string: "intercept" or "drop"

	stopCh chan struct{}
	wg     sync.WaitGroup
}

type violationCounter struct {
	mu        sync.Mutex
	count     int64
	firstSeen int64
	bannedTil int64
}

func NewIPReputation() *IPReputation {
	r := &IPReputation{
		stopCh: make(chan struct{}),
	}
	r.autoBanThreshold.Store(10)
	r.autoBanWindow.Store(60)
	r.autoBanDuration.Store(3600)
	r.autoBanAction.Store("intercept")
	r.wg.Add(1)
	go r.cleaner()
	return r
}

func (r *IPReputation) Close() {
	close(r.stopCh)
	r.wg.Wait()
}

func (r *IPReputation) SetLists(black, white []IPListEntry) {
	r.mu.Lock()
	r.blacklist = black
	r.whitelist = white
	r.mu.Unlock()
}

func (r *IPReputation) ConfigureAutoBan(enabled bool, threshold, windowSec, durationSec int) {
	r.autoBanEnabled.Store(enabled)
	if threshold > 0 {
		r.autoBanThreshold.Store(int64(threshold))
	}
	if windowSec > 0 {
		r.autoBanWindow.Store(int64(windowSec))
	}
	if durationSec > 0 {
		r.autoBanDuration.Store(int64(durationSec))
	}
}

// ConfigureAutoBanAction sets the action taken when an IP is auto-banned.
func (r *IPReputation) ConfigureAutoBanAction(action string) {
	switch action {
	case "drop", "block":
		r.autoBanAction.Store("drop")
	case "intercept", "":
		r.autoBanAction.Store("intercept")
	}
}

// Decision for an IP lookup.
type IPDecision struct {
	Allowed  bool
	Matched  bool
	Reason   string
	Category string
	Action   string // "drop" for TCP close, "intercept" for HTTP 403
}

// Check returns the reputation decision for the given IP.
func (r *IPReputation) Check(ip net.IP) IPDecision {
	if ip == nil {
		return IPDecision{Allowed: true}
	}

	r.mu.RLock()
	for _, e := range r.whitelist {
		if entryMatches(e, ip) {
			r.mu.RUnlock()
			return IPDecision{Allowed: true, Matched: true, Reason: e.Note, Category: "whitelist"}
		}
	}
	for _, e := range r.blacklist {
		if entryMatches(e, ip) {
			r.mu.RUnlock()
			return IPDecision{Allowed: false, Matched: true, Reason: e.Note, Category: "blacklist", Action: e.Action}
		}
	}
	r.mu.RUnlock()

	// Auto-ban lookup.
	if r.autoBanEnabled.Load() {
		if v, ok := r.violations.Load(ip.String()); ok {
			vc := v.(*violationCounter)
			vc.mu.Lock()
			bt := vc.bannedTil
			vc.mu.Unlock()
			if bt > time.Now().Unix() {
				act, _ := r.autoBanAction.Load().(string)
				return IPDecision{Allowed: false, Matched: true, Reason: "auto-banned", Category: "auto_ban", Action: act}
			}
		}
	}

	return IPDecision{Allowed: true}
}

func (r *IPReputation) RecordViolation(ip net.IP) bool {
	if ip == nil || !r.autoBanEnabled.Load() {
		return false
	}

	key := ip.String()
	now := time.Now().Unix()
	window := r.autoBanWindow.Load()
	threshold := r.autoBanThreshold.Load()
	duration := r.autoBanDuration.Load()

	v, _ := r.violations.LoadOrStore(key, &violationCounter{firstSeen: now})
	vc := v.(*violationCounter)

	vc.mu.Lock()
	defer vc.mu.Unlock()

	// Reset counter if outside window.
	if now-vc.firstSeen > window {
		vc.count = 0
		vc.firstSeen = now
	}
	vc.count++

	if vc.count >= threshold && vc.bannedTil < now {
		vc.bannedTil = now + duration
		return true
	}
	return false
}

type BanEntry struct {
	IP        string `json:"ip"`
	Count     int64  `json:"count"`
	BannedTil int64  `json:"banned_til"`
}

func (r *IPReputation) ActiveBans() []BanEntry {
	now := time.Now().Unix()
	var out []BanEntry
	r.violations.Range(func(k, v any) bool {
		vc := v.(*violationCounter)
		vc.mu.Lock()
		if vc.bannedTil > now {
			out = append(out, BanEntry{
				IP:        k.(string),
				Count:     vc.count,
				BannedTil: vc.bannedTil,
			})
		}
		vc.mu.Unlock()
		return true
	})
	return out
}

func entryMatches(e IPListEntry, ip net.IP) bool {
	if e.ExpireAt > 0 && time.Now().Unix() > e.ExpireAt {
		return false
	}
	if e.CIDR != nil && e.CIDR.Contains(ip) {
		return true
	}
	if e.Single != nil && e.Single.Equal(ip) {
		return true
	}
	return false
}

// ParseIPListEntry parses a CIDR or single IP string into an IPListEntry.
func ParseIPListEntry(s string, note string, action ...string) (IPListEntry, bool) {
	s = trimSpace(s)
	if s == "" {
		return IPListEntry{}, false
	}
	act := "intercept"
	if len(action) > 0 && action[0] != "" {
		switch action[0] {
		case "drop", "block":
			act = "drop"
		case "intercept":
			act = "intercept"
		}
	}
	if _, cidr, err := net.ParseCIDR(s); err == nil {
		return IPListEntry{CIDR: cidr, Note: note, Action: act}, true
	}
	if ip := net.ParseIP(s); ip != nil {
		return IPListEntry{Single: ip, Note: note, Action: act}, true
	}
	return IPListEntry{}, false
}

func (r *IPReputation) cleaner() {
	defer r.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			now := time.Now().Unix()
			r.violations.Range(func(k, v any) bool {
				vc := v.(*violationCounter)
				vc.mu.Lock()
				expired := vc.bannedTil < now && now-vc.firstSeen > 3600
				vc.mu.Unlock()
				if expired {
					r.violations.Delete(k)
				}
				return true
			})
		}
	}
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
