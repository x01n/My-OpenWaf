package dataplane

import (
	"strings"
	"sync"
)

// HostTrieNode represents a single node in the domain trie.
type HostTrieNode struct {
	children map[string]*HostTrieNode
	siteID   uint // exact match site ID (0 = no match)
	wildcard uint // wildcard match site ID (*.example.com → 0 = no match)
}

// HostTrie is a thread-safe trie for efficient domain-to-site matching.
// Domains are stored in reverse-label order (e.g. "www.example.com" → ["com","example","www"]).
type HostTrie struct {
	mu   sync.RWMutex
	root *HostTrieNode
}

// NewHostTrie creates an empty HostTrie.
func NewHostTrie() *HostTrie {
	return &HostTrie{
		root: &HostTrieNode{children: make(map[string]*HostTrieNode)},
	}
}

// Insert adds a domain → siteID mapping. Supports wildcard domains like "*.example.com".
func (t *HostTrie) Insert(host string, siteID uint) {
	host = normalizeHost(host)
	if host == "" {
		return
	}

	isWildcard := false
	if strings.HasPrefix(host, "*.") {
		isWildcard = true
		host = host[2:] // remove "*."
	}

	labels := reverseLabels(host)

	t.mu.Lock()
	defer t.mu.Unlock()

	node := t.root
	for _, label := range labels {
		if node.children == nil {
			node.children = make(map[string]*HostTrieNode)
		}
		child, ok := node.children[label]
		if !ok {
			child = &HostTrieNode{children: make(map[string]*HostTrieNode)}
			node.children[label] = child
		}
		node = child
	}

	if isWildcard {
		node.wildcard = siteID
	} else {
		node.siteID = siteID
	}
}

// Match finds the best matching site ID for a given host.
// Priority: exact match > wildcard match.
// Returns (siteID, true) on match, (0, false) otherwise.
func (t *HostTrie) Match(host string) (uint, bool) {
	host = normalizeHost(host)
	if host == "" {
		return 0, false
	}

	labels := reverseLabels(host)

	t.mu.RLock()
	defer t.mu.RUnlock()

	node := t.root
	var lastWildcard uint

	for _, label := range labels {
		if node.wildcard != 0 {
			lastWildcard = node.wildcard
		}
		if node.children == nil {
			break
		}
		child, ok := node.children[label]
		if !ok {
			// No exact child — check wildcard child "*"
			if wc, wcOK := node.children["*"]; wcOK {
				if wc.siteID != 0 {
					lastWildcard = wc.siteID
				}
			}
			// Return best wildcard found so far
			if lastWildcard != 0 {
				return lastWildcard, true
			}
			return 0, false
		}
		node = child
	}

	// Exact match at terminal node
	if node.siteID != 0 {
		return node.siteID, true
	}
	// Wildcard at this depth (e.g. *.example.com matches sub.example.com)
	if node.wildcard != 0 {
		return node.wildcard, true
	}
	if lastWildcard != 0 {
		return lastWildcard, true
	}
	return 0, false
}

// Remove removes a domain from the trie.
func (t *HostTrie) Remove(host string) {
	host = normalizeHost(host)
	if host == "" {
		return
	}

	isWildcard := false
	if strings.HasPrefix(host, "*.") {
		isWildcard = true
		host = host[2:]
	}

	labels := reverseLabels(host)

	t.mu.Lock()
	defer t.mu.Unlock()

	node := t.root
	for _, label := range labels {
		if node.children == nil {
			return
		}
		child, ok := node.children[label]
		if !ok {
			return
		}
		node = child
	}

	if isWildcard {
		node.wildcard = 0
	} else {
		node.siteID = 0
	}
}

// Clear removes all entries from the trie.
func (t *HostTrie) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.root = &HostTrieNode{children: make(map[string]*HostTrieNode)}
}

// normalizeHost strips port and lowercases the host.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(host, ":"); i >= 0 {
		// Only strip if what follows looks like a port (all digits)
		port := host[i+1:]
		allDigits := true
		for _, ch := range port {
			if ch < '0' || ch > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && len(port) > 0 {
			host = host[:i]
		}
	}
	return host
}

// reverseLabels splits a domain by "." and reverses the order.
// "www.example.com" → ["com", "example", "www"]
func reverseLabels(host string) []string {
	parts := strings.Split(host, ".")
	n := len(parts)
	reversed := make([]string, n)
	for i, p := range parts {
		reversed[n-1-i] = p
	}
	return reversed
}
