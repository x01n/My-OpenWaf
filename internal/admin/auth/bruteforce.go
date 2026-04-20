package auth

import (
	"fmt"
	"sync"
	"time"
)

// BruteForceDetector tracks login failures by IP and username to prevent brute force attacks.
type BruteForceDetector struct {
	mu          sync.RWMutex
	attempts    map[string]*attemptRecord
	maxFailures int
	lockoutDur  time.Duration
}

type attemptRecord struct {
	failures  int
	lockedAt  time.Time
	lastFail  time.Time
}

// NewBruteForceDetector creates a detector with configurable limits.
// Default: 5 failures, 15 minute lockout.
func NewBruteForceDetector(maxFailures int, lockoutDuration time.Duration) *BruteForceDetector {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if lockoutDuration <= 0 {
		lockoutDuration = 15 * time.Minute
	}
	bf := &BruteForceDetector{
		attempts:    make(map[string]*attemptRecord),
		maxFailures: maxFailures,
		lockoutDur:  lockoutDuration,
	}
	go bf.cleanupLoop()
	return bf
}

func bruteforceKey(ip, username string) string {
	return fmt.Sprintf("%s|%s", ip, username)
}

// IsLocked returns true if the given IP+username combination is locked out.
func (bf *BruteForceDetector) IsLocked(ip, username string) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	// Check IP-level lock.
	if bf.isLockedKey(ip) {
		return true
	}
	// Check IP+username lock.
	return bf.isLockedKey(bruteforceKey(ip, username))
}

func (bf *BruteForceDetector) isLockedKey(key string) bool {
	rec, ok := bf.attempts[key]
	if !ok {
		return false
	}
	if rec.failures >= bf.maxFailures {
		if time.Since(rec.lockedAt) < bf.lockoutDur {
			return true
		}
		// Lockout expired, reset.
		delete(bf.attempts, key)
		return false
	}
	return false
}

// RecordFailure increments the failure counter for both IP and IP+username.
func (bf *BruteForceDetector) RecordFailure(ip, username string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	now := time.Now()
	// Record for IP+username.
	bf.recordForKey(bruteforceKey(ip, username), now)
	// Record for IP alone (global IP rate).
	bf.recordForKey(ip, now)
}

func (bf *BruteForceDetector) recordForKey(key string, now time.Time) {
	rec, ok := bf.attempts[key]
	if !ok {
		rec = &attemptRecord{}
		bf.attempts[key] = rec
	}
	rec.failures++
	rec.lastFail = now
	if rec.failures >= bf.maxFailures {
		rec.lockedAt = now
	}
}

// RecordSuccess clears the failure counter for the given IP+username.
func (bf *BruteForceDetector) RecordSuccess(ip, username string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	delete(bf.attempts, bruteforceKey(ip, username))
}

// RemainingAttempts returns how many attempts remain before lockout.
func (bf *BruteForceDetector) RemainingAttempts(ip, username string) int {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	key := bruteforceKey(ip, username)
	rec, ok := bf.attempts[key]
	if !ok {
		return bf.maxFailures
	}
	remaining := bf.maxFailures - rec.failures
	if remaining < 0 {
		remaining = 0
	}
	return remaining
}

// LockoutRemaining returns time remaining on lockout, or 0 if not locked.
func (bf *BruteForceDetector) LockoutRemaining(ip, username string) time.Duration {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	key := bruteforceKey(ip, username)
	rec, ok := bf.attempts[key]
	if !ok || rec.failures < bf.maxFailures {
		return 0
	}
	remaining := bf.lockoutDur - time.Since(rec.lockedAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (bf *BruteForceDetector) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		bf.mu.Lock()
		now := time.Now()
		for key, rec := range bf.attempts {
			// Remove entries that have been idle for longer than lockout duration.
			if now.Sub(rec.lastFail) > bf.lockoutDur*2 {
				delete(bf.attempts, key)
			}
		}
		bf.mu.Unlock()
	}
}
