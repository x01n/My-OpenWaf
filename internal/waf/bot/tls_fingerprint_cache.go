package bot

import (
	"bytes"
	"hash/maphash"
	"sync"
)

const tlsFingerprintCacheSize = 256

type tlsFingerprintCacheEntry struct {
	mu     sync.RWMutex
	hash   uint64
	record []byte
	fp     TLSClientFingerprint
}

var tlsFingerprintCache [tlsFingerprintCacheSize]tlsFingerprintCacheEntry
var tlsFingerprintCacheSeed = maphash.MakeSeed()

func lookupTLSFingerprintCacheWithHash(record []byte, hash uint64) (TLSClientFingerprint, bool) {
	if len(record) == 0 {
		return TLSClientFingerprint{}, false
	}
	entry := &tlsFingerprintCache[hash&(tlsFingerprintCacheSize-1)]

	entry.mu.RLock()
	if entry.hash != hash || len(entry.record) != len(record) || !bytes.Equal(entry.record, record) {
		entry.mu.RUnlock()
		return TLSClientFingerprint{}, false
	}
	fp := entry.fp
	entry.mu.RUnlock()
	return fp, true
}

func storeTLSFingerprintCacheWithHash(record []byte, hash uint64, fp TLSClientFingerprint) {
	if len(record) == 0 || !fp.HasValue() {
		return
	}
	entry := &tlsFingerprintCache[hash&(tlsFingerprintCacheSize-1)]

	entry.mu.Lock()
	if cap(entry.record) < len(record) {
		entry.record = make([]byte, len(record))
	} else {
		entry.record = entry.record[:len(record)]
	}
	copy(entry.record, record)
	entry.hash = hash
	entry.fp = cloneTLSFingerprintForCache(fp)
	entry.mu.Unlock()
}

func tlsFingerprintCacheHash(record []byte) uint64 {
	return maphash.Bytes(tlsFingerprintCacheSeed, record)
}

func cloneTLSFingerprintForCache(fp TLSClientFingerprint) TLSClientFingerprint {
	fp.ALPN = append([]string(nil), fp.ALPN...)
	fp.CipherSuites = append([]uint16(nil), fp.CipherSuites...)
	fp.Extensions = append([]uint16(nil), fp.Extensions...)
	fp.Curves = append([]uint16(nil), fp.Curves...)
	fp.PointFormats = append([]uint8(nil), fp.PointFormats...)
	return fp
}
