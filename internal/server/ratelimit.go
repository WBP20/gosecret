package server

import (
	"net"
	"sync"
	"time"
)

type ipLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	maxKeys int
	window  map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newIPLimiter(rate, burst float64) *ipLimiter {
	return &ipLimiter{rate: rate, burst: burst, maxKeys: 50000, window: make(map[string]*bucket)}
}

func (l *ipLimiter) Allow(key string) bool {
	key = normalizeIP(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.window[key]
	if !ok {
		if len(l.window) >= l.maxKeys {
			l.evictOldest()
		}
		l.window[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens = min(l.burst, b.tokens+elapsed*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// normalizeIP truncates IPv6 addresses to /64 so that clients rotating within
// a /64 prefix share a single rate-limit bucket.
func normalizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if p4 := parsed.To4(); p4 != nil {
		return p4.String()
	}
	mask := net.CIDRMask(64, 128)
	return parsed.Mask(mask).String()
}

func (l *ipLimiter) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, b := range l.window {
		if first || b.last.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.last
			first = false
		}
	}
	if !first {
		delete(l.window, oldestKey)
	}
}

func (l *ipLimiter) sweep(maxAge time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for k, b := range l.window {
		if b.last.Before(cutoff) {
			delete(l.window, k)
		}
	}
}
