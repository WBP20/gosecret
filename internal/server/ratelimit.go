package server

import (
	"container/list"
	"net"
	"sync"
	"time"
)

type ipLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	maxKeys int
	window  map[string]*list.Element // value: *bucket (Element.Value)
	lru     *list.List               // front = most recent, back = oldest
}

type bucket struct {
	key    string
	tokens float64
	last   time.Time
}

func newIPLimiter(rate, burst float64) *ipLimiter {
	return &ipLimiter{
		rate:    rate,
		burst:   burst,
		maxKeys: 50000,
		window:  make(map[string]*list.Element),
		lru:     list.New(),
	}
}

func (l *ipLimiter) Allow(key string) bool {
	key = normalizeIP(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if el, ok := l.window[key]; ok {
		b := el.Value.(*bucket)
		elapsed := now.Sub(b.last).Seconds()
		if elapsed < 0 {
			elapsed = 0 // clock skew (e.g. NTP correction)
		}
		b.tokens = min(l.burst, b.tokens+elapsed*l.rate)
		b.last = now
		l.lru.MoveToFront(el)
		if b.tokens < 1 {
			return false
		}
		b.tokens--
		return true
	}
	if len(l.window) >= l.maxKeys {
		if back := l.lru.Back(); back != nil {
			delete(l.window, back.Value.(*bucket).key)
			l.lru.Remove(back)
		}
	}
	b := &bucket{key: key, tokens: l.burst - 1, last: now}
	l.window[key] = l.lru.PushFront(b)
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

func (l *ipLimiter) sweep(maxAge time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	// LRU back-to-front: as soon as we see a fresh bucket, the rest is fresher.
	for {
		back := l.lru.Back()
		if back == nil {
			return
		}
		b := back.Value.(*bucket)
		if !b.last.Before(cutoff) {
			return
		}
		delete(l.window, b.key)
		l.lru.Remove(back)
	}
}
