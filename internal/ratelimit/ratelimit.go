// Package ratelimit provides a simple fixed-window, in-memory rate limiter
// with no external dependencies.
package ratelimit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type window struct {
	count int
	reset time.Time
}

// Limiter enforces a maximum number of requests per key within a sliding
// fixed-window duration.
type Limiter struct {
	mu      sync.Mutex
	windows map[string]*window
	limit   int
	dur     time.Duration
}

// New creates a Limiter that allows at most limit requests per dur per key.
func New(limit int, dur time.Duration) *Limiter {
	l := &Limiter{windows: make(map[string]*window), limit: limit, dur: dur}
	go l.cleanup()
	return l
}

// Allow returns true if the key is within its rate budget.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w, ok := l.windows[key]
	if !ok || now.After(w.reset) {
		l.windows[key] = &window{count: 1, reset: now.Add(l.dur)}
		return true
	}
	if w.count >= l.limit {
		return false
	}
	w.count++
	return true
}

// cleanup removes expired windows to prevent unbounded memory growth.
func (l *Limiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		for k, w := range l.windows {
			if now.After(w.reset) {
				delete(l.windows, k)
			}
		}
		l.mu.Unlock()
	}
}

// ClientIP extracts the real client IP from a request, honouring
// X-Forwarded-For when set (e.g. behind a reverse proxy).
func ClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
