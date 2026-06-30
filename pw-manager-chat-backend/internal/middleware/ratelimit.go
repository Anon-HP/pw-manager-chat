package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var (
	limiters   = make(map[string]*ipLimiter)
	limitersMu sync.Mutex
)

func getLimiter(ip string) *rate.Limiter {
	limitersMu.Lock()
	defer limitersMu.Unlock()

	entry, exists := limiters[ip]

	if !exists {
		entry = &ipLimiter{limiter: rate.NewLimiter(rate.Every(time.Minute/5), 5)}
		limiters[ip] = entry
	}

	entry.lastSeen = time.Now()
	return entry.limiter
}

func CleanupLimiters() {
	for {
		time.Sleep(5 * time.Minute)
		limitersMu.Lock()

		for ip, entry := range limiters {
			if time.Since(entry.lastSeen) > 10*time.Minute {
				delete(limiters, ip)
			}
		}

		limitersMu.Unlock()
	}
}

func RateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr // fallback
		}
		if !getLimiter(ip).Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"Too many requests. Please slow down."}`))
			return
		}
		next(w, r)
	}
}
