package main

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// AuthConfig holds API security keys and authorization rules
type AuthConfig struct {
	MasterAPIKey    string
	DashboardKey    string
	RequireAuthAll  bool
}

// GlobalAuth holds the active authentication configuration
var GlobalAuth = NewAuthConfig()

// NewAuthConfig initializes authentication rules from environment
func NewAuthConfig() *AuthConfig {
	return &AuthConfig{
		MasterAPIKey:   strings.TrimSpace(os.Getenv("HONEYTRACE_API_KEY")),
		DashboardKey:   strings.TrimSpace(os.Getenv("HONEYTRACE_DASHBOARD_KEY")),
		RequireAuthAll: strings.ToLower(strings.TrimSpace(os.Getenv("HONEYTRACE_REQUIRE_AUTH_ALL"))) == "true",
	}
}

// Reload re-reads environment variables
func (a *AuthConfig) Reload() {
	a.MasterAPIKey = strings.TrimSpace(os.Getenv("HONEYTRACE_API_KEY"))
	a.DashboardKey = strings.TrimSpace(os.Getenv("HONEYTRACE_DASHBOARD_KEY"))
	a.RequireAuthAll = strings.ToLower(strings.TrimSpace(os.Getenv("HONEYTRACE_REQUIRE_AUTH_ALL"))) == "true"
}

// ExtractAPIKey extracts the authentication key from Headers or Query Parameters
func ExtractAPIKey(r *http.Request) string {
	// 1. Check X-API-Key header
	if key := strings.TrimSpace(r.Header.Get("X-API-Key")); key != "" {
		return key
	}

	// 2. Check Authorization: Bearer <key>
	if authHeader := strings.TrimSpace(r.Header.Get("Authorization")); authHeader != "" {
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			return strings.TrimSpace(authHeader[7:])
		}
		return authHeader
	}

	// 3. Check query param ?api_key=... (primarily for SSE / EventSource connections)
	if qKey := strings.TrimSpace(r.URL.Query().Get("api_key")); qKey != "" {
		return qKey
	}

	return ""
}

// IsAuthorized checks if the given request provides a valid master or dashboard key
func (a *AuthConfig) IsAuthorized(r *http.Request, requireMaster bool) bool {
	// If no master key is configured on the server, allow in dev mode
	if a.MasterAPIKey == "" {
		return true
	}

	providedKey := ExtractAPIKey(r)
	if providedKey == "" {
		return false
	}

	// Master key always grants full access
	if providedKey == a.MasterAPIKey {
		return true
	}

	// Dashboard key grants access if master is not strictly required
	if !requireMaster && a.DashboardKey != "" && providedKey == a.DashboardKey {
		return true
	}

	return false
}

// RequireMasterAuth enforces authentication for high-privilege routes (AI, payload downloads, session forensics)
func RequireMasterAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if !GlobalAuth.IsAuthorized(r, true) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "Unauthorized",
				"message": "Valid HoneyTrace API key required for this endpoint. Provide X-API-Key or Authorization header.",
			})
			return
		}

		next(w, r)
	}
}

// RequireGeneralAuth enforces authentication if HONEYTRACE_REQUIRE_AUTH_ALL is true
func RequireGeneralAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if GlobalAuth.RequireAuthAll && !GlobalAuth.IsAuthorized(r, false) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "Unauthorized",
				"message": "Valid HoneyTrace API key or Dashboard key required. Provide X-API-Key or Authorization header.",
			})
			return
		}

		next(w, r)
	}
}

// --- Per-IP Rate Limiting (Token Bucket / Sliding Window) ---

type rateLimitEntry struct {
	tokens     float64
	lastRefill time.Time
}

// IPRateLimiter provides memory-safe sliding window rate limiting
type IPRateLimiter struct {
	mu       sync.Mutex
	limits   map[string]*rateLimitEntry
	rate     float64 // tokens added per second
	capacity float64 // burst capacity
}

// NewIPRateLimiter creates a rate limiter with specified requests-per-minute and burst capacity
func NewIPRateLimiter(requestsPerMinute int, burstCapacity int) *IPRateLimiter {
	limiter := &IPRateLimiter{
		limits:   make(map[string]*rateLimitEntry),
		rate:     float64(requestsPerMinute) / 60.0,
		capacity: float64(burstCapacity),
	}

	// Periodic cleanup of stale IPs every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			limiter.mu.Lock()
			now := time.Now()
			for ip, entry := range limiter.limits {
				if now.Sub(entry.lastRefill) > 10*time.Minute {
					delete(limiter.limits, ip)
				}
			}
			limiter.mu.Unlock()
		}
	}()

	return limiter
}

// Global rate limiters
var (
	GeneralRateLimiter = NewIPRateLimiter(120, 30) // 120 req/min for general telemetry
	AIRateLimiter      = NewIPRateLimiter(15, 5)   // 15 req/min for expensive AI queries
)

// getClientIP extracts real client IP
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			clean := strings.TrimSpace(parts[0])
			if clean != "" {
				return clean
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// Allow checks if the client IP is within rate limits
func (l *IPRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	entry, exists := l.limits[ip]
	if !exists {
		l.limits[ip] = &rateLimitEntry{
			tokens:     l.capacity - 1,
			lastRefill: now,
		}
		return true
	}

	elapsed := now.Sub(entry.lastRefill).Seconds()
	entry.lastRefill = now
	entry.tokens = entry.tokens + (elapsed * l.rate)
	if entry.tokens > l.capacity {
		entry.tokens = l.capacity
	}

	if entry.tokens >= 1.0 {
		entry.tokens -= 1.0
		return true
	}

	return false
}

// RateLimit enforces rate limiting on a handler
func RateLimit(limiter *IPRateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		if !limiter.Allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "Too Many Requests",
				"message": "Rate limit exceeded. Please slow down your requests.",
			})
			return
		}
		next(w, r)
	}
}
