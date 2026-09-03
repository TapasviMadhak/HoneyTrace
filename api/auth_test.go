package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuth_ExtractAPIKey(t *testing.T) {
	// Test X-API-Key header
	req1 := httptest.NewRequest("GET", "/api/v1/test", nil)
	req1.Header.Set("X-API-Key", "secret-key-123")
	if key := ExtractAPIKey(req1); key != "secret-key-123" {
		t.Errorf("Expected secret-key-123, got %q", key)
	}

	// Test Authorization Bearer
	req2 := httptest.NewRequest("GET", "/api/v1/test", nil)
	req2.Header.Set("Authorization", "Bearer bearer-key-456")
	if key := ExtractAPIKey(req2); key != "bearer-key-456" {
		t.Errorf("Expected bearer-key-456, got %q", key)
	}

	// Test Query Param
	req3 := httptest.NewRequest("GET", "/api/v1/test?api_key=query-key-789", nil)
	if key := ExtractAPIKey(req3); key != "query-key-789" {
		t.Errorf("Expected query-key-789, got %q", key)
	}

	// Test Empty
	req4 := httptest.NewRequest("GET", "/api/v1/test", nil)
	if key := ExtractAPIKey(req4); key != "" {
		t.Errorf("Expected empty string, got %q", key)
	}
}

func TestAuth_RequireMasterAuthMiddleware(t *testing.T) {
	// Configure test auth
	GlobalAuth.MasterAPIKey = "test-master-token-abc"
	GlobalAuth.DashboardKey = "test-dashboard-token-xyz"
	defer func() {
		GlobalAuth.MasterAPIKey = ""
		GlobalAuth.DashboardKey = ""
	}()

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	protectedHandler := RequireMasterAuth(dummyHandler)

	// 1. Unauthenticated Request -> 401
	reqUnauth := httptest.NewRequest("POST", "/api/v1/ai/summary", nil)
	recUnauth := httptest.NewRecorder()
	protectedHandler.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Errorf("Expected HTTP 401 for unauthenticated request, got %d", recUnauth.Code)
	}

	// 2. Request with Wrong Key -> 401
	reqWrong := httptest.NewRequest("POST", "/api/v1/ai/summary", nil)
	reqWrong.Header.Set("X-API-Key", "wrong-key")
	recWrong := httptest.NewRecorder()
	protectedHandler.ServeHTTP(recWrong, reqWrong)
	if recWrong.Code != http.StatusUnauthorized {
		t.Errorf("Expected HTTP 401 for wrong key, got %d", recWrong.Code)
	}

	// 3. Request with Dashboard Key (not master) -> 401
	reqDash := httptest.NewRequest("POST", "/api/v1/ai/summary", nil)
	reqDash.Header.Set("X-API-Key", "test-dashboard-token-xyz")
	recDash := httptest.NewRecorder()
	protectedHandler.ServeHTTP(recDash, reqDash)
	if recDash.Code != http.StatusUnauthorized {
		t.Errorf("Expected HTTP 401 for dashboard key on master route, got %d", recDash.Code)
	}

	// 4. Request with Valid Master Key -> 200 OK
	reqValid := httptest.NewRequest("POST", "/api/v1/ai/summary", nil)
	reqValid.Header.Set("X-API-Key", "test-master-token-abc")
	recValid := httptest.NewRecorder()
	protectedHandler.ServeHTTP(recValid, reqValid)
	if recValid.Code != http.StatusOK {
		t.Errorf("Expected HTTP 200 for valid master key, got %d", recValid.Code)
	}
}

func TestRateLimit_TokenBucket(t *testing.T) {
	limiter := NewIPRateLimiter(60, 3) // Capacity 3, refill 1 token/sec

	ip := "203.0.113.195"

	// First 3 requests must pass (consuming burst capacity)
	for i := 1; i <= 3; i++ {
		if !limiter.Allow(ip) {
			t.Errorf("Request %d should have been allowed under burst capacity", i)
		}
	}

	// 4th request must be rejected immediately (bucket empty)
	if limiter.Allow(ip) {
		t.Errorf("Request 4 should have been blocked by rate limiter")
	}

	// Different IP should still be allowed
	differentIP := "198.51.100.42"
	if !limiter.Allow(differentIP) {
		t.Errorf("Request from different IP should have been allowed")
	}
}
