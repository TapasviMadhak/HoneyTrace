package main

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestThreatIntel_IgnoredIPPrivacy(t *testing.T) {
	// Set ignored IP and CIDR
	origEnv := os.Getenv("HONEYTRACE_IGNORE_IPS")
	defer os.Setenv("HONEYTRACE_IGNORE_IPS", origEnv)

	os.Setenv("HONEYTRACE_IGNORE_IPS", "49.36.78.52,49.36.0.0/14")

	abuse := NewAbuseClient()
	greynoise := NewGreyNoiseClient()

	// 1. Direct user IP
	userIP := "49.36.78.52"
	abuseRep, err := abuse.CheckIP(userIP)
	if err != nil {
		t.Fatalf("abuse.CheckIP returned unexpected error: %v", err)
	}
	if abuseRep.ISP != "Internal/Ignored Network" || abuseRep.Score != 0 {
		t.Errorf("Privacy leak: user IP was not intercepted by AbuseClient: %+v", abuseRep)
	}

	gnRep, err := greynoise.CheckIP(userIP)
	if err != nil {
		t.Fatalf("greynoise.CheckIP returned unexpected error: %v", err)
	}
	if gnRep.Name != "Internal/Ignored Network" || gnRep.Classification != "benign" {
		t.Errorf("Privacy leak: user IP was not intercepted by GreyNoiseClient: %+v", gnRep)
	}

	// 2. Subnet IP (49.37.10.20 falls within 49.36.0.0/14)
	subnetIP := "49.37.10.20"
	abuseSub, err := abuse.CheckIP(subnetIP)
	if err != nil || abuseSub.ISP != "Internal/Ignored Network" {
		t.Errorf("Privacy leak: user subnet IP was not intercepted by AbuseClient: %+v", abuseSub)
	}

	// 3. Tailscale IP (100.89.14.122)
	tailscaleIP := "100.89.14.122"
	abuseTS, err := abuse.CheckIP(tailscaleIP)
	if err != nil || abuseTS.ISP != "Internal/Ignored Network" {
		t.Errorf("Privacy leak: Tailscale IP was not intercepted: %+v", abuseTS)
	}
}

func TestRateLimit_XRealIPAndCapacityCap(t *testing.T) {
	// 1. Verify getClientIP prioritizes X-Real-IP set by Nginx
	req, _ := http.NewRequest("GET", "/api/v1/telemetry/stats", nil)
	req.Header.Set("X-Real-IP", "203.0.113.195")
	req.Header.Set("X-Forwarded-For", "198.51.100.44, 10.0.0.1")
	req.RemoteAddr = "127.0.0.1:54321"

	clientIP := getClientIP(req)
	if clientIP != "203.0.113.195" {
		t.Errorf("getClientIP did not prioritize X-Real-IP: got %s, want 203.0.113.195", clientIP)
	}

	// 2. Verify rate limiter capacity bounding
	limiter := NewIPRateLimiter(60, 10)
	// Fill limiter with entries
	for i := 0; i < 10050; i++ {
		fakeIP := "192.0.2.1"
		limiter.Allow(fakeIP)
	}
	limiter.mu.Lock()
	count := len(limiter.limits)
	limiter.mu.Unlock()

	if count > 10000 {
		t.Errorf("Rate limiter map exceeded capacity cap: got %d entries", count)
	}
}

func TestStore_ActorClusteringAndCaching(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "honeytrace-test-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	connStr := dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", connStr)
	if err != nil {
		t.Fatalf("failed opening test DB: %v", err)
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		t.Fatalf("initSchema failed: %v", err)
	}

	// Insert mock events with HASSH fingerprints
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)
	rawJSON1 := `{"hassh": "01ca35584ad5a1b66cf6a9846b5b2821"}`
	rawJSON2 := `{"hassh": "98ddc5604ef6a1006a2b49a58759fbe6"}`

	_, err = db.Exec(`
		INSERT INTO events (id, timestamp, source_ip, session_id, username, password, event_type, severity, summary, raw_json)
		VALUES 
			('ev1', ?, '198.51.100.1', 'sess-1', 'root', '123456', 'cowrie.login.failed', 'low', 'SSH attempt', ?),
			('ev2', ?, '198.51.100.1', 'sess-1', 'admin', 'admin', 'cowrie.login.success', 'critical', 'SSH breach', ?),
			('ev3', ?, '198.51.100.2', 'sess-2', 'root', 'toor', 'cowrie.login.failed', 'low', 'SSH attempt', ?);
	`, nowStr, rawJSON1, nowStr, rawJSON1, nowStr, rawJSON2)
	if err != nil {
		t.Fatalf("failed inserting test events: %v", err)
	}

	store := &Store{
		db:          db,
		dbPath:      dbPath,
		stopChan:    make(chan struct{}),
		subscribers: make(map[chan LiveAttackEvent]struct{}),
	}

	// Run SyncActorClusters
	count, err := store.SyncActorClusters()
	if err != nil {
		t.Fatalf("SyncActorClusters failed: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 clusters, got %d", count)
	}

	actors := store.ListActors()
	if len(actors) != 2 {
		t.Errorf("Expected 2 actor clusters returned, got %d", len(actors))
	}
	if actors[0].ActorID != "actor:01ca35584ad5" && actors[1].ActorID != "actor:01ca35584ad5" {
		t.Errorf("Expected actor:01ca35584ad5 in actors, got %+v", actors)
	}

	// Test GetEventByID
	ev, err := store.GetEventByID("ev2")
	if err != nil || ev == nil {
		t.Fatalf("GetEventByID failed: %v", err)
	}
	if ev.Username != "admin" || ev.EventType != "cowrie.login.success" {
		t.Errorf("GetEventByID returned wrong data: %+v", ev)
	}

	// Test TTL caching on GetGlobeTelemetry
	globe1 := store.GetGlobeTelemetry(false)
	globe2 := store.GetGlobeTelemetry(false)
	if !globe1.ServerTime.Equal(globe2.ServerTime) {
		t.Errorf("GetGlobeTelemetry did not return cached value within TTL")
	}

	// Test WAL checkpoint
	store.CheckpointWAL()
}
