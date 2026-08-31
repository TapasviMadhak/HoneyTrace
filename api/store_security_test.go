package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestPathTraversal_InputValidation(t *testing.T) {
	maliciousHashes := []string{
		"../../../../etc/passwd",
		"../../../../proc/self/environ",
		"/etc/passwd",
		"\\..\\..\\windows\\system32\\cmd.exe",
		"..%2f..%2f..%2fetc/passwd",
		"pay-../../../../etc/shadow",
		"23e4b2bc928d35118948e5af8d1b720499c220fcbeb8694e1bf4093512c7d40d/../../../../etc/passwd",
		"23e4b2bc928d35118948e5af8d1b720499c220fcbeb8694e1bf4093512c7d40d\x00.png",
		"23e4b2bc928d35118948e5af8d1b720499c220fcbeb8694e1bf4093512c7d40d\n/etc/passwd",
		"'; DROP TABLE payloads; --",
		"",
		"   ",
	}

	for _, badHash := range maliciousHashes {
		if isValidSafeHash(badHash) {
			t.Errorf("Security check failed: isValidSafeHash allowed malicious hash: %q", badHash)
		}
	}

	validHashes := []string{
		"23e4b2bc928d35118948e5af8d1b720499c220fcbeb8694e1bf4093512c7d40d",
		"94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00",
		"pay-0da25bf692e3c4e0",
		"pay-23e4b2bc928d35118948e5af8d1b720499c220fcbeb8694e1bf4093512c7d40d",
	}

	for _, goodHash := range validHashes {
		if !isValidSafeHash(goodHash) {
			t.Errorf("False positive: isValidSafeHash rejected valid hash: %q", goodHash)
		}
	}
}

func TestPathTraversal_SessionIDValidation(t *testing.T) {
	maliciousSessionIDs := []string{
		"../../../../etc/passwd",
		"../../var/log/cowrie/cowrie.json",
		"0a96cb919bcb/../../../etc/shadow",
		"/etc/passwd",
		"sess-\x00-admin",
		"sess\r\nadmin",
		"",
	}

	for _, badID := range maliciousSessionIDs {
		if isValidSafeSessionID(badID) {
			t.Errorf("Security check failed: isValidSafeSessionID allowed malicious ID: %q", badID)
		}
	}

	validSessionIDs := []string{
		"0a96cb919bcb",
		"af5283fedeba",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"sess-2026-08-30-prod-01",
	}

	for _, goodID := range validSessionIDs {
		if !isValidSafeSessionID(goodID) {
			t.Errorf("False positive: isValidSafeSessionID rejected valid session ID: %q", goodID)
		}
	}
}

func TestPathTraversal_SafeJoinAndVerify(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "honeytrace-safe-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a dummy legit file in tempDir
	legitFile := filepath.Join(tempDir, "legit.bin")
	_ = os.WriteFile(legitFile, []byte("safe content"), 0600)

	// Test legit access
	resolved, err := safeJoinAndVerify(tempDir, "legit.bin")
	if err != nil {
		t.Fatalf("safeJoinAndVerify rejected legit file: %v", err)
	}
	if resolved != legitFile {
		t.Errorf("Expected %s, got %s", legitFile, resolved)
	}

	// Test traversal attempts
	traversals := []string{
		"../../../../etc/passwd",
		"../" + filepath.Base(tempDir) + "_other",
		"/etc/passwd",
		"..",
		".",
	}

	for _, trav := range traversals {
		_, err := safeJoinAndVerify(tempDir, trav)
		if err == nil {
			t.Errorf("Security violation: safeJoinAndVerify allowed traversal path: %q", trav)
		}
	}
}

func TestPathTraversal_HTTPRoutesBlocked(t *testing.T) {
	// Setup in-memory sqlite store
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open memory db: %v", err)
	}
	defer db.Close()

	store := &Store{
		db:      db,
		geo:     NewGeoResolver(""),
		logPath: "",
	}
	_ = initSchema(db)

	routes := Routes{store: store}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/telemetry/payloads/inspect", routes.payloadsInspect)
	mux.HandleFunc("/api/v1/telemetry/payloads/download", routes.payloadsDownload)
	mux.HandleFunc("/api/v1/telemetry/sessions/replay", routes.sessionsReplay)

	testCases := []struct {
		url            string
		expectedStatus int
	}{
		{"/api/v1/telemetry/payloads/download?sha256=../../../../etc/passwd", http.StatusBadRequest},
		{"/api/v1/telemetry/payloads/inspect?id=../../../../proc/self/environ", http.StatusBadRequest},
		{"/api/v1/telemetry/payloads/download?id=..%2f..%2f..%2fetc/passwd", http.StatusBadRequest},
		{"/api/v1/telemetry/sessions/replay?id=../../../../etc/shadow", http.StatusBadRequest},
		{"/api/v1/telemetry/payloads/download?sha256=nonexistent_invalid", http.StatusBadRequest},
		{"/api/v1/telemetry/payloads/download?sha256=0000000000000000000000000000000000000000000000000000000000000000", http.StatusNotFound},
	}

	for _, tc := range testCases {
		req := httptest.NewRequest("GET", tc.url, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != tc.expectedStatus {
			t.Errorf("For URL %q: expected HTTP status %d, got %d (body: %s)", tc.url, tc.expectedStatus, rec.Code, rec.Body.String())
		}
	}
}
