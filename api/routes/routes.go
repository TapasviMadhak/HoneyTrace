package routes

import (
	"encoding/json"
	"net/http"
	"time"
)

func Register(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", healthz)
	mux.HandleFunc("/api/v1/events", events)
	mux.HandleFunc("/api/v1/actors", actors)
	mux.HandleFunc("/api/v1/sessions", sessions)
	mux.HandleFunc("/api/v1/search", search)
	mux.HandleFunc("/api/v1/enrich", enrich)
	mux.HandleFunc("/api/v1/triage", triage)
	mux.HandleFunc("/api/v1/settings", settings)
	mux.HandleFunc("/api/v1/report", report)
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"service":   "honeytrace-api",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func events(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
}

func actors(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
}

func sessions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
}

func search(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
}

func enrich(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "queued"})
}

func triage(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": "Triage scaffold is live. Connect a provider to generate analyst notes.",
	})
}

func settings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "stub"})
}

func report(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "review-required"})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
