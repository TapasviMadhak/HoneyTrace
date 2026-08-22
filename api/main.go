package main

import (
	"log"
	"net/http"
	"time"

	"honeytrace/api/config"
)

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Cache-Control, Pragma")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	cfg := config.Load()
	mux := http.NewServeMux()

	store, err := NewStore(cfg.DBPath, cfg.CowrieLogPath, cfg.GeoIPCityPath)
	if err != nil {
		log.Fatalf("failed opening store database: %v", err)
	}
	defer store.Close()

	ai := NewAIService()
	abuse := NewAbuseClient()
	Register(mux, store, ai, abuse)

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           corsMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("honeytrace api listening on %s (database: %s, cowrie log: %s)", cfg.Addr, cfg.DBPath, cfg.CowrieLogPath)
	log.Fatal(server.ListenAndServe())
}
