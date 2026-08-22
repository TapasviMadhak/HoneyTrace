package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

	// Static Cyber HUD frontend serving with SPA routing fallback
	distCandidates := []string{
		"dashboard/dist",
		"./dist",
		"/opt/honeytrace/dashboard/dist",
	}
	var distDir string
	for _, dir := range distCandidates {
		if info, err := os.Stat(filepath.Join(dir, "index.html")); err == nil && !info.IsDir() {
			distDir = dir
			break
		}
	}

	if distDir != "" {
		fileServer := http.FileServer(http.Dir(distDir))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/healthz" {
				return
			}
			fpath := filepath.Join(distDir, filepath.Clean(r.URL.Path))
			if info, err := os.Stat(fpath); err == nil && !info.IsDir() {
				fileServer.ServeHTTP(w, r)
				return
			}
			http.ServeFile(w, r, filepath.Join(distDir, "index.html"))
		})
		log.Printf("[Frontend] Serving static Cyber HUD from: %s", distDir)
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           corsMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("honeytrace api listening on %s (database: %s, cowrie log: %s)", cfg.Addr, cfg.DBPath, cfg.CowrieLogPath)
	log.Fatal(server.ListenAndServe())
}
