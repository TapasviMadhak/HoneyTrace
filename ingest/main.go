package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	log.Println("honeytrace ingest engine starting...")

	dbPath := os.Getenv("HONEYTRACE_DB_PATH")
	if dbPath == "" {
		candidates := []string{
			"/opt/honeytrace/data/honeytrace.db",
			"/var/lib/honeytrace/cowrie-events.sqlite3",
			"./data/honeytrace.db",
			"./honeytrace.db",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				dbPath = c
				break
			}
		}
		if dbPath == "" {
			dbPath = "/opt/honeytrace/data/honeytrace.db"
		}
	}

	logPath := os.Getenv("COWRIE_LOG_PATH")
	if logPath == "" {
		candidates := []string{
			"/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
			"/var/log/cowrie/cowrie.json",
			"./data/cowrie.json",
			"./cowrie.json",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				logPath = c
				break
			}
		}
		if logPath == "" {
			logPath = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
		}
	}

	mmdbPath := os.Getenv("GEOIP_CITY_PATH")

	tailer, err := NewTailer(dbPath, logPath, mmdbPath)
	if err != nil {
		log.Fatalf("[Ingest] Failed starting tailer engine: %v", err)
	}

	go tailer.Start()

	// Wait for shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[Ingest] Shutdown signal received. Stopping tailer...")
	tailer.Stop()
	log.Println("[Ingest] Ingest engine exited cleanly.")
}
