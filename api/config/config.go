package config

import (
	"bufio"
	"os"
	"strings"
)

type Config struct {
	Addr          string
	DBPath        string
	CowrieLogPath string
	GeoIPCityPath string
}

func loadEnvFiles() {
	candidates := []string{
		".env",
		"../.env",
		"/opt/honeytrace/.env",
		"/var/lib/honeytrace/.env",
	}
	for _, p := range candidates {
		if file, err := os.Open(p); err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					k := strings.TrimSpace(parts[0])
					v := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
					if os.Getenv(k) == "" {
						_ = os.Setenv(k, v)
					}
				}
			}
			_ = file.Close()
			break
		}
	}
}

func Load() Config {
	loadEnvFiles()

	addr := os.Getenv("HONEYTRACE_ADDR")
	if addr == "" {
		addr = ":8080"
	}

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

	return Config{
		Addr:          addr,
		DBPath:        dbPath,
		CowrieLogPath: logPath,
		GeoIPCityPath: mmdbPath,
	}
}
