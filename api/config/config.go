package config

import "os"

type Config struct {
	Addr          string
	DBPath        string
	CowrieLogPath string
	GeoIPCityPath string
}

func Load() Config {
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
