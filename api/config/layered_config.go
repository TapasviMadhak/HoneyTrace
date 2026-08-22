package config

import "os"

func ResolveConfigFile() string {
	path := os.Getenv("HONEYTRACE_CONFIG_FILE")
	if path == "" {
		path = ""
	}

	return path
}
