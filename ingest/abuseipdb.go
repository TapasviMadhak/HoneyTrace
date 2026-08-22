package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type IngestAbuseClient struct {
	apiKey     string
	httpClient *http.Client
	reported   map[string]time.Time
	mu         sync.Mutex
}

func NewIngestAbuseClient() *IngestAbuseClient {
	apiKey := os.Getenv("ABUSEIPDB_API_KEY")
	if apiKey != "" {
		log.Printf("[Ingest/AbuseIPDB] Automated reporting enabled (key starts with %s...)", apiKey[:min(8, len(apiKey))])
	}

	return &IngestAbuseClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		reported: make(map[string]time.Time),
	}
}

// ReportAttacker reports malicious honeypot attackers to AbuseIPDB with 24-hour rate-limiting.
func (c *IngestAbuseClient) ReportAttacker(ip string, attempts int, sampleUsername string) error {
	if c.apiKey == "" || ip == "" || ip == "127.0.0.1" || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "100.") || strings.HasPrefix(ip, "192.168.") {
		return nil
	}

	// Rate limit: Do not report the exact same IP more than once every 24 hours
	c.mu.Lock()
	lastReport, exists := c.reported[ip]
	if exists && time.Since(lastReport) < 24*time.Hour {
		c.mu.Unlock()
		return nil
	}
	c.reported[ip] = time.Now()
	c.mu.Unlock()

	endpoint := "https://api.abuseipdb.com/api/v2/report"

	// Categories: 18 = Brute-Force, 22 = SSH
	data := url.Values{}
	data.Set("ip", ip)
	data.Set("categories", "18,22")
	data.Set("comment", fmt.Sprintf("HoneyTrace Deception Sensor: Unauthorized SSH brute-force attack detected (%d attempts, targeted user: %s).", attempts, sampleUsername))

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("abuseipdb report status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("[AbuseIPDB] Successfully reported threat actor %s to global database", ip)
	return nil
}
