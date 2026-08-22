package main

import (
	"encoding/json"
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

type AbuseCheckResponse struct {
	Data struct {
		IPAddress            string   `json:"ipAddress"`
		IsPublic             bool     `json:"isPublic"`
		IPVersion            int      `json:"ipVersion"`
		IsWhitelisted        bool     `json:"isWhitelisted"`
		AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
		CountryCode          string   `json:"countryCode"`
		UsageType            string   `json:"usageType"`
		ISP                  string   `json:"isp"`
		Domain               string   `json:"domain"`
		Hostnames            []string `json:"hostnames"`
		TotalReports         int      `json:"totalReports"`
		NumDistinctUsers     int      `json:"numDistinctUsers"`
		LastReportedAt       string   `json:"lastReportedAt"`
	} `json:"data"`
}

type CachedReputation struct {
	IP               string    `json:"ip"`
	Score            int       `json:"score"`
	TotalReports     int       `json:"total_reports"`
	NumDistinctUsers int       `json:"num_distinct_users"`
	ISP              string    `json:"isp"`
	UsageType        string    `json:"usage_type"`
	Domain           string    `json:"domain"`
	CountryCode      string    `json:"country_code"`
	IsWhitelisted    bool      `json:"is_whitelisted"`
	LastReportedAt   string    `json:"last_reported_at"`
	CachedAt         time.Time `json:"cached_at"`
}

type AbuseClient struct {
	apiKey     string
	httpClient *http.Client
	cache      map[string]CachedReputation
	mu         sync.RWMutex
}

func NewAbuseClient() *AbuseClient {
	apiKey := os.Getenv("ABUSEIPDB_API_KEY")
	if apiKey != "" {
		log.Printf("[AbuseIPDB] Client initialized with API key (starts with: %s...)", apiKey[:min(8, len(apiKey))])
	} else {
		log.Printf("[AbuseIPDB] No ABUSEIPDB_API_KEY found in environment. Reputation lookups will return simulated baseline scores.")
	}

	return &AbuseClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		cache: make(map[string]CachedReputation),
	}
}

// CheckIP fetches reputation data from AbuseIPDB APIv2 with in-memory caching.
func (c *AbuseClient) CheckIP(ip string) (*CachedReputation, error) {
	if ip == "" || ip == "127.0.0.1" || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "100.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "172.16.") {
		return &CachedReputation{
			IP:        ip,
			Score:     0,
			ISP:       "Internal/Private Network",
			UsageType: "Private / Reserved",
			CachedAt:  time.Now(),
		}, nil
	}

	// 1. Check in-memory cache (valid for 6 hours)
	c.mu.RLock()
	cached, exists := c.cache[ip]
	c.mu.RUnlock()
	if exists && time.Since(cached.CachedAt) < 6*time.Hour {
		return &cached, nil
	}

	// If no API key configured, return a deterministic fallback
	if c.apiKey == "" {
		rep := CachedReputation{
			IP:           ip,
			Score:        90,
			TotalReports: 142,
			ISP:          "External Host",
			UsageType:    "Data Center / Hosting",
			CachedAt:     time.Now(),
		}
		return &rep, nil
	}

	// 2. Query AbuseIPDB APIv2
	endpoint := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=30", url.QueryEscape(ip))
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("abuseipdb check failed (%d): %s", resp.StatusCode, string(body))
	}

	var result AbuseCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// 3. Save to cache
	rep := CachedReputation{
		IP:               result.Data.IPAddress,
		Score:            result.Data.AbuseConfidenceScore,
		TotalReports:     result.Data.TotalReports,
		NumDistinctUsers: result.Data.NumDistinctUsers,
		ISP:              result.Data.ISP,
		UsageType:        result.Data.UsageType,
		Domain:           result.Data.Domain,
		CountryCode:      result.Data.CountryCode,
		IsWhitelisted:    result.Data.IsWhitelisted,
		LastReportedAt:   result.Data.LastReportedAt,
		CachedAt:         time.Now(),
	}

	c.mu.Lock()
	if len(c.cache) > 5000 {
		for k, v := range c.cache {
			if time.Since(v.CachedAt) > 6*time.Hour {
				delete(c.cache, k)
			}
		}
	}
	c.cache[ip] = rep
	c.mu.Unlock()

	return &rep, nil
}

// ReportAttacker reports malicious honeypot breaches/scanners to AbuseIPDB.
func (c *AbuseClient) ReportAttacker(ip string, attempts int, sampleUsername string) error {
	if c.apiKey == "" || ip == "" || ip == "127.0.0.1" || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "100.") || strings.HasPrefix(ip, "192.168.") {
		return nil
	}

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
		return fmt.Errorf("abuseipdb report failed (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}
