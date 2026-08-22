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

type GreyNoiseCommunityResponse struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"` // "malicious", "benign", "unknown"
	Name           string `json:"name"`           // Actor/scanner name e.g. "Mirai", "Shodan.io"
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

type CachedGreyNoise struct {
	IP             string    `json:"ip"`
	Noise          bool      `json:"noise"`
	Riot           bool      `json:"riot"`
	Classification string    `json:"classification"`
	Name           string    `json:"name"`
	Link           string    `json:"link"`
	LastSeen       string    `json:"last_seen"`
	Message        string    `json:"message"`
	CachedAt       time.Time `json:"cached_at"`
}

type GreyNoiseClient struct {
	apiKey     string
	httpClient *http.Client
	cache      map[string]CachedGreyNoise
	mu         sync.RWMutex
}

func NewGreyNoiseClient() *GreyNoiseClient {
	apiKey := os.Getenv("GREYNOISE_API_KEY")
	if apiKey != "" {
		log.Printf("[GreyNoise] Client initialized with API key (starts with: %s...)", apiKey[:min(6, len(apiKey))])
	} else {
		log.Printf("[GreyNoise] Running in Community mode (no GREYNOISE_API_KEY set).")
	}

	return &GreyNoiseClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		cache: make(map[string]CachedGreyNoise),
	}
}

// CheckIP queries GreyNoise Community API v3 with caching
func (c *GreyNoiseClient) CheckIP(ip string) (*CachedGreyNoise, error) {
	if ip == "" || ip == "127.0.0.1" || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "100.") || strings.HasPrefix(ip, "192.168.") {
		return &CachedGreyNoise{
			IP:             ip,
			Noise:          false,
			Riot:           false,
			Classification: "benign",
			Name:           "Internal/Private Network",
			Link:           "",
			LastSeen:       time.Now().UTC().Format(time.RFC3339),
			CachedAt:       time.Now(),
		}, nil
	}

	// 1. Check in-memory cache (valid for 6 hours)
	c.mu.RLock()
	cached, exists := c.cache[ip]
	c.mu.RUnlock()
	if exists && time.Since(cached.CachedAt) < 6*time.Hour {
		return &cached, nil
	}

	// 2. Query GreyNoise Community API
	endpoint := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", url.PathEscape(ip))
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	if c.apiKey != "" {
		req.Header.Set("key", c.apiKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// IP not observed as mass scanner
		result := CachedGreyNoise{
			IP:             ip,
			Noise:          false,
			Riot:           false,
			Classification: "unknown",
			Name:           "Targeted Scanner (Not in Mass Noise)",
			Link:           fmt.Sprintf("https://viz.greynoise.io/ip/%s", ip),
			LastSeen:       "Not observed in mass scan internet noise",
			CachedAt:       time.Now(),
		}
		c.mu.Lock()
		c.cache[ip] = result
		c.mu.Unlock()
		return &result, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("greynoise check failed (%d): %s", resp.StatusCode, string(body))
	}

	var data GreyNoiseCommunityResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	result := CachedGreyNoise{
		IP:             data.IP,
		Noise:          data.Noise,
		Riot:           data.Riot,
		Classification: data.Classification,
		Name:           data.Name,
		Link:           data.Link,
		LastSeen:       data.LastSeen,
		Message:        data.Message,
		CachedAt:       time.Now(),
	}

	c.mu.Lock()
	if len(c.cache) > 5000 {
		for k, v := range c.cache {
			if time.Since(v.CachedAt) > 6*time.Hour {
				delete(c.cache, k)
			}
		}
	}
	c.cache[ip] = result
	c.mu.Unlock()

	return &result, nil
}
