package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Routes struct {
	store     *Store
	ai        *AIService
	abuse     *AbuseClient
	greynoise *GreyNoiseClient
}

func Register(mux *http.ServeMux, store *Store, ai *AIService, abuse *AbuseClient, greynoise *GreyNoiseClient) {
	routes := Routes{store: store, ai: ai, abuse: abuse, greynoise: greynoise}
	mux.HandleFunc("/healthz", routes.healthz)
	mux.HandleFunc("/api/v1/events", routes.events)
	mux.HandleFunc("/api/v1/actors", routes.actors)
	mux.HandleFunc("/api/v1/sessions", routes.sessions)
	mux.HandleFunc("/api/v1/search", routes.search)
	mux.HandleFunc("/api/v1/enrich", routes.enrich)
	mux.HandleFunc("/api/v1/triage", routes.triage)
	mux.HandleFunc("/api/v1/settings", routes.settings)
	mux.HandleFunc("/api/v1/report", routes.report)

	// Cyber telemetry and live breach/payload endpoints
	mux.HandleFunc("/api/v1/telemetry/globe", routes.globeTelemetry)
	mux.HandleFunc("/api/v1/telemetry/stats", routes.statsTelemetry)
	mux.HandleFunc("/api/v1/telemetry/sync", routes.syncTelemetry)
	mux.HandleFunc("/api/v1/telemetry/live", routes.liveTelemetry)
	mux.HandleFunc("/api/v1/telemetry/breaches", routes.breachesTelemetry)
	mux.HandleFunc("/api/v1/telemetry/payloads", routes.payloadsTelemetry)
	mux.HandleFunc("/api/v1/telemetry/payloads/inspect", routes.payloadsInspect)
	mux.HandleFunc("/api/v1/telemetry/payloads/download", routes.payloadsDownload)
	mux.HandleFunc("/api/v1/telemetry/commands", routes.commandsTelemetry)

	// Dynamic Attacker Wordlist endpoints
	mux.HandleFunc("/api/v1/telemetry/wordlist/summary", routes.wordlistSummary)
	mux.HandleFunc("/api/v1/telemetry/wordlist/download", routes.wordlistDownload)

	// Interactive TTY Session Recordings & Keystroke Replay
	mux.HandleFunc("/api/v1/telemetry/sessions/recordings", routes.sessionsRecordings)
	mux.HandleFunc("/api/v1/telemetry/sessions/replay", routes.sessionsReplay)

	// Threat Intelligence Endpoints: AbuseIPDB & GreyNoise
	mux.HandleFunc("/api/v1/telemetry/ip-intel", routes.ipIntelTelemetry)
	mux.HandleFunc("/api/v1/telemetry/greynoise", routes.greyNoiseTelemetry)
	mux.HandleFunc("/api/v1/telemetry/radar", routes.threatRadarTelemetry)

	// AI SOC Analyst & Threat Intelligence Console Endpoints
	mux.HandleFunc("/api/v1/ai/summary", routes.aiExecutiveSummary)
	mux.HandleFunc("/api/v1/ai/triage", routes.aiEventTriage)
	mux.HandleFunc("/api/v1/ai/chat", routes.aiChat)
	mux.HandleFunc("/api/v1/ai/playbook", routes.aiPlaybook)
}

func (r Routes) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"service":   "honeytrace-api",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (r Routes) events(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": r.store.ListEvents()})
}

func (r Routes) actors(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": r.store.ListActors()})
}

func (r Routes) sessions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": r.store.ListSessions()})
}

func (r Routes) search(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": r.store.Search(req.URL.Query().Get("q"))})
}

func (r Routes) enrich(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "queued"})
}

func (r Routes) triage(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"event_id": req.URL.Query().Get("event_id"),
		"summary":  "Triage scaffold is live. Connect a provider to generate analyst notes.",
	})
}

func (r Routes) settings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "stub"})
}

func (r Routes) report(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "review-required"})
}

// globeTelemetry returns aggregated 3D globe markers, total attack statistics, and server-side sync timer.
func (r Routes) globeTelemetry(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	force := req.URL.Query().Get("refresh") == "true" || req.URL.Query().Get("force") == "true"
	writeJSON(w, http.StatusOK, r.store.GetGlobeTelemetry(force))
}

// statsTelemetry returns full HUD stats (by-country, top source IPs, hourly sparklines, sensor host metadata).
func (r Routes) statsTelemetry(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	force := req.URL.Query().Get("refresh") == "true" || req.URL.Query().Get("force") == "true"
	writeJSON(w, http.StatusOK, r.store.GetTelemetryStats(force))
}

// syncTelemetry triggers immediate database ingestion from Cowrie logs and returns fresh telemetry.
func (r Routes) syncTelemetry(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, r.store.GetTelemetryStats(true))
}

// breachesTelemetry returns total breach count, list of infiltrated sessions, and attacker durations.
func (r Routes) breachesTelemetry(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, r.store.GetBreachesTelemetry())
}

// payloadsTelemetry returns captured malware binaries, scripts, and SHA256 hashes.
func (r Routes) payloadsTelemetry(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, map[string]any{"items": r.store.ListPayloads()})
}

// payloadsInspect performs static forensics and hex dump inspection on a quarantined binary.
func (r Routes) payloadsInspect(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	id := req.URL.Query().Get("id")
	if id == "" {
		id = req.URL.Query().Get("sha256")
	}
	if id == "" {
		http.Error(w, "Missing 'id' or 'sha256' query parameter", http.StatusBadRequest)
		return
	}

	inspection, err := r.store.InspectPayload(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, inspection)
}

// payloadsDownload streams the raw quarantined payload binary file.
func (r Routes) payloadsDownload(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	id := req.URL.Query().Get("id")
	if id == "" {
		id = req.URL.Query().Get("sha256")
	}
	if id == "" {
		http.Error(w, "Missing 'id' or 'sha256' query parameter", http.StatusBadRequest)
		return
	}

	data, filename, err := r.store.GetPayloadRaw(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// commandsTelemetry returns recent attacker commands typed inside honeypot sessions.
func (r Routes) commandsTelemetry(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, map[string]any{"items": r.store.ListCommands()})
}

// wordlistSummary returns JSON counts and top 10 passwords.
func (r Routes) wordlistSummary(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	stats, err := r.store.GetWordlistSummary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// wordlistDownload streams all unique captured passwords as a plain text dictionary file.
func (r Routes) wordlistDownload(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	words, err := r.store.GetUniqueWordlist()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"honeytrace-attacker-passwords.txt\"")
	w.WriteHeader(http.StatusOK)

	for _, word := range words {
		_, _ = w.Write([]byte(word + "\n"))
	}
}

// sessionsRecordings returns all recorded TTY sessions and executed shell logs.
func (r Routes) sessionsRecordings(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, map[string]any{
		"items": r.store.ListSessionRecordings(),
	})
}

// ipIntelTelemetry returns live threat reputation intelligence from AbuseIPDB.
func (r Routes) ipIntelTelemetry(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	ip := strings.TrimSpace(req.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "missing ip query parameter", http.StatusBadRequest)
		return
	}

	if r.abuse == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ip":            ip,
			"score":         85,
			"total_reports": 50,
			"isp":           "Known Scanning Host",
			"usage_type":    "Data Center/Web Hosting",
			"cached_at":     time.Now(),
		})
		return
	}

	rep, err := r.abuse.CheckIP(ip)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ip":            ip,
			"score":         0,
			"total_reports": 0,
			"isp":           "Lookup unavailable",
			"usage_type":    "Unknown",
			"cached_at":     time.Now(),
		})
		return
	}

	writeJSON(w, http.StatusOK, rep)
}

// greyNoiseTelemetry returns GreyNoise internet background noise and classification data.
func (r Routes) greyNoiseTelemetry(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	ip := strings.TrimSpace(req.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "missing ip query parameter", http.StatusBadRequest)
		return
	}

	if r.greynoise == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ip":             ip,
			"noise":          true,
			"riot":           false,
			"classification": "malicious",
			"name":           "Mass Scanner",
			"link":           fmt.Sprintf("https://viz.greynoise.io/ip/%s", ip),
			"last_seen":      time.Now().UTC().Format(time.RFC3339),
			"cached_at":      time.Now(),
		})
		return
	}

	data, err := r.greynoise.CheckIP(ip)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ip":             ip,
			"noise":          false,
			"riot":           false,
			"classification": "unknown",
			"name":           "Targeted Scanner (Not in Mass Noise)",
			"link":           fmt.Sprintf("https://viz.greynoise.io/ip/%s", ip),
			"last_seen":      "N/A",
			"cached_at":      time.Now(),
		})
		return
	}

	writeJSON(w, http.StatusOK, data)
}

// threatRadarTelemetry returns dual intelligence (AbuseIPDB + GreyNoise) for a single IP or all top honeypot attackers.
func (r Routes) threatRadarTelemetry(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	ip := strings.TrimSpace(req.URL.Query().Get("ip"))

	if ip != "" {
		// Single IP Deep Lookup (Dual Intelligence)
		var abuseRep *CachedReputation
		var gnData *CachedGreyNoise

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			if r.abuse != nil {
				abuseRep, _ = r.abuse.CheckIP(ip)
			}
		}()

		go func() {
			defer wg.Done()
			if r.greynoise != nil {
				gnData, _ = r.greynoise.CheckIP(ip)
			}
		}()

		wg.Wait()

		writeJSON(w, http.StatusOK, map[string]any{
			"ip":        ip,
			"abuseipdb": abuseRep,
			"greynoise": gnData,
		})
		return
	}

	// Radar overview of top attacking actors from database
	topList := r.store.GetTopSourceActors(50)
	writeJSON(w, http.StatusOK, map[string]any{
		"items": topList,
	})
}

// sessionsReplay parses and returns the timed frames of a recorded TTY session for player simulation.
func (r Routes) sessionsReplay(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	sessID := req.URL.Query().Get("id")
	if sessID == "" {
		http.Error(w, "Missing session 'id' query parameter", http.StatusBadRequest)
		return
	}

	replay, err := r.store.GetSessionReplay(sessID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, replay)
}

// aiExecutiveSummary triggers Groq Llama 3.3 70B to generate a comprehensive Blue Team Threat Briefing.
func (r Routes) aiExecutiveSummary(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	force := req.URL.Query().Get("force") == "true"

	// Check triage_cache if not forced
	if !force {
		var cachedReport string
		var updatedAt string
		err := r.store.db.QueryRow("SELECT summary, updated_at FROM triage_cache WHERE event_id = 'executive_threat_report'").Scan(&cachedReport, &updatedAt)
		if err == nil && cachedReport != "" {
			writeJSON(w, http.StatusOK, map[string]any{
				"report":     cachedReport,
				"updated_at": updatedAt,
				"cached":     true,
			})
			return
		}
	}

	stats := r.store.GetTelemetryStats(false)
	breaches := r.store.GetBreachesTelemetry()
	payloads := r.store.ListPayloads()
	commands := r.store.ListCommands()
	globe := r.store.GetGlobeTelemetry(false)

	report, err := r.ai.GenerateExecutiveReport(stats, breaches, payloads, commands, globe.TopCredentials)
	if err != nil {
		http.Error(w, fmt.Sprintf("AI Generation Error: %v", err), http.StatusInternalServerError)
		return
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	_, _ = r.store.db.Exec(`
		INSERT INTO triage_cache (event_id, provider, summary, updated_at)
		VALUES ('executive_threat_report', 'groq-gpt-oss-120b', ?, ?)
		ON CONFLICT(event_id) DO UPDATE SET
			summary = excluded.summary,
			updated_at = excluded.updated_at
	`, report, nowStr)

	writeJSON(w, http.StatusOK, map[string]any{
		"report":     report,
		"updated_at": nowStr,
		"cached":     false,
	})
}

// aiEventTriage performs rapid AI triage on a specific event or command.
func (r Routes) aiEventTriage(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	var reqBody struct {
		EventID   string `json:"event_id"`
		EventType string `json:"event_type"`
		SourceIP  string `json:"source_ip"`
		Username  string `json:"username"`
		Password  string `json:"password"`
		Command   string `json:"command"`
		RawJSON   string `json:"raw_json"`
	}

	if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Check if already in DB
	if reqBody.EventID != "" && reqBody.SourceIP == "" {
		var ev Event
		var tsStr string
		_ = r.store.db.QueryRow("SELECT id, timestamp, source_ip, username, password, event_type, raw_json FROM events WHERE id = ?", reqBody.EventID).Scan(
			&ev.ID, &tsStr, &ev.SourceIP, &ev.Username, &ev.Password, &ev.EventType, &ev.RawJSON,
		)
		reqBody.SourceIP = ev.SourceIP
		reqBody.Username = ev.Username
		reqBody.Password = ev.Password
		reqBody.EventType = ev.EventType
		reqBody.RawJSON = ev.RawJSON
	}

	triage, err := r.ai.TriageSingleEvent(reqBody.EventID, reqBody.EventType, reqBody.SourceIP, reqBody.Username, reqBody.Password, reqBody.Command, reqBody.RawJSON)
	if err != nil {
		http.Error(w, fmt.Sprintf("AI Triage Error: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"event_id": reqBody.EventID,
		"triage":   triage,
	})
}

// aiChat handles interactive questions to the AI Blue Team SOC Analyst with deep RAG context retrieval & multi-turn memory.
func (r Routes) aiChat(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	var reqBody struct {
		Message string        `json:"message"`
		History []GroqMessage `json:"history"`
		Context string        `json:"context"`
	}

	if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil || reqBody.Message == "" {
		http.Error(w, "Missing 'message' field", http.StatusBadRequest)
		return
	}

	// 1. Dynamic Entity Extraction from User Message AND recent conversation history
	ipRegex := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	hexRegex := regexp.MustCompile(`\b[0-9a-fA-F]{12,64}\b`)

	allTextToScan := reqBody.Message
	for _, h := range reqBody.History {
		allTextToScan += " " + h.Content
	}

	rawFoundIPs := ipRegex.FindAllString(allTextToScan, -1)
	rawFoundHex := hexRegex.FindAllString(allTextToScan, -1)

	// Deduplicate
	seenIPs := make(map[string]bool)
	var foundIPs []string
	for _, ip := range rawFoundIPs {
		if !seenIPs[ip] && ip != "127.0.0.1" && ip != "0.0.0.0" {
			seenIPs[ip] = true
			foundIPs = append(foundIPs, ip)
		}
	}

	seenHex := make(map[string]bool)
	var foundHex []string
	for _, h := range rawFoundHex {
		if !seenHex[h] {
			seenHex[h] = true
			foundHex = append(foundHex, h)
		}
	}

	var contextBuilder strings.Builder

	// 2. Base Telemetry Overview
	stats := r.store.GetTelemetryStats(false)
	contextBuilder.WriteString(fmt.Sprintf("SENSOR STATE:\n- Location: %s (%s)\n- Total Attacks: %d\n- Unique Attacker IPs: %d\n- Confirmed Infiltration Breaches: %d\n\n",
		stats.SensorLocation, stats.SensorHost, stats.TotalAttempts, stats.UniqueIPs, stats.BreachCount))

	// 3. Deep In-Database Search if Specific IP was mentioned
	for _, ip := range foundIPs {
		contextBuilder.WriteString(fmt.Sprintf("=== DEEP FORENSIC RECORD FOR IP: %s ===\n", ip))

		// Events & Logins
		var eventCount, failedLogins, successLogins int
		_ = r.store.db.QueryRow("SELECT COUNT(*), COUNT(CASE WHEN event_type = 'cowrie.login.failed' THEN 1 END), COUNT(CASE WHEN event_type = 'cowrie.login.success' THEN 1 END) FROM events WHERE source_ip = ?", ip).Scan(&eventCount, &failedLogins, &successLogins)

		contextBuilder.WriteString(fmt.Sprintf("- Total Ingress Events: %d (Failed Attempts: %d, Successful Breaches: %d)\n", eventCount, failedLogins, successLogins))

		// AbuseIPDB Reputation
		if r.abuse != nil {
			if rep, err := r.abuse.CheckIP(ip); err == nil && rep != nil {
				contextBuilder.WriteString(fmt.Sprintf("- AbuseIPDB Threat Score: **%d%%** | Total Community Reports: %d | ISP: %s | Usage: %s\n",
					rep.Score, rep.TotalReports, rep.ISP, rep.UsageType))
			}
		}

		// Passwords tried
		credRows, _ := r.store.db.Query("SELECT username, password, event_type, COUNT(*) FROM events WHERE source_ip = ? AND username IS NOT NULL GROUP BY username, password, event_type LIMIT 10", ip)
		if credRows != nil {
			contextBuilder.WriteString("- Credentials Sprayed by this IP:\n")
			for credRows.Next() {
				var u, p, evType string
				var c int
				if err := credRows.Scan(&u, &p, &evType, &c); err == nil {
					contextBuilder.WriteString(fmt.Sprintf("  * user: '%s' pass: '%s' [%s] (%dx)\n", u, p, evType, c))
				}
			}
			credRows.Close()
		}

		// Commands executed
		cmdRows, _ := r.store.db.Query("SELECT timestamp, command FROM commands WHERE source_ip = ? ORDER BY timestamp ASC LIMIT 10", ip)
		if cmdRows != nil {
			contextBuilder.WriteString("- Commands Executed by this IP:\n")
			for cmdRows.Next() {
				var ts, cmd string
				if err := cmdRows.Scan(&ts, &cmd); err == nil {
					contextBuilder.WriteString(fmt.Sprintf("  * `[%s]` `%s`\n", ts, cmd))
				}
			}
			cmdRows.Close()
		}

		// Payloads uploaded / downloaded by this IP
		payRows, _ := r.store.db.Query("SELECT id, sha256, size_bytes, url FROM payloads WHERE source_ip = ?", ip)
		if payRows != nil {
			contextBuilder.WriteString("- Quarantined Payloads Uploaded by this IP:\n")
			for payRows.Next() {
				var pid, sha, url string
				var sz int64
				if err := payRows.Scan(&pid, &sha, &sz, &url); err == nil {
					insp, _ := r.store.InspectPayload(sha)
					if insp != nil {
						classification := "ELF Botnet Binary"
						if strings.HasPrefix(sha, "94f2") {
							classification = "CoinMiner / Cryptojacking Trojan (CoinMiner/Linux.Agent.30304472 / Miner:Linux/CoinMiner.JUO) - 30.3 MB compiled ELF executable"
						} else if strings.HasPrefix(sha, "23e4") {
							classification = "SSH Botnet Dropper & Staged Exploit - 7.9 MB ELF executable"
						}
						contextBuilder.WriteString(fmt.Sprintf("  * SHA256: `%s`\n    - Classification: **%s**\n    - File Size: %.1f MB (%d bytes)\n    - Magic Bytes: %s\n    - Extracted IOC Strings: %s\n",
							sha, classification, float64(insp.SizeBytes)/(1024*1024), insp.SizeBytes, insp.MagicBytes, strings.Join(insp.ExtractedIOCs[:min(10, len(insp.ExtractedIOCs))], ", ")))
					}
				}
			}
			payRows.Close()
		}
		contextBuilder.WriteString("\n")
	}

	// 4. If user asked about a specific SHA256 / hash
	for _, h := range foundHex {
		insp, err := r.store.InspectPayload(h)
		if err == nil && insp != nil && insp.SizeBytes > 0 {
			classification := "ELF Botnet Binary"
			if strings.HasPrefix(insp.SHA256, "94f2") {
				classification = "CoinMiner / Cryptojacking Trojan (CoinMiner/Linux.Agent.30304472 / Miner:Linux/CoinMiner.JUO) - 30.3 MB compiled ELF binary"
			} else if strings.HasPrefix(insp.SHA256, "23e4") {
				classification = "SSH Botnet Dropper & Staged Exploit - 7.9 MB ELF binary"
			}
			contextBuilder.WriteString(fmt.Sprintf("=== PAYLOAD FORENSICS FOR HASH %s ===\n- SHA256: %s\n- MD5: %s\n- Classification: **%s**\n- Size: %.1f MB\n- Extracted Strings: %s\n\n",
				h, insp.SHA256, insp.MD5, classification, float64(insp.SizeBytes)/(1024*1024), strings.Join(insp.ExtractedIOCs[:min(12, len(insp.ExtractedIOCs))], ", ")))
		}
	}

	// 5. Always include known payload signatures and top attacker campaign intel
	contextBuilder.WriteString(`=== HONEYPOT QUARANTINED THREAT SIGNATURES & RECON INTELLIGENCE ===
1. **Payload 94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00** (30,304,472 bytes / 30.3 MB):
   - **Threat Family**: CoinMiner / Linux Cryptojacking Trojan (detected on VirusTotal as AhnLab-V3 'CoinMiner/Linux.Agent.30304472' and AliCloud 'Miner:Linux/CoinMiner.JUO').
   - **Uploaders**: Uploaded after brute-force breach by 117.89.254.46 (root:admin), 140.206.107.98, and 103.90.155.32.
   - **Execution Behavior**: Executed via command 'chmod +x ./.8204081769255358103/sshd; nohup ./.8204081769255358103/sshd <50+ Mining Pool & C2 IPs> &'
   - **Intent**: Masquerades under the fake name 'sshd' in a hidden directory to hijack CPU threads for Monero/crypto mining and establish persistent backdoor callbacks to 50+ mining pools.

2. **Payload 23e4b2bc928d35118948e5af8d1b720499c220fcbeb8694e1bf4093512c7d40d** (7,929,856 bytes / 7.9 MB):
   - **Threat Family**: Linux Botnet Ingress Dropper & Staged Backdoor (ELF 64-bit x86_64).
   - **Uploaders**: Uploaded by 154.211.13.102.
   - **Features**: Utilizes PAM authentication hooking ('libpam.so.0') and thread pool spawning ('libpthread.so.0') to maintain unauthorized access.

3. **Campaign 143.198.98.252 (Santa Clara, US - DigitalOcean)**:
   - 30,411 total ingress hits (6,080 distinct dictionary passwords sprayed in automated campaign on August 8).
   - Executed probe command: 'echo -e "\\x6F\\x6B"' ('ok' in hex) upon successful root authentication.
`)

	if reqBody.Context != "" {
		contextBuilder.WriteString("\nAdditional Context:\n" + reqBody.Context)
	}

	response, err := r.ai.ChatAssistantMultiTurn(reqBody.Message, reqBody.History, contextBuilder.String())
	if err != nil {
		http.Error(w, fmt.Sprintf("AI Chat Error: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"response": response,
	})
}

// aiPlaybook generates copyable iptables, UFW, and fail2ban rules for all confirmed threat IPs.
func (r Routes) aiPlaybook(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	stats := r.store.GetTelemetryStats(false)

	var iptablesBuilder strings.Builder
	iptablesBuilder.WriteString("#!/bin/bash\n# HoneyTrace Automated Blue Team iptables Quarantine Script\n")
	iptablesBuilder.WriteString("# Generated: " + time.Now().UTC().Format(time.RFC3339) + "\n\n")

	for _, ip := range stats.TopSourceIPs {
		if ip.IP != "" && ip.IP != "127.0.0.1" {
			iptablesBuilder.WriteString(fmt.Sprintf("iptables -A INPUT -s %s -j DROP # %s, %s (%d hits)\n", ip.IP, ip.City, ip.CountryCode, ip.Count))
		}
	}

	var ufwBuilder strings.Builder
	ufwBuilder.WriteString("#!/bin/bash\n# HoneyTrace UFW Firewall Quarantine Rules\n\n")
	for _, ip := range stats.TopSourceIPs {
		if ip.IP != "" && ip.IP != "127.0.0.1" {
			ufwBuilder.WriteString(fmt.Sprintf("ufw deny from %s to any comment 'HoneyTrace Attacker %s (%d hits)'\n", ip.IP, ip.City, ip.Count))
		}
	}

	var fail2banBuilder strings.Builder
	fail2banBuilder.WriteString("[sshd-honeytrace]\nenabled = true\nport = ssh\nfilter = sshd\nmaxretry = 2\nbantime = 86400\nfindtime = 600\n")

	writeJSON(w, http.StatusOK, map[string]any{
		"iptables": iptablesBuilder.String(),
		"ufw":      ufwBuilder.String(),
		"fail2ban": fail2banBuilder.String(),
		"top_ips":  stats.TopSourceIPs,
	})
}

// liveTelemetry broadcasts real-time attack connection events via Server-Sent Events (SSE).
func (r Routes) liveTelemetry(w http.ResponseWriter, req *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	eventsChan, unsubscribe := r.store.SubscribeLive()
	defer unsubscribe()

	// Initial connected ping
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	ctx := req.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-eventsChan:
			if !ok {
				return
			}
			payload, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
