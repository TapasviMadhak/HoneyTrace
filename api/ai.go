package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type GroqMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type GroqChatRequest struct {
	Model       string        `json:"model"`
	Messages    []GroqMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
}

type GroqChoice struct {
	Message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"message"`
	FinishReason string `json:"finish_reason"`
}

type GroqChatResponse struct {
	ID      string       `json:"id"`
	Choices []GroqChoice `json:"choices"`
	Error   *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

type AIService struct {
	apiKey string
	client *http.Client
}

func NewAIService() *AIService {
	apiKey := strings.TrimSpace(os.Getenv("GROQ_API_KEY"))

	// If empty, check .env files
	if apiKey == "" {
		candidates := []string{
			".env",
			"../.env",
			"/opt/honeytrace/.env",
		}
		for _, p := range candidates {
			if data, err := os.ReadFile(p); err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "GROQ_API_KEY=") {
						apiKey = strings.TrimSpace(strings.TrimPrefix(line, "GROQ_API_KEY="))
						apiKey = strings.Trim(apiKey, "\"'")
						break
					}
				}
				if apiKey != "" {
					break
				}
			}
		}
	}

	if apiKey != "" {
		log.Printf("[AI] Groq AI service initialized (key loaded: %s...)", apiKey[:min(10, len(apiKey))])
	} else {
		log.Printf("[AI] Warning: GROQ_API_KEY not set. Set GROQ_API_KEY in .env or environment.")
	}

	return &AIService{
		apiKey: apiKey,
		client: &http.Client{Timeout: 45 * time.Second},
	}
}

func (ai *AIService) CallGroqMessages(messages []GroqMessage, maxTokens int) (string, error) {
	if ai.apiKey == "" {
		return "", fmt.Errorf("GROQ_API_KEY is not configured on the server")
	}

	reqBody := GroqChatRequest{
		Model:       "openai/gpt-oss-120b",
		Messages:    messages,
		Temperature: 0.3,
		MaxTokens:   maxTokens,
	}

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequest("POST", "https://api.groq.com/openai/v1/chat/completions", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return "", err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+ai.apiKey)

	resp, err := ai.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("groq API request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed reading groq response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("groq API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var chatResp GroqChatResponse
	if err := json.Unmarshal(bodyBytes, &chatResp); err != nil {
		return "", fmt.Errorf("failed parsing groq response JSON: %w", err)
	}

	if chatResp.Error != nil {
		return "", fmt.Errorf("groq error: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) > 0 {
		return chatResp.Choices[0].Message.Content, nil
	}

	return "", fmt.Errorf("no choices returned by Groq AI")
}

func (ai *AIService) CallGroq(systemPrompt, userPrompt string, maxTokens int) (string, error) {
	return ai.CallGroqMessages([]GroqMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}, maxTokens)
}

// GenerateExecutiveReport analyzes all honeypot telemetry and produces an in-depth Blue Team Cyber Briefing.
func (ai *AIService) GenerateExecutiveReport(
	stats TelemetryStatsResponse,
	breaches BreachesResponse,
	payloads []PayloadItem,
	commands []CommandItem,
	topCreds []TopCredential,
) (string, error) {
	systemPrompt := `You are an elite Lead Incident Response Commander & Blue Team Cyber Threat Intelligence Analyst operating in a Security Operations Center (SOC).
Your task is to analyze real honeypot sensor telemetry, classify attacker campaigns according to the MITRE ATT&CK framework, assess potential blast radius, identify threat actor signatures, and generate actionable Blue Team containment and hardening recommendations.
Format your output with clear, professional GitHub-Flavored Markdown with tables, alerts, MITRE technique tags, and copyable bash/iptables hardening commands.`

	topIPsSummary := make([]string, 0)
	for i, ip := range stats.TopSourceIPs {
		if i >= 6 {
			break
		}
		topIPsSummary = append(topIPsSummary, fmt.Sprintf("- **%s** (%s, %s): %d hits", ip.IP, ip.City, ip.CountryCode, ip.Count))
	}

	breachSummary := make([]string, 0)
	for i, b := range breaches.Items {
		if i >= 8 {
			break
		}
		breachSummary = append(breachSummary, fmt.Sprintf("- IP %s (user: `%s` pass: `%s`, %ds duration, %d commands)", b.SourceIP, b.Username, b.Password, b.DurationSec, b.CommandCount))
	}

	cmdSummary := make([]string, 0)
	for i, c := range commands {
		if i >= 10 {
			break
		}
		cmdSummary = append(cmdSummary, fmt.Sprintf("- `[%s]` `%s` (by %s)", c.Timestamp.Format("15:04:05"), c.Command, c.SourceIP))
	}

	payloadSummary := make([]string, 0)
	for i, p := range payloads {
		if i >= 5 {
			break
		}
		payloadSummary = append(payloadSummary, fmt.Sprintf("- SHA256 `%s...` (%.1f MB, %s from %s)", p.SHA256[:min(16, len(p.SHA256))], float64(p.SizeBytes)/(1024*1024), p.FileType, p.SourceIP))
	}

	credSummary := make([]string, 0)
	for i, cr := range topCreds {
		if i >= 8 {
			break
		}
		credSummary = append(credSummary, fmt.Sprintf("- `%s:%s` (%d attempts)", cr.User, cr.Pass, cr.Count))
	}

	userPrompt := fmt.Sprintf(`### INGRESS HONEYPOT TELEMETRY DATA DUMP
- **Sensor Node**: %s (%s)
- **Total Ingress Attacks**: %d
- **Unique Attacking IPs**: %d
- **Confirmed Infiltrations (Breaches)**: %d
- **Quarantined Malware Binaries**: %d

#### Top Attacker IPs:
%s

#### Sample Breached Sessions:
%s

#### Top Sprayed Credentials:
%s

#### Quarantined Payload Binaries:
%s

#### Executed Shell Recon Commands:
%s

Please produce a comprehensive Blue Team Cyber Threat Intelligence Briefing covering:
1. **Executive Threat Landscape & Incident Overview**
2. **Observed Threat Actor Campaigns & MITRE ATT&CK Matrix Mapping** (Explicitly analyze the 30k+ spray from Santa Clara 143.198.98.252, the Indonesian botnet wave 160.187.174.22, and the 7.6MB/28.9MB dropped ELF botnet binaries)
3. **Attacker Reconnaissance & Shell Behavior Analysis** (Explain what the executed commands like 'uname -s -v -n -m', 'chmod +x sshd; nohup', and 'echo -e "\\x6F\\x6B"' were attempting to do)
4. **Actionable Blue Team Containment & Mitigation Playbook** (Include copyable iptables firewall rules, SSH configuration hardening, and fail2ban rules).`,
		stats.SensorLocation, stats.SensorHost, stats.TotalAttempts, stats.UniqueIPs, stats.BreachCount, len(payloads),
		strings.Join(topIPsSummary, "\n"),
		strings.Join(breachSummary, "\n"),
		strings.Join(credSummary, "\n"),
		strings.Join(payloadSummary, "\n"),
		strings.Join(cmdSummary, "\n"),
	)

	return ai.CallGroq(systemPrompt, userPrompt, 2048)
}

// TriageSingleEvent performs rapid AI analysis on a single log event or command.
func (ai *AIService) TriageSingleEvent(eventID, eventType, srcIP, user, pass, cmd, rawJSON string) (string, error) {
	systemPrompt := `You are an AI SOC Analyst triage assistant.
Given a single raw honeypot security event, provide a concise, sharp 3-part triage note:
1. Threat Identification & MITRE ATT&CK Technique
2. Attacker Intent & Severity Rating (CRITICAL / HIGH / MEDIUM / LOW)
3. Immediate Blue Team Action`

	userPrompt := fmt.Sprintf(`Analyze this security event:
- Event ID: %s
- Event Type: %s
- Attacker IP: %s
- Attempted User: %s
- Attempted Password: %s
- Executed Command: %s
- Raw JSON: %s`, eventID, eventType, srcIP, user, pass, cmd, rawJSON)

	return ai.CallGroq(systemPrompt, userPrompt, 512)
}

// ChatAssistant handles single-turn questions (fallback).
func (ai *AIService) ChatAssistant(userQuery string, contextData string) (string, error) {
	return ai.ChatAssistantMultiTurn(userQuery, nil, contextData)
}

// ChatAssistantMultiTurn handles multi-turn SOC blue team questions with conversation memory and forensic precision.
func (ai *AIService) ChatAssistantMultiTurn(userQuery string, history []GroqMessage, contextData string) (string, error) {
	systemPrompt := `You are HoneyTrace AI SOC Analyst & Lead Incident Response Commander.
You have direct, real-time access to the HoneyTrace honeypot sensor SQLite database, raw Cowrie event logs, quarantined malware binaries on disk, and static forensic disassemblies.

CRITICAL INSTRUCTIONS:
1. Maintain active conversation context across turns. If the user asks a follow-up question (such as "what kind of host-level information?", "say in short", "how do I block this?", or "explain more"), answer directly in the context of the ongoing attacker investigation discussed in previous messages!
2. When asked about a specific attacker IP (e.g., 195.178.110.217, 117.89.254.46, 143.198.98.252, etc.), specific payload SHA256, or command, synthesize the EXACT database records, file sizes, dropped payloads, and forensic IOCs provided in the context.
3. If asked for a short summary ("say in short" / "tldr"), provide a sharp, concise 2-4 bullet summary answering what was just asked, rather than repeating unrelated generic stats.
4. If asked what host-level information an attacker's reconnaissance script collects, detail the exact fields from their script (OS distribution, kernel version, CPU architecture/model/cores, GPU acceleration, uptime, login history, shell execution filters).
5. Structure your response cleanly using Markdown with technical precision and ready-to-run Blue Team mitigation commands.`

	systemMsg := fmt.Sprintf("%s\n\n### HONEYPOT TELEMETRY & FORENSIC DOSSIER\n%s", systemPrompt, contextData)

	messages := make([]GroqMessage, 0, len(history)+2)
	messages = append(messages, GroqMessage{Role: "system", Content: systemMsg})

	// Add past conversation turns (limiting to last 10 messages)
	startIdx := 0
	if len(history) > 10 {
		startIdx = len(history) - 10
	}
	for i := startIdx; i < len(history); i++ {
		msg := history[i]
		if msg.Role == "user" || msg.Role == "assistant" {
			messages = append(messages, msg)
		}
	}

	// Append current user message
	messages = append(messages, GroqMessage{Role: "user", Content: userQuery})

	return ai.CallGroqMessages(messages, 1536)
}
