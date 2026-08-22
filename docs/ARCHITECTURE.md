# HoneyTrace System Architecture

HoneyTrace is an end-to-end cyber threat intelligence platform that captures real attack traffic, correlates host and network telemetry, enriches the alerts, and turns the output into analyst-readable triage.

<sub>**Project inspired by [NetworkShard](https://networkshard.com)**</sub>

---

## System Architecture

```mermaid
flowchart TB
 subgraph WAN["Public Internet"]
        A["Adversaries / Botnets<br>(SSH Brute-force &amp; Scanners)"]
  end
 subgraph NETLIFY["Netlify Edge & DNS Layer"]
        DNS["Custom Subdomain<br>honeytrace.tapasvimadhak.works"]
        SPA["Vite + React Cyber HUD<br>(3D Threat Globe &amp; Intel Console)"]
        PROXY["Netlify Edge Proxy<br>(_redirects / netlify.toml)"]
  end
 subgraph INGRESS["Network Boundary &amp; Routing"]
        PUB_IP["Public IPv4 Interface<br>(13.234.121.199)"]
        IPTABLES["iptables NAT Rule<br>(Redirect :22 to :2222)"]
  end
 subgraph HONEYPOT_ENV["Deception & Telemetry Engine"]
        COWRIE["Cowrie Honeypot Daemon<br>(Port :2222)"]
        HONEYFS["Juicy HoneyFS &amp; Decoys<br>(Fake .env, AWS Keys, .bash_history)"]
        JSONLOG["Structured Audit Log<br>(cowrie.json)"]
        DOWNLOADS["Malware &amp; Payload Vault<br>(var/lib/cowrie/downloads)"]
  end
 subgraph BACKEND_STACK["HoneyTrace Analytics Core"]
        INGEST["honeytrace-ingest (Go Daemon)<br>(Tail Parser, GeoIP, GeoLite2 Enrichment)"]
        SQLITE[("SQLite Database<br>(WAL Mode Enabled)")]
        API["honeytrace-api (Go REST/SSE)<br>(CORS Middleware, Port :8080)"]
        WORDLIST["Dynamic Wordlist Generator<br>(Unique Passwords / Shell Commands)"]
  end
 subgraph SECURE_MGMT["Administrative Management Layer"]
        TS_DAEMON["Tailscale Daemon<br>(Tailscale SSH + MagicDNS ec2)"]
        REAL_SSHD["Host OpenSSH Daemon<br>(Restricted to tailscale0)"]
  end
 subgraph EC2["EC2 Instance (t3.micro / Amazon Linux)"]
        INGRESS
        HONEYPOT_ENV
        BACKEND_STACK
        SECURE_MGMT
  end
 subgraph AWS["AWS Cloud (ap-south-1 Mumbai)"]
        EC2
  end
 subgraph ADMIN_CLIENTS["Secure Tailnet Devices"]
        ADMIN["Admin Workstation / Termux<br>(Mac / Windows / Mobile)"]
        BROWSER["Web Browser User<br>(Public View)"]
  end
    DNS --> SPA
    SPA -- API Requests (/api/*) --> PROXY
    PUB_IP --> IPTABLES
    IPTABLES --> COWRIE
    COWRIE -. Emulates .-> HONEYFS
    COWRIE --> JSONLOG & DOWNLOADS
    JSONLOG --> INGEST
    INGEST --> SQLITE
    SQLITE <--> API
    SQLITE --> WORDLIST
    WORDLIST --> API
    TS_DAEMON --> REAL_SSHD
    A -- Public SSH Attack (:22) --> PUB_IP
    PROXY -- "HTTPS-to-HTTP Proxy Relay (:8080)" --> API
    BROWSER --> DNS
    ADMIN -- Encrypted Tailscale SSH --> TS_DAEMON

     A:::attacker
     DNS:::edge
     SPA:::edge
     PROXY:::edge
     COWRIE:::host
     HONEYFS:::host
     JSONLOG:::host
     DOWNLOADS:::host
     INGEST:::core
     SQLITE:::db
     API:::core
     WORDLIST:::core
     TS_DAEMON:::vpn
     REAL_SSHD:::vpn
     ADMIN:::client
     BROWSER:::client
    classDef attacker fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#b71c1c
    classDef edge fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px,color:#4a148c
    classDef host fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    classDef core fill:#e1f5fe,stroke:#0277bd,stroke-width:2px,color:#01579b
    classDef db fill:#fff3e0,stroke:#ef6c00,stroke-width:2px,color:#e65100
    classDef vpn fill:#f5f5f5,stroke:#424242,stroke-width:2px,color:#212121
    classDef client fill:#fce4ec,stroke:#ad1457,stroke-width:2px,color:#880e4f
```

---

## Core Pipeline Subsystems

### 1. Ingress & Deception Subsystem
- **Public Bait SSH Interface (Port 22)**: Public AWS IPv4 interface routes inbound port 22 traffic via iptables PREROUTING NAT redirection directly to the unprivileged Cowrie daemon on port 2222.
- **Deception Shell & Fake Filesystem**: Simulates a vulnerable Linux root environment with realistic honey tokens (`.bash_history`, fake AWS credentials, environment configs).
- **Artifact Quarantine Vault**: Intercepts and archives inbound attacker payload binaries directly to disk (`var/lib/cowrie/downloads/`).

### 2. Analytics & Ingest Engine (Go)
- **Multi-File Event Tailer**: Continuously monitors rotated Cowrie JSON logs with checkpoint tracking.
- **MaxMind GeoIP2 Resolution**: Enriches attacker IPv4 addresses with geographic country codes, city names, and latitude/longitude coordinates.
- **WAL-Mode SQLite Persistence**: High-throughput storage preserving over 41,400 raw attack records, session durations, and sprayed passwords.

### 3. API & AI SOC Intelligence Layer
- **Go REST Service (`:8080`)**: Exposes structured telemetry, 3D globe coordinates, quarantined binary hex inspection, and wordlist streams.
- **Groq LPU Acceleration**: Powers the AI Incident Response Commander with real-time RAG context retrieval and MITRE ATT&CK campaign mapping.

### 4. Edge Distribution & Administration
- **Netlify Edge Reverse Proxy**: Relays public HTTPS dashboard traffic to the AWS EC2 API endpoint (`:8080`), eliminating CORS and mixed-content issues.
- **Tailscale Encrypted Mesh**: Restricts administrative OpenSSH access exclusively to authorized Tailnet keys.
