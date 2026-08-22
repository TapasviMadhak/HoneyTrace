# HoneyTrace System Architecture

HoneyTrace is an end-to-end cyber threat intelligence platform that captures real attack traffic, correlates host and network telemetry, enriches alerts with dual threat intelligence feeds (**AbuseIPDB** & **GreyNoise**), and turns the output into analyst-readable triage.

<sub>**Project inspired by [NetworkShard](https://networkshard.com)**</sub>

---

## System Architecture

```mermaid
flowchart TB
 subgraph WAN["Public Internet"]
        A["Adversaries / Botnets<br>(SSH Brute-force &amp; Scanners)"]
  end
 subgraph VERCEL_EDGE["Vercel Global Edge Network"]
        DNS["Custom Domain (HTTPS)<br>honeytrace.tapasvimadhak.works"]
        SPA["React 18 + Vite Cyber HUD<br>(3D Threat Globe &amp; Threat Radar)"]
        PROXY["Vercel Serverless Rewrites<br>(vercel.json /api/* proxy)"]
  end
 subgraph THREAT_INTEL["External Threat Intelligence APIs"]
        ABUSE["AbuseIPDB API v2<br>(IP Threat Score &amp; Auto-Report)"]
        GREYNOISE["GreyNoise Community API v3<br>(Internet Noise &amp; RIOT Engine)"]
  end
 subgraph INGRESS["Network Boundary &amp; Isolation"]
        PUB_IP["Public IPv4 Interface<br>(13.234.121.199)"]
        IPTABLES["iptables NAT Rule<br>(Redirect :22 to :2222)"]
        FILTER["Ingress IP Filter<br>(Excludes Mac/Admin/VPN/Dashboard)"]
  end
 subgraph HONEYPOT_ENV["Deception &amp; Telemetry Engine"]
        COWRIE["Cowrie Honeypot Daemon<br>(Port :2222)"]
        HONEYFS["Juicy HoneyFS &amp; Decoys<br>(Fake .env, AWS Keys, .bash_history)"]
        JSONLOG["Structured Audit Log<br>(cowrie.json)"]
        DOWNLOADS["Malware &amp; Payload Vault<br>(var/lib/cowrie/downloads)"]
  end
 subgraph BACKEND_STACK["HoneyTrace Analytics Core"]
        INGEST["honeytrace-ingest (Go Daemon)<br>(Tail Parser, GeoIP, GeoLite2 Enrichment)"]
        SQLITE[("SQLite Database<br>(WAL Mode Enabled)")]
        API["honeytrace-api (Go REST/SSE)<br>(Port :8080)"]
        RADAR["Threat Reputation Radar Core<br>(Dual AbuseIPDB + GreyNoise Cache)"]
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
 subgraph ADMIN_CLIENTS["Secure Client Devices"]
        ADMIN["Admin Workstation / Termux<br>(Mac / Windows / Mobile)"]
        BROWSER["Web Browser Analyst<br>(Public View)"]
  end
    DNS --> SPA
    SPA -- API Requests (/api/*) --> PROXY
    PUB_IP --> IPTABLES
    IPTABLES --> COWRIE
    COWRIE -. Emulates .-> HONEYFS
    COWRIE --> JSONLOG & DOWNLOADS
    JSONLOG --> FILTER
    FILTER --> INGEST
    INGEST --> SQLITE
    SQLITE <--> API
    API <--> RADAR
    RADAR <--> ABUSE & GREYNOISE
    SQLITE --> WORDLIST
    WORDLIST --> API
    TS_DAEMON --> REAL_SSHD
    A -- Public SSH Attack (:22) --> PUB_IP
    PROXY -- "HTTPS-to-HTTP Edge Proxy (:8080)" --> API
    BROWSER --> DNS
    ADMIN -- Encrypted Tailscale SSH --> TS_DAEMON

     A:::attacker
     DNS:::edge
     SPA:::edge
     PROXY:::edge
     ABUSE:::intel
     GREYNOISE:::intel
     COWRIE:::host
     HONEYFS:::host
     JSONLOG:::host
     DOWNLOADS:::host
     FILTER:::core
     INGEST:::core
     SQLITE:::db
     API:::core
     RADAR:::core
     WORDLIST:::core
     TS_DAEMON:::vpn
     REAL_SSHD:::vpn
     ADMIN:::client
     BROWSER:::client
    classDef attacker fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#b71c1c
    classDef edge fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px,color:#4a148c
    classDef intel fill:#e8eaf6,stroke:#283593,stroke-width:2px,color:#1a237e
    classDef host fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    classDef core fill:#e1f5fe,stroke:#0277bd,stroke-width:2px,color:#01579b
    classDef db fill:#fff3e0,stroke:#ef6c00,stroke-width:2px,color:#e65100
    classDef vpn fill:#f5f5f5,stroke:#424242,stroke-width:2px,color:#212121
    classDef client fill:#fce4ec,stroke:#ad1457,stroke-width:2px,color:#880e4f
```

---

## Core Pipeline Subsystems

### 1. Ingress & Deception Subsystem
- **Public Port 22**: Redirected via Linux `iptables` NAT PREROUTING to Cowrie (`:2222`).
- **Ingress Isolation Filter**: Excludes loopback (`127.0.0.1`), private networks (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`), Carrier-Grade NAT / Tailscale (`100.64.0.0/10`), and admin workstations so dashboard views are never counted as attacks.
- **HoneyFS Decoys**: HoneyFS emulates realistic Ubuntu filesystem trees with honeypot credentials (`.env`, `id_rsa`, AWS secret keys).

### 2. Analytics & Threat Intelligence Radar
- **MaxMind GeoIP2**: In-memory binary MMDB lookup for physical latitude, longitude, ISO country code, and city.
- **AbuseIPDB Threat Engine**: Automated confidence reputation scores (0–100%) and automated attacker reporting on breach events.
- **GreyNoise Noise Engine**: Classifies internet background noise (`noise: true`) vs targeted custom exploits, and verifies benign services with RIOT.
- **Dynamic Attacker Wordlist**: Aggregates attacker brute-force credentials and shell commands into live downloadable `.txt` files.

### 3. Frontend & Global Edge Delivery
- **Vercel Edge Network**: Hosted at `https://honeytrace.tapasvimadhak.works` with zero-config HTTPS and global low-latency CDN.
- **API Edge Proxy (`vercel.json`)**: Serverless rewrites relay `/api/*` requests over HTTPS directly to the AWS EC2 Go backend (`:8080`).
- **Live Threat Radar (`/radar`)**: Interactive deep lookup, 1-click smooth inspect, and dedicated filter tabs (Top 10 Attackers, Critical Threats $\ge 75\%$, Live Feed 10 Unique non-repeating IPs).
