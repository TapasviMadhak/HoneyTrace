# Security Policy

## Supported Versions

HoneyTrace is an active security research and cyber threat intelligence platform. The following versions are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| `0.1.x` | :white_check_mark: |
| `< 0.1` | :x:                |

---

## Reporting a Vulnerability

The security and integrity of HoneyTrace is a top priority. If you discover a security vulnerability, flaw, or credential leakage within HoneyTrace or its supporting infrastructure:

1. **Do NOT open a public GitHub issue** to report security vulnerabilities.
2. Please send a detailed report directly via email to:
   - **Contact**: `tapasvimadhak8711@gmail.com`
3. Include in your report:
   - Description of the vulnerability and its potential impact.
   - Exact steps or proof-of-concept (PoC) to reproduce the issue.
   - Affected components (`api`, `ingest`, `dashboard`, `infra`).

### Disclosure Process & Response Timeline
- **Initial Response**: Within 24 hours acknowledging receipt of your advisory.
- **Triage & Validation**: Within 48 hours to confirm the issue and develop a patch.
- **Fix & Advisory Release**: Coordinated public release and acknowledgment once remediated.

---

## Honeypot Deployment Best Practices
When deploying HoneyTrace or Cowrie in production:
- **Never** expose real SSH administrative ports to the public WAN.
- Always isolate host administrative access using an encrypted VPN or private mesh such as **Tailscale**.
- Ensure database files (`*.db`) and environment files (`.env`) have restricted permissions (`chmod 600`) and are strictly excluded from version control.
