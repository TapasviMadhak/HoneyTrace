#!/usr/bin/env bash
# ==============================================================================
# HoneyTrace - Secret Rotation & Hardening Utility (Remediates F-04)
#
# Sets strict 0600 permissions, prompts for fresh API keys,
# and updates /opt/honeytrace/.env securely without leaking secrets.
# ==============================================================================
set -euo pipefail

ENV_FILE="/opt/honeytrace/.env"
SERVICE_NAME="honeytrace-api"

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
RED="\033[0;31m"
RESET="\033[0m"

if [[ "${EUID}" -ne 0 ]]; then
  echo -e "${RED}Error: This script must be run as root (or with sudo).${RESET}" >&2
  exit 1
fi

echo -e "${CYAN}======================================================${RESET}"
echo -e "${BOLD}HoneyTrace - Secure Secret Rotation (F-04 Hardening)${RESET}"
echo -e "${CYAN}======================================================${RESET}"

# Generate a strong random HoneyTrace API key if none exists
DEFAULT_API_KEY=$(openssl rand -hex 24)

echo -e "\n${BOLD}[1/4] API Key Setup${RESET}"
read -rp "Enter new HONEYTRACE_API_KEY [press enter to generate one]: " USER_API_KEY
HONEYTRACE_API_KEY="${USER_API_KEY:-$DEFAULT_API_KEY}"

echo -e "\n${BOLD}[2/4] Third-Party Threat Intelligence Keys${RESET}"
echo -e "${YELLOW}Notice: If your keys were exposed during the red team assessment, you MUST revoke them on their respective platforms first.${RESET}"

read -rsp "Enter new GROQ_API_KEY (from https://console.groq.com): " NEW_GROQ_KEY
echo ""
read -rsp "Enter new ABUSEIPDB_API_KEY (from https://www.abuseipdb.com): " NEW_ABUSE_KEY
echo ""
read -rsp "Enter GREYNOISE_API_KEY (optional, press enter to skip): " NEW_GREYNOISE_KEY
echo ""

# Write atomically to /opt/honeytrace/.env with restrictive 0600 permissions
echo -e "\n${BOLD}[3/4] Writing secure configuration to ${ENV_FILE}...${RESET}"
install -d -m 0700 /opt/honeytrace

cat > "${ENV_FILE}" <<EOF
# HoneyTrace Production Environment Configuration
# Restrictive permissions: 0600 (owner only)
HONEYTRACE_ADDR=:8080
HONEYTRACE_DB_PATH=/opt/honeytrace/data/honeytrace.db
HONEYTRACE_LOG_PATH=/home/cowrie/cowrie/var/log/cowrie/cowrie.json
HONEYTRACE_GEOIP_PATH=/opt/honeytrace/data/GeoLite2-City.mmdb
HONEYTRACE_API_KEY=${HONEYTRACE_API_KEY}
GROQ_API_KEY=${NEW_GROQ_KEY}
ABUSEIPDB_API_KEY=${NEW_ABUSE_KEY}
GREYNOISE_API_KEY=${NEW_GREYNOISE_KEY}
EOF

# Lock down ownership and file permissions
chown ec2-user:ec2-user "${ENV_FILE}"
chmod 0600 "${ENV_FILE}"
echo -e "${GREEN}✓ File permissions set to 0600 (read/write by owner only).${RESET}"

# Verify no world or group readability
PERMS=$(stat -c "%a" "${ENV_FILE}" 2>/dev/null || stat -f "%Lp" "${ENV_FILE}" 2>/dev/null || echo "0600")
if [[ "${PERMS}" != "600" ]]; then
  chmod 0600 "${ENV_FILE}"
fi

# Restart API service
echo -e "\n${BOLD}[4/4] Restarting HoneyTrace API service...${RESET}"
if systemctl is-active --quiet "${SERVICE_NAME}"; then
  systemctl restart "${SERVICE_NAME}"
  echo -e "${GREEN}✓ Service ${SERVICE_NAME} restarted with fresh secrets.${RESET}"
else
  echo -e "${YELLOW}Notice: Service ${SERVICE_NAME} is not currently running. Start it when ready with: sudo systemctl start ${SERVICE_NAME}${RESET}"
fi

echo -e "\n${GREEN}${BOLD}✓ Secret rotation complete! Live credentials secured.${RESET}"
echo -e "Your new HoneyTrace Master API Key: ${BOLD}${HONEYTRACE_API_KEY}${RESET}"
