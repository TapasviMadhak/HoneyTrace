#!/usr/bin/env bash
# ==============================================================================
# HoneyTrace - Admin Public IPv4 Exclusion & Firewall Bypass Tool
#
# Usage:
#   sudo ./exclude_admin_ip.sh [ADMIN_PUBLIC_IP]
#
# If no IP is passed, auto-detects caller public IP via ifconfig.me.
#
# Actions:
# 1. Adds an iptables NAT bypass rule so the admin's public IPv4 is NEVER
#    redirected to the Cowrie honeypot (Port 2222).
# 2. Configures HONEYTRACE_ADMIN_IP in /opt/honeytrace/.env.
# 3. Purges any historical events matching this IP from the SQLite database.
# 4. Restarts honeytrace-api service.
# ==============================================================================
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[0;33m"
RESET="\033[0m"

ADMIN_IP="${1:-$(curl -s --connect-timeout 5 ifconfig.me || echo "")}"

if [[ -z "${ADMIN_IP}" ]]; then
  echo -e "${YELLOW}Could not auto-detect public IP. Please specify: $0 <YOUR_PUBLIC_IP>${RESET}" >&2
  exit 1
fi

echo -e "${CYAN}======================================================${RESET}"
echo -e "${BOLD}HoneyTrace - Admin Public IPv4 Exclusion Tool${RESET}"
echo -e "${CYAN}======================================================${RESET}"
echo -e "Admin Public IPv4: ${BOLD}${ADMIN_IP}${RESET}"

# 1. Update iptables NAT bypass
if command -v iptables >/dev/null 2>&1; then
  echo -e "\n${BOLD}[1/3] Adding iptables NAT bypass for ${ADMIN_IP}...${RESET}"
  # Remove duplicate rule if exists
  iptables -t nat -D PREROUTING -s "${ADMIN_IP}" -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
  # Insert at top of PREROUTING chain (before the Cowrie redirect rule)
  iptables -t nat -I PREROUTING 1 -s "${ADMIN_IP}" -p tcp --dport 22 -j ACCEPT
  echo -e "${GREEN}iptables bypass rule inserted.${RESET}"
fi

# 2. Update .env file
ENV_FILE="/opt/honeytrace/.env"
if [[ -f "${ENV_FILE}" ]]; then
  echo -e "\n${BOLD}[2/3] Updating ${ENV_FILE}...${RESET}"
  if grep -q "HONEYTRACE_ADMIN_IP" "${ENV_FILE}"; then
    sed -i "s/^HONEYTRACE_ADMIN_IP=.*/HONEYTRACE_ADMIN_IP=${ADMIN_IP}/" "${ENV_FILE}"
  else
    echo "HONEYTRACE_ADMIN_IP=${ADMIN_IP}" >> "${ENV_FILE}"
  fi
  chmod 600 "${ENV_FILE}"
  echo -e "${GREEN}.env updated.${RESET}"
fi

# 3. Purge from database & restart API
echo -e "\n${BOLD}[3/3] Purging database entries & restarting services...${RESET}"
DB_PATH="/opt/honeytrace/data/honeytrace.db"
if [[ -f "${DB_PATH}" ]] && command -v sqlite3 >/dev/null 2>&1; then
  sqlite3 "${DB_PATH}" "DELETE FROM events WHERE source_ip = '${ADMIN_IP}';" || true
  sqlite3 "${DB_PATH}" "DELETE FROM commands WHERE source_ip = '${ADMIN_IP}';" || true
  sqlite3 "${DB_PATH}" "DELETE FROM payloads WHERE source_ip = '${ADMIN_IP}';" || true
  sqlite3 "${DB_PATH}" "DELETE FROM sessions WHERE source_ip = '${ADMIN_IP}';" || true
  echo -e "${GREEN}Historical database records for ${ADMIN_IP} purged.${RESET}"
fi

if systemctl is-active --quiet honeytrace-api; then
  systemctl restart honeytrace-api
  echo -e "${GREEN}honeytrace-api restarted.${RESET}"
fi

echo -e "\n${GREEN}${BOLD}✓ Admin IP ${ADMIN_IP} successfully excluded from Cowrie and HoneyTrace!${RESET}"
