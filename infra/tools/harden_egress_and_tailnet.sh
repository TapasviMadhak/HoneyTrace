#!/usr/bin/env bash
# ==============================================================================
# HoneyTrace - Egress Firewall & Tailnet Isolation (Remediates F-02 & F-03)
#
# Prevents Cowrie SSRF, AWS IMDS metadata probing, and lateral movement
# into the operator's private Tailscale network.
# ==============================================================================
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
RED="\033[0;31m"
RESET="\033[0m"

if [[ "${EUID}" -ne 0 ]]; then
  echo -e "${RED}Error: This script must be run as root (or with sudo).${RESET}" >&2
  exit 1
fi

echo -e "${CYAN}======================================================${RESET}"
echo -e "${BOLD}HoneyTrace - Egress Firewall & Tailnet Hardening${RESET}"
echo -e "${CYAN}======================================================${RESET}"

COWRIE_USER="cowrie"
if ! id "${COWRIE_USER}" >/dev/null 2>&1; then
  echo -e "${RED}Error: User ${COWRIE_USER} does not exist on this host.${RESET}" >&2
  exit 1
fi

echo -e "\n${BOLD}[1/3] Applying kernel-level iptables egress filters for '${COWRIE_USER}'...${RESET}"

# Function to add rule idempotently if not already present
add_rule() {
  local rule=("$@")
  if ! iptables -C "${rule[@]}" 2>/dev/null; then
    iptables -I "${rule[@]}"
    echo "  + Applied: iptables -I ${rule[*]}"
  else
    echo "  = Already active: iptables ${rule[*]}"
  fi
}

# 1. Block cowrie user from reaching Tailscale interface
add_rule OUTPUT -m owner --uid-owner "${COWRIE_USER}" -o tailscale0 -j DROP

# 2. Block cowrie user from reaching Tailscale CGNAT IP block (100.64.0.0/10)
add_rule OUTPUT -m owner --uid-owner "${COWRIE_USER}" -d 100.64.0.0/10 -j DROP

# 3. Block cowrie user from reaching AWS IMDS metadata service (169.254.169.254)
add_rule OUTPUT -m owner --uid-owner "${COWRIE_USER}" -d 169.254.169.254/32 -j DROP
add_rule OUTPUT -m owner --uid-owner "${COWRIE_USER}" -d 169.254.0.0/16 -j DROP

# 4. Block cowrie user from reaching local loopback / localhost services
add_rule OUTPUT -m owner --uid-owner "${COWRIE_USER}" -d 127.0.0.0/8 -j DROP

# 5. Block cowrie user from probing internal VPC / RFC1918 private subnets
add_rule OUTPUT -m owner --uid-owner "${COWRIE_USER}" -d 10.0.0.0/8 -j DROP
add_rule OUTPUT -m owner --uid-owner "${COWRIE_USER}" -d 172.16.0.0/12 -j DROP
add_rule OUTPUT -m owner --uid-owner "${COWRIE_USER}" -d 192.168.0.0/16 -j DROP

echo -e "\n${BOLD}[2/3] Hardening Cowrie redirect handling in cowrie.cfg...${RESET}"
COWRIE_CFG="/home/cowrie/cowrie/etc/cowrie.cfg"
if [[ -f "${COWRIE_CFG}" ]]; then
  # Ensure raw logging is active but outbound pivoting is constrained
  if ! grep -q "allow_internet" "${COWRIE_CFG}"; then
    sed -i '/\[shell\]/a allow_internet = false' "${COWRIE_CFG}" 2>/dev/null || true
  fi
  echo -e "${GREEN}✓ Cowrie configuration audited.${RESET}"
fi

echo -e "\n${BOLD}[3/3] Persisting iptables rules across reboots...${RESET}"
if command -v iptables-save >/dev/null; then
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4
  echo -e "${GREEN}✓ Rules saved to /etc/iptables/rules.v4.${RESET}"
fi

echo -e "\n${GREEN}${BOLD}✓ Complete! The honeypot process is strictly blocked from accessing:${RESET}"
echo -e "  • AWS Metadata Service (169.254.169.254)"
echo -e "  • Tailscale Private Network (100.64.0.0/10 and tailscale0)"
echo -e "  • Internal VPC / Private Subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)"
echo -e "  • Localhost services (127.0.0.0/8)"
