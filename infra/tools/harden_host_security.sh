#!/usr/bin/env bash
# ==============================================================================
# HoneyTrace - Host Misconfiguration Hardening Utility (Remediates F-08)
#
# 1. Scopes iptables NAT redirect strictly to public interface (excludes tailscale0).
# 2. Removes ec2-user from unnecessary privileged groups (adm, cowrie).
# 3. Deploys and activates backup script (/opt/honeytrace/backup.sh).
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
echo -e "${BOLD}HoneyTrace - Host Misconfiguration Hardening (F-08)${RESET}"
echo -e "${CYAN}======================================================${RESET}"

# 1. Scope iptables NAT redirect strictly to public interfaces (preventing tailscale0 interception)
echo -e "\n${BOLD}[1/3] Scoping iptables NAT redirect rule...${RESET}"
# Remove any overly broad redirect on all interfaces
iptables -t nat -D PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222 2>/dev/null || true

# Add interface-constrained rule: only redirect traffic NOT arriving via tailscale0
if ! iptables -t nat -C PREROUTING ! -i tailscale0 -p tcp --dport 22 -j REDIRECT --to-ports 2222 2>/dev/null; then
  iptables -t nat -I PREROUTING ! -i tailscale0 -p tcp --dport 22 -j REDIRECT --to-ports 2222
  echo -e "${GREEN}✓ Applied NAT rule: Only non-tailscale interfaces redirected to Cowrie (:2222).${RESET}"
else
  echo -e "${GREEN}✓ Interface-scoped NAT rule is already active.${RESET}"
fi

# 2. Audit and reduce ec2-user group memberships
echo -e "\n${BOLD}[2/3] Hardening ec2-user group memberships...${RESET}"
if id "ec2-user" >/dev/null 2>&1; then
  for grp in adm cowrie; do
    if id -nG "ec2-user" | grep -qw "$grp"; then
      gpasswd -d ec2-user "$grp" 2>/dev/null || true
      echo -e "${GREEN}✓ Removed ec2-user from group '$grp'.${RESET}"
    else
      echo "  ec2-user is not in group '$grp'."
    fi
  done
fi

# 3. Deploy backup script and verify systemd timer
echo -e "\n${BOLD}[3/3] Setting up automated backup script...${RESET}"
SCRIPT_SRC="$(dirname "$0")/backup.sh"
if [[ -f "${SCRIPT_SRC}" ]]; then
  install -m 0700 "${SCRIPT_SRC}" /opt/honeytrace/backup.sh
  echo -e "${GREEN}✓ Installed /opt/honeytrace/backup.sh.${RESET}"
elif [[ -f "/opt/honeytrace/infra/tools/backup.sh" ]]; then
  install -m 0700 /opt/honeytrace/infra/tools/backup.sh /opt/honeytrace/backup.sh
  echo -e "${GREEN}✓ Installed /opt/honeytrace/backup.sh.${RESET}"
fi

# Ensure backup directory exists
install -d -m 0700 /var/backups/honeytrace

# If systemd timer exists, reload and enable
if systemctl list-unit-files | grep -q "honeytrace-backup.timer"; then
  systemctl daemon-reload
  systemctl enable --now honeytrace-backup.timer 2>/dev/null || true
  echo -e "${GREEN}✓ honeytrace-backup.timer activated.${RESET}"
fi

# Save iptables rules
if command -v iptables-save >/dev/null; then
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4
fi

echo -e "\n${GREEN}${BOLD}✓ Host configuration hardened successfully!${RESET}"
