#!/usr/bin/env bash
# ==============================================================================
# HoneyTrace - Tailscale Setup & Private SSH Configuration
#
# Target System: Amazon Linux 2023
#
# Configures the Tailscale package repository, installs Tailscale, enables and
# starts the tailscaled service, and installs the OpenSSH configuration template
# for private management access.
#
# Note: This script intentionally DOES NOT run `tailscale up` because interactive
# authentication must be completed by the administrator.
# ==============================================================================
set -euo pipefail

readonly TAILSCALE_REPO_URL="https://pkgs.tailscale.com/stable/amazon-linux/2023/tailscale.repo"
readonly SSHD_CONFIG_D="/etc/ssh/sshd_config.d"
readonly TAILSCALE_SSHD_CONF="${SSHD_CONFIG_D}/tailscale.conf"

# Text formatting helpers
BOLD="\033[1m"
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
RESET="\033[0m"

if [[ "${EUID}" -ne 0 ]]; then
  echo -e "${RED}Error: This script must be run as root (e.g. sudo $0).${RESET}" >&2
  exit 1
fi

echo -e "${CYAN}======================================================${RESET}"
echo -e "${BOLD}HoneyTrace - Tailscale Installation & Setup${RESET}"
echo -e "${CYAN}======================================================${RESET}"

# Step 1: Add Tailscale yum repository for Amazon Linux 2023
echo -e "\n${BOLD}[1/4] Adding Tailscale repository for Amazon Linux 2023...${RESET}"
if command -v dnf-3 >/dev/null 2>&1 && dnf config-manager --help >/dev/null 2>&1; then
  dnf config-manager --add-repo "${TAILSCALE_REPO_URL}"
else
  # Direct repo file installation fallback
  echo "Downloading Tailscale repository definition..."
  curl -fsSL "${TAILSCALE_REPO_URL}" -o /etc/yum.repos.d/tailscale.repo
fi

# Step 2: Install Tailscale package
echo -e "\n${BOLD}[2/4] Installing Tailscale package via dnf...${RESET}"
dnf install -y tailscale

# Step 3: Enable and start tailscaled daemon
echo -e "\n${BOLD}[3/4] Enabling and starting tailscaled systemd service...${RESET}"
systemctl daemon-reload
systemctl enable tailscaled.service
systemctl restart tailscaled.service

if systemctl is-active --quiet tailscaled.service; then
  echo -e "${GREEN}tailscaled.service is active and running.${RESET}"
else
  echo -e "${RED}Error: tailscaled.service failed to start.${RESET}" >&2
  systemctl status tailscaled.service --no-pager
  exit 1
fi

# Step 4: Generate template sshd_config.d/tailscale.conf
echo -e "\n${BOLD}[4/4] Creating OpenSSH private interface config template...${RESET}"
install -d -m 0755 "${SSHD_CONFIG_D}"

cat > "${TAILSCALE_SSHD_CONF}" <<'EOF'
# ==============================================================================
# HoneyTrace - Tailscale Private OpenSSH Management Listener
#
# IMPORTANT:
# 1. Authenticate with Tailscale:
#      sudo tailscale up
# 2. Get your assigned 100.x.y.z IP:
#      tailscale ip -4
# 3. Replace <TAILSCALE_IP> below with your Tailscale IP, or run:
#      sudo sed -i "s/<TAILSCALE_IP>/$(tailscale ip -4)/g" /etc/ssh/sshd_config.d/tailscale.conf
# 4. Unmask and start real OpenSSH when ready:
#      sudo systemctl unmask sshd
#      sudo systemctl enable --now sshd
# ==============================================================================
Port 22
ListenAddress <TAILSCALE_IP>
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
ChallengeResponseAuthentication no
X11Forwarding no
EOF

chmod 0644 "${TAILSCALE_SSHD_CONF}"
echo -e "Template generated at: ${CYAN}${TAILSCALE_SSHD_CONF}${RESET}"

echo
echo -e "${CYAN}======================================================${RESET}"
echo -e "${GREEN}${BOLD}Tailscale setup complete!${RESET}"
echo -e "${CYAN}======================================================${RESET}"
echo -e "Follow these steps to complete private administration setup:"
echo
echo -e "  1. ${BOLD}Authenticate Tailscale on this instance:${RESET}"
echo -e "     ${CYAN}sudo tailscale up${RESET}"
echo
echo -e "  2. ${BOLD}Populate your assigned Tailscale IP into the sshd configuration:${RESET}"
echo -e "     ${CYAN}sudo sed -i \"s/<TAILSCALE_IP>/\$(tailscale ip -4)/g\" ${TAILSCALE_SSHD_CONF}${RESET}"
echo
echo -e "  3. ${BOLD}Verify the configuration:${RESET}"
echo -e "     ${CYAN}cat ${TAILSCALE_SSHD_CONF}${RESET}"
echo
echo -e "  4. ${BOLD}Unmask and activate OpenSSH solely on the Tailscale IP:${RESET}"
echo -e "     ${CYAN}sudo systemctl unmask sshd${RESET}"
echo -e "     ${CYAN}sudo systemctl enable --now sshd${RESET}"
echo -e "     ${CYAN}sudo systemctl status sshd --no-pager${RESET}"
echo
