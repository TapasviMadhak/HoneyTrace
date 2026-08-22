#!/usr/bin/env bash
# ==============================================================================
# HoneyTrace - Apply Tailscale OpenSSH & Update NAT Redirect
#
# Target System: Amazon Linux 2023
#
# 1. Binds OpenSSH exclusively to the private Tailscale interface (Port 22).
# 2. Validates sshd configuration syntax.
# 3. Unmasks, enables, and starts sshd.
# 4. Updates iptables PREROUTING NAT so that:
#    - Non-Tailscale traffic (! -i tailscale0) on port 22 redirects to Cowrie (port 2222).
#    - Tailscale traffic (tailscale0) reaches real OpenSSH on port 22.
# 5. Displays service and firewall status.
# ==============================================================================
set -euo pipefail

readonly TAILSCALE_IP="${1:-100.89.14.122}"
readonly SSHD_CONFIG_D="/etc/ssh/sshd_config.d"
readonly TAILSCALE_SSHD_CONF="${SSHD_CONFIG_D}/tailscale.conf"
readonly REDIRECT_HELPER="/usr/local/sbin/honeytrace-port-redirect"

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
echo -e "${BOLD}HoneyTrace - Apply Tailscale OpenSSH & NAT Update${RESET}"
echo -e "${CYAN}======================================================${RESET}"
echo -e "Tailscale IP: ${BOLD}${TAILSCALE_IP}${RESET}"

# Step 1: Write sshd configuration for Tailscale
echo -e "\n${BOLD}[1/5] Writing OpenSSH configuration to ${TAILSCALE_SSHD_CONF}...${RESET}"
install -d -m 0755 "${SSHD_CONFIG_D}"

cat > "${TAILSCALE_SSHD_CONF}" <<EOF
# HoneyTrace Tailscale OpenSSH Configuration
Port 22
ListenAddress ${TAILSCALE_IP}
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin prohibit-password
EOF

chmod 0644 "${TAILSCALE_SSHD_CONF}"
echo -e "${GREEN}Configuration file written.${RESET}"

# Step 2: Validate sshd configuration syntax
echo -e "\n${BOLD}[2/5] Validating sshd configuration syntax (sshd -t)...${RESET}"
if sshd -t; then
  echo -e "${GREEN}sshd configuration is valid.${RESET}"
else
  echo -e "${RED}Error: sshd configuration test failed. Please check ${TAILSCALE_SSHD_CONF}.${RESET}" >&2
  exit 1
fi

# Step 3: Unmask, enable, and start sshd service
echo -e "\n${BOLD}[3/5] Unmasking and starting sshd.service...${RESET}"
systemctl unmask sshd.service || true
systemctl daemon-reload
systemctl enable --now sshd.service
systemctl restart sshd.service

# Step 4: Update iptables PREROUTING NAT
echo -e "\n${BOLD}[4/5] Updating iptables PREROUTING NAT rules...${RESET}"
echo "Flushing existing PREROUTING nat table..."
iptables -t nat -F PREROUTING

echo "Adding rule: redirect non-Tailscale port 22 traffic to Cowrie (port 2222)..."
iptables -t nat -A PREROUTING ! -i tailscale0 -p tcp --dport 22 -j REDIRECT --to-ports 2222

# Update the persistent redirect helper if it exists
if [[ -f "${REDIRECT_HELPER}" ]]; then
  echo "Updating persistent redirect helper at ${REDIRECT_HELPER}..."
  install -m 0755 /dev/stdin "${REDIRECT_HELPER}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

readonly IPTABLES="/usr/sbin/iptables"
readonly RULE=(-t nat PREROUTING ! -i tailscale0 -p tcp --dport 22 -j REDIRECT --to-ports 2222)

case "${1:-start}" in
  start)
    "${IPTABLES}" -t nat -C PREROUTING ! -i tailscale0 -p tcp --dport 22 -j REDIRECT --to-ports 2222 2>/dev/null || \
      "${IPTABLES}" "${RULE[@]}"
    ;;
  stop)
    while "${IPTABLES}" -t nat -C PREROUTING ! -i tailscale0 -p tcp --dport 22 -j REDIRECT --to-ports 2222 2>/dev/null; do
      "${IPTABLES}" -t nat -D PREROUTING ! -i tailscale0 -p tcp --dport 22 -j REDIRECT --to-ports 2222
    done
    ;;
  *)
    echo "Usage: $0 {start|stop}" >&2
    exit 2
    ;;
esac
EOF
fi

# Step 5: Print status of sshd and iptables rules
echo -e "\n${BOLD}[5/5] Checking service and firewall status...${RESET}"
echo
echo -e "${CYAN}--- OpenSSH Service Status ---${RESET}"
systemctl status sshd --no-pager || true

echo
echo -e "${CYAN}--- Active NAT PREROUTING Rules ---${RESET}"
iptables -t nat -L PREROUTING -v -n --line-numbers

echo
echo -e "${CYAN}--- Active SSH / Cowrie Sockets ---${RESET}"
ss -tlnp | grep -E ':(22|2222)[[:space:]]' || true

echo
echo -e "${CYAN}======================================================${RESET}"
echo -e "${GREEN}${BOLD}Tailscale OpenSSH setup applied successfully!${RESET}"
echo -e "${CYAN}======================================================${RESET}"
echo -e "Real OpenSSH is now listening on: ${BOLD}${TAILSCALE_IP}:22${RESET}"
echo -e "Public TCP/22 remains redirected to Cowrie on TCP/2222."
echo
