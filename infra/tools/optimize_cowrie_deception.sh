#!/usr/bin/env bash
# ==============================================================================
# HoneyTrace - Cowrie Deception & Payload Capture Optimizer
#
# Purpose:
# 1. Configures AuthRandom so brute-force botnets are accepted on the 2nd-4th attempt,
#    triggering their Stage-2 payload drops, wget/curl scripts, and terminal commands.
# 2. Enables SFTP/SCP uploads and Direct-TCP/IP tunnel capture.
# 3. Ensures TTY keystroke recording is always active.
# 4. Sets 100MB download quarantine limits.
# 5. Restarts cowrie service cleanly.
# ==============================================================================
set -euo pipefail

COWRIE_HOME="/home/cowrie/cowrie"
COWRIE_CFG="${COWRIE_HOME}/etc/cowrie.cfg"
USERDB="${COWRIE_HOME}/etc/userdb.txt"

BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
RESET="\033[0m"

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must run as root." >&2
  exit 1
fi

echo -e "${CYAN}======================================================${RESET}"
echo -e "${BOLD}HoneyTrace - Cowrie Deception Optimizer${RESET}"
echo -e "${CYAN}======================================================${RESET}"

# 1. Update userdb.txt with wildcard matches
echo -e "\n${BOLD}[1/3] Updating userdb with wildcard botnet lures...${RESET}"
cat > "${USERDB}" <<'EOF'
# Wildcard and common botnet lure credentials
root:*
admin:*
ubuntu:*
user:*
test:*
guest:*
support:*
oracle:*
postgres:*
EOF
chown cowrie:cowrie "${USERDB}"
chmod 0640 "${USERDB}"
echo -e "${GREEN}userdb.txt updated.${RESET}"

# 2. Write optimized cowrie.cfg
echo -e "\n${BOLD}[2/3] Writing optimized deception configuration to ${COWRIE_CFG}...${RESET}"
cat > "${COWRIE_CFG}" <<'EOF'
[honeypot]
hostname = prod-app-server-01
log_raw_input = true
log_raw_output = true
download_limit_size = 104857600
download_total_size = 1048576000
auth_class = AuthRandom
auth_random_low = 2
auth_random_high = 4

[ssh]
listen_endpoints = tcp:2222:interface=0.0.0.0
sftp_enabled = true
forwarding = true
version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10

[shell]
filesystem = var/lib/cowrie/fs.pickle
arch = linux-x86_64
kernel_version = 5.15.0-105-generic
kernel_build = #115-Ubuntu SMP

[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json
EOF
chown cowrie:cowrie "${COWRIE_CFG}"
chmod 0640 "${COWRIE_CFG}"
echo -e "${GREEN}cowrie.cfg updated.${RESET}"

# 3. Restart Cowrie service
echo -e "\n${BOLD}[3/3] Restarting Cowrie daemon...${RESET}"
if systemctl is-active --quiet cowrie; then
  systemctl restart cowrie
  echo -e "${GREEN}Cowrie restarted with active deception engine.${RESET}"
else
  echo -e "${GREEN}Cowrie configuration ready.${RESET}"
fi

echo -e "\n${GREEN}${BOLD}✓ Deception optimizer applied! Botnets will now be granted shells to drop payloads.${RESET}"
