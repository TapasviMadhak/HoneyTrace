#!/usr/bin/env bash
# Run as root from an SSM Session Manager shell on the HoneyTrace instance.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this bootstrap script as root (for example: sudo ./bootstrap.sh)." >&2
  exit 1
fi

run_stage() {
  local name="$1"
  local script="$2"
  echo
  echo "========== ${name} =========="
  "${SCRIPT_DIR}/${script}"
}

run_stage "1/5 Installing Cowrie as the dedicated cowrie user" "install_cowrie.sh"
run_stage "2/5 Applying the host and Cowrie stealth persona" "stealth_persona.sh"
run_stage "3/5 Building Cowrie's emulated bait filesystem" "configure_bait_files.sh"
run_stage "4/5 Installing and starting the Cowrie systemd service" "install_systemd.sh"
run_stage "5/5 Disabling OpenSSH and installing the persistent port-22 redirect" "harden_ssh.sh"

echo
echo "========== HoneyTrace bootstrap complete =========="
systemctl status cowrie --no-pager
echo
echo "Cowrie listener on TCP 2222:"
ss -tlnp | grep -E '[:.]2222[[:space:]]' || {
  echo "Cowrie is not listening on TCP 2222." >&2
  exit 1
}
