#!/usr/bin/env bash
# cowrie.service is intentionally the only component that starts or stops Cowrie.
set -euo pipefail

readonly COWRIE_HOME="/home/cowrie/cowrie"
readonly COWRIE_PYTHON="${COWRIE_HOME}/cowrie-env/bin/python"
readonly COWRIE_SCRIPT="${COWRIE_HOME}/src/cowrie/scripts/cowrie.py"

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must run as root." >&2
  exit 1
fi
if [[ ! -x "${COWRIE_PYTHON}" || ! -f "${COWRIE_SCRIPT}" ]]; then
  echo "Cowrie is not installed; run install_cowrie.sh first." >&2
  exit 1
fi

cat > /etc/systemd/system/cowrie.service <<EOF
[Unit]
Description=Cowrie SSH honeypot
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=cowrie
Group=cowrie
WorkingDirectory=${COWRIE_HOME}
Environment=PYTHONPATH=${COWRIE_HOME}/src
ExecStart=${COWRIE_PYTHON} ${COWRIE_SCRIPT} start -n
Restart=on-failure
RestartSec=5
KillMode=control-group
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cowrie.service
systemctl restart cowrie.service
echo "cowrie.service is enabled and is the sole Cowrie process manager."
