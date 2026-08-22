#!/usr/bin/env bash
# SSM is the administrative channel. This disables real SSH and redirects public TCP/22 to Cowrie on 2222.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must run as root." >&2
  exit 1
fi

echo "Installing iptables support..."
dnf install -y iptables-services

echo "Disabling and masking the real OpenSSH daemon..."
if systemctl list-unit-files --no-legend 'sshd.service' | grep -q '^sshd\.service'; then
  if systemctl is-enabled sshd.service 2>/dev/null | grep -qx 'masked'; then
    echo "sshd.service is already masked."
  else
    systemctl disable --now sshd.service
    systemctl mask sshd.service
  fi
  if systemctl is-active --quiet sshd.service; then
    echo "sshd is still active after disable/mask; refusing to install the redirect." >&2
    exit 1
  fi
else
  echo "sshd.service is not installed."
fi
if systemctl list-unit-files --no-legend 'sshd.socket' | grep -q '^sshd\.socket'; then
  if systemctl is-enabled sshd.socket 2>/dev/null | grep -qx 'masked'; then
    echo "sshd.socket is already masked."
  else
    systemctl disable --now sshd.socket
    systemctl mask sshd.socket
  fi
fi

install -m 0755 /dev/stdin /usr/local/sbin/honeytrace-port-redirect <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

readonly IPTABLES="/usr/sbin/iptables"
readonly RULE=(-t nat PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222)

case "${1:-start}" in
  start)
    "${IPTABLES}" -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222 2>/dev/null || \
      "${IPTABLES}" "${RULE[@]}"
    ;;
  stop)
    while "${IPTABLES}" -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222 2>/dev/null; do
      "${IPTABLES}" -t nat -D PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222
    done
    ;;
  *)
    echo "Usage: $0 {start|stop}" >&2
    exit 2
    ;;
esac
EOF

cat > /etc/systemd/system/honeytrace-port-redirect.service <<'EOF'
[Unit]
Description=HoneyTrace redirect TCP 22 to Cowrie TCP 2222
Wants=network-online.target
After=network-online.target cowrie.service
Requires=cowrie.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/honeytrace-port-redirect start
ExecStop=/usr/local/sbin/honeytrace-port-redirect stop
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable honeytrace-port-redirect.service
systemctl restart honeytrace-port-redirect.service
echo "TCP/22 redirect is active and persistent via honeytrace-port-redirect.service."
