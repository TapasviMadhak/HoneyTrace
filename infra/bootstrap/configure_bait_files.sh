#!/usr/bin/env bash
# Decoys are staged, embedded in Cowrie's emulated filesystem metadata, then removed from the host.
set -euo pipefail

readonly COWRIE_USER="cowrie"
readonly COWRIE_HOME="/home/${COWRIE_USER}/cowrie"
readonly VENV="${COWRIE_HOME}/cowrie-env"
readonly COWRIE_CONFIG="${COWRIE_HOME}/etc/cowrie.cfg"
readonly FSCTL_MODULE="${COWRIE_HOME}/src/cowrie/scripts/fsctl.py"
readonly FS_PICKLE="${COWRIE_HOME}/var/lib/cowrie/fs.pickle"
readonly FS_SOURCE="${COWRIE_HOME}/var/lib/cowrie/fs-source"

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must run as root." >&2
  exit 1
fi
if [[ ! -d "${COWRIE_HOME}/.git" || ! -x "${VENV}/bin/python" || ! -f "${COWRIE_CONFIG}" ]]; then
  echo "Cowrie is not installed; run install_cowrie.sh first." >&2
  exit 1
fi
if [[ ! -f "${FSCTL_MODULE}" ]]; then
  echo "Cowrie fsctl module is missing: ${FSCTL_MODULE}" >&2
  exit 1
fi

echo "Writing decoy files into Cowrie's temporary filesystem source..."
install -d -o "${COWRIE_USER}" -g "${COWRIE_USER}" -m 0750 \
  "${FS_SOURCE}/home/deploy/.ssh" \
  "${FS_SOURCE}/etc/nginx/sites-available"

cat > "${FS_SOURCE}/home/deploy/.env" <<'EOF'
APP_ENV=production
AWS_REGION=ap-south-1
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgresql://appsvc:ChangeMeBeforeLaunch@db-prod-01.internal:5432/orders
REDIS_URL=redis://:cache-prod-placeholder@redis-prod-01.internal:6379/0
EOF

cat > "${FS_SOURCE}/home/deploy/.ssh/id_rsa" <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA0a8xQ4JQmG7J4m6sQ9Y0G0f8hXxYzN7n7cJ5W9JxXgP5HONEYTRACE
DECOYKEYONLYNOTVALIDFORAUTHENTICATION000000000000000000000000000000000=
-----END OPENSSH PRIVATE KEY-----
EOF

cat > "${FS_SOURCE}/etc/nginx/sites-available/app.conf" <<'EOF'
server {
    listen 80;
    server_name app.internal.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

chmod 0600 "${FS_SOURCE}/home/deploy/.env" "${FS_SOURCE}/home/deploy/.ssh/id_rsa"
chown -R "${COWRIE_USER}:${COWRIE_USER}" "${FS_SOURCE}"

if [[ ! -f "${FS_PICKLE}" ]]; then
  echo "Creating a private, editable copy of Cowrie's fake filesystem metadata..."
  runuser -u "${COWRIE_USER}" -- sh -c 'cd "$1" && "$2" -c "$3"' sh \
    "${COWRIE_HOME}" "${VENV}/bin/python" \
    "from cowrie.core.resources import read_data_bytes; open('var/lib/cowrie/fs.pickle', 'wb').write(read_data_bytes('fs.pickle'))"
fi

fsctl() {
  local command="$1"
  runuser -u "${COWRIE_USER}" -- sh -c 'cd "$1" && PYTHONPATH="$1/src" "$2" -m cowrie.scripts.fsctl "$3" "$4"' sh \
    "${COWRIE_HOME}" "${VENV}/bin/python" "${FS_PICKLE}" "${command}"
}

echo "Embedding the bait paths in Cowrie's emulated filesystem..."
fsctl "mkdir /home/deploy"
fsctl "mkdir /home/deploy/.ssh"
fsctl "mkdir /etc/nginx/sites-available"
fsctl "touch /home/deploy/.env"
fsctl "touch /home/deploy/.ssh/id_rsa"
fsctl "touch /etc/nginx/sites-available/app.conf"
fsctl "embed ${FS_SOURCE}"

rm -rf -- "${FS_SOURCE}"
echo "Bait files are embedded in Cowrie's fake filesystem; the temporary host source was removed."
