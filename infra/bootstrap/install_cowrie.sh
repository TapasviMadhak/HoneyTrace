#!/usr/bin/env bash
# Installs Cowrie from its official source repository, but deliberately does not start it.
set -euo pipefail

readonly COWRIE_USER="cowrie"
readonly COWRIE_HOME="/home/${COWRIE_USER}/cowrie"
readonly VENV="${COWRIE_HOME}/cowrie-env"
readonly COWRIE_REPOSITORY="https://github.com/cowrie/cowrie.git"
readonly DATA_ETC="${COWRIE_HOME}/src/cowrie/data/etc"

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must run as root." >&2
  exit 1
fi

echo "Installing Amazon Linux 2023 packages required by Cowrie..."
dnf install -y python3.11 python3.11-pip python3.11-devel gcc make \
  openssl-devel libffi-devel git

if ! getent passwd "${COWRIE_USER}" >/dev/null; then
  echo "Creating the non-root ${COWRIE_USER} system user..."
  useradd --system --create-home --home-dir "/home/${COWRIE_USER}" --shell /sbin/nologin "${COWRIE_USER}"
fi

# A failed prior version created only a virtualenv inside the intended clone path.
if [[ ! -d "${COWRIE_HOME}/.git" && -d "${COWRIE_HOME}/cowrie-env" && ! -e "${COWRIE_HOME}/etc/cowrie.cfg" ]]; then
  echo "Removing the incomplete virtualenv from the failed install attempt..."
  rm -rf -- "${COWRIE_HOME}/cowrie-env"
fi

if [[ ! -d "${COWRIE_HOME}/.git" ]]; then
  if [[ -e "${COWRIE_HOME}" ]] && [[ -n "$(find "${COWRIE_HOME}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "${COWRIE_HOME} exists but is not a Cowrie Git checkout; refusing to overwrite it." >&2
    exit 1
  fi
  echo "Cloning the official Cowrie repository..."
  rmdir "${COWRIE_HOME}" 2>/dev/null || true
  runuser -u "${COWRIE_USER}" -- git clone --depth 1 "${COWRIE_REPOSITORY}" "${COWRIE_HOME}"
fi

if [[ -x "${VENV}/bin/python" ]] && "${VENV}/bin/python" -c 'import sys; raise SystemExit(sys.version_info[:2] != (3, 11))'; then
  echo "Existing Cowrie virtualenv uses Python 3.11."
elif [[ -d "${VENV}" ]]; then
  echo "Existing Cowrie virtualenv does not use Python 3.11; rebuilding it..."
  rm -rf -- "${VENV}"
fi

if [[ ! -x "${VENV}/bin/python" ]]; then
  echo "Creating Cowrie virtualenv..."
  runuser -u "${COWRIE_USER}" -- /usr/bin/python3.11 -m venv "${VENV}"
fi

if runuser -u "${COWRIE_USER}" -- sh -c 'cd "$1" && "$2" -m pip show cowrie >/dev/null && "$2" -c "import cowrie, cryptography, twisted" && "$2" -m pip check' sh \
  "${COWRIE_HOME}" "${VENV}/bin/python"; then
  echo "Existing Cowrie virtualenv and dependencies are healthy; skipping pip installation."
else
  echo "Installing Cowrie Python dependencies from requirements.txt..."
  runuser -u "${COWRIE_USER}" -- "${VENV}/bin/python" -m pip install --upgrade pip
  runuser -u "${COWRIE_USER}" -- sh -c 'cd "$1" && "$2" -m pip install -r requirements.txt' sh \
    "${COWRIE_HOME}" "${VENV}/bin/python"
  runuser -u "${COWRIE_USER}" -- sh -c 'cd "$1" && "$2" install -e .' sh \
    "${COWRIE_HOME}" "${VENV}/bin/pip"
fi

if [[ ! -f "${COWRIE_HOME}/etc/cowrie.cfg" ]]; then
  cp "${DATA_ETC}/cowrie.cfg.dist" "${COWRIE_HOME}/etc/cowrie.cfg"
fi
if [[ ! -f "${COWRIE_HOME}/etc/userdb.txt" ]]; then
  cp "${DATA_ETC}/userdb.example" "${COWRIE_HOME}/etc/userdb.txt"
fi

cat > "${COWRIE_HOME}/etc/cowrie.cfg" <<'EOF'
[ssh]
listen_endpoints = tcp:2222:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json

[honeypot]
hostname = prod-app-server-01

[shell]
filesystem = var/lib/cowrie/fs.pickle
EOF

install -d -o "${COWRIE_USER}" -g "${COWRIE_USER}" -m 0750 \
  "${COWRIE_HOME}/var/log/cowrie" "${COWRIE_HOME}/var/lib/cowrie"
chown -R "${COWRIE_USER}:${COWRIE_USER}" "${COWRIE_HOME}"

echo "Cowrie source is installed at ${COWRIE_HOME}; it has not been started."
