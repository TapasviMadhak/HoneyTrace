#!/usr/bin/env bash
# ==============================================================================
# HoneyTrace - Atomic SQLite Telemetry Backup Utility (Remediates F-08)
#
# Performs atomic online backup of /opt/honeytrace/data/honeytrace.db
# using SQLite VACUUM INTO / .backup to ensure zero database locking or corruption.
# Compresses backups, retains last 7 days, and optionally syncs to S3.
# ==============================================================================
set -euo pipefail

BACKUP_DIR="/var/backups/honeytrace"
DB_PATH="/opt/honeytrace/data/honeytrace.db"
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%SZ")
BACKUP_FILE="${BACKUP_DIR}/honeytrace_${TIMESTAMP}.db"
COMPRESSED_FILE="${BACKUP_FILE}.gz"

install -d -m 0700 "${BACKUP_DIR}"

if [[ ! -f "${DB_PATH}" ]]; then
  echo "Database not found at ${DB_PATH}. Skipping backup." >&2
  exit 0
fi

echo "Starting atomic SQLite backup from ${DB_PATH}..."
# Use sqlite3 .backup or VACUUM INTO for 100% atomic snapshot without locking writes
sqlite3 "${DB_PATH}" "VACUUM INTO '${BACKUP_FILE}';" 2>/dev/null || sqlite3 "${DB_PATH}" ".backup '${BACKUP_FILE}'"

if [[ -f "${BACKUP_FILE}" ]]; then
  gzip -9 "${BACKUP_FILE}"
  chmod 0600 "${COMPRESSED_FILE}"
  echo "Backup successfully created: ${COMPRESSED_FILE} ($(du -h "${COMPRESSED_FILE}" | cut -f1))"

  # Retain only last 7 days of backups
  find "${BACKUP_DIR}" -name "honeytrace_*.db.gz" -type f -mtime +7 -delete 2>/dev/null || true

  # If AWS CLI is present and backup bucket configured, sync to S3
  if command -v aws >/dev/null 2>&1 && [[ -n "${HONEYTRACE_BACKUP_S3_BUCKET:-}" ]]; then
    echo "Syncing backup to s3://${HONEYTRACE_BACKUP_S3_BUCKET}/..."
    aws s3 cp "${COMPRESSED_FILE}" "s3://${HONEYTRACE_BACKUP_S3_BUCKET}/backups/" --quiet || true
  fi
fi

echo "Backup process finished."
