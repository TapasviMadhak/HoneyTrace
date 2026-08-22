#!/usr/bin/env bash
# ==============================================================================
# HoneyTrace - Cowrie Log Credential & IP Scrubber
#
# Filters out operator/admin IPs (e.g. public IP, Tailscale IP) and associated
# session activity from Cowrie JSON logs to prevent personal test data from
# contaminating honeypot intelligence and analytics.
#
# Defaults to DRY-RUN mode.
# ==============================================================================
set -euo pipefail

# Default configuration
DEFAULT_LOG_GLOB="/home/cowrie/cowrie/var/log/cowrie/cowrie.json*"
PREVIEW_FILE="scrubbed_preview.json"
CLEAN_SUFFIX=".clean"
APPLY_CHANGES=false
TARGET_IPS=()
TARGET_FILES=()

# Text formatting helpers
BOLD="\033[1m"
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
RESET="\033[0m"

usage() {
  cat <<EOF
${BOLD}Usage:${RESET} $0 [OPTIONS] [IP_ADDRESSES...]

${BOLD}Description:${RESET}
  Scans Cowrie JSON log files, detects log entries and sessions matching target
  operator/admin IPs, and generates scrubbed preview logs and clean output files.

${BOLD}Options:${RESET}
  -i, --ip <IP>          Target IP to filter out (can be specified multiple times or comma-separated)
  -f, --file <PATH>      Specific log file or glob pattern to process (default: ${DEFAULT_LOG_GLOB})
  -p, --preview <FILE>   Path to output scrubbed matching entries (default: ${PREVIEW_FILE})
  -s, --suffix <SUFFIX>  Suffix for clean log files (default: ${CLEAN_SUFFIX})
      --apply            Apply changes in-place by creating .bak backups and replacing original logs
      --dry-run          Run in preview mode without touching originals (default behavior)
  -h, --help             Display this help message and exit

${BOLD}Examples:${RESET}
  # Dry-run filter for your public IP and Tailscale IP:
  $0 -i 203.0.113.50 -i 100.64.0.15

  # Filter comma-separated IPs against a specific log file:
  $0 --ip "203.0.113.50,100.64.0.15" -f /path/to/cowrie.json

  # Apply scrub in-place after verifying preview:
  $0 -i 203.0.113.50 -i 100.64.0.15 --apply
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -i|--ip)
      if [[ -z "${2:-}" ]]; then
        echo -e "${RED}Error: --ip requires an IP argument.${RESET}" >&2
        exit 1
      fi
      IFS=',' read -ra ADDR_ARRAY <<< "$2"
      for addr in "${ADDR_ARRAY[@]}"; do
        trimmed="$(echo -n "${addr}" | xargs)"
        [[ -n "${trimmed}" ]] && TARGET_IPS+=("${trimmed}")
      done
      shift 2
      ;;
    -f|--file)
      if [[ -z "${2:-}" ]]; then
        echo -e "${RED}Error: --file requires a path argument.${RESET}" >&2
        exit 1
      fi
      TARGET_FILES+=("$2")
      shift 2
      ;;
    -p|--preview)
      PREVIEW_FILE="$2"
      shift 2
      ;;
    -s|--suffix)
      CLEAN_SUFFIX="$2"
      shift 2
      ;;
    --apply)
      APPLY_CHANGES=true
      shift
      ;;
    --dry-run)
      APPLY_CHANGES=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      # Treat positional arguments: if it looks like an IP, add to TARGET_IPS, else check if it is a file
      if [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || [[ "$1" =~ : ]]; then
        TARGET_IPS+=("$1")
      elif [[ -f "$1" ]]; then
        TARGET_FILES+=("$1")
      else
        echo -e "${RED}Unknown argument: $1${RESET}" >&2
        usage
        exit 1
      fi
      shift
      ;;
  esac
done

# Ensure jq is installed
if ! command -v jq >/dev/null 2>&1; then
  echo -e "${RED}Error: 'jq' command is required but not installed.${RESET}" >&2
  echo -e "Install jq on Amazon Linux / RHEL: ${CYAN}sudo dnf install -y jq${RESET}" >&2
  echo -e "Install jq on Debian / Ubuntu:    ${CYAN}sudo apt-get install -y jq${RESET}" >&2
  echo -e "Install jq on macOS:              ${CYAN}brew install jq${RESET}" >&2
  exit 1
fi

# Validate target IPs
if [[ ${#TARGET_IPS[@]} -eq 0 ]]; then
  echo -e "${RED}Error: No target IPs specified to filter.${RESET}" >&2
  echo -e "Provide target IPs using ${CYAN}-i <IP>${RESET} or as arguments." >&2
  echo -e "Example: $0 -i <YOUR_PUBLIC_IP> -i <YOUR_TAILSCALE_IP>" >&2
  exit 1
fi

# Resolve target log files
LOG_FILES=()
if [[ ${#TARGET_FILES[@]} -gt 0 ]]; then
  for tf in "${TARGET_FILES[@]}"; do
    # Expand glob if needed
    for match in ${tf}; do
      [[ -f "${match}" ]] && LOG_FILES+=("${match}")
    done
  done
else
  # Expand default glob
  shopt -s nullglob
  for match in ${DEFAULT_LOG_GLOB}; do
    [[ -f "${match}" ]] && LOG_FILES+=("${match}")
  done
  shopt -u nullglob
fi

if [[ ${#LOG_FILES[@]} -eq 0 ]]; then
  echo -e "${YELLOW}Warning: No Cowrie log files found matching pattern:${RESET}" >&2
  if [[ ${#TARGET_FILES[@]} -gt 0 ]]; then
    echo "  ${TARGET_FILES[*]}" >&2
  else
    echo "  ${DEFAULT_LOG_GLOB}" >&2
  fi
  echo -e "Specify a log file explicitly with ${CYAN}-f <path/to/cowrie.json>${RESET}." >&2
  exit 0
fi

# Build JSON array of target IPs for jq
TARGET_IPS_JSON="$(printf '%s\n' "${TARGET_IPS[@]}" | jq -R . | jq -s .)"

echo -e "${CYAN}======================================================${RESET}"
echo -e "${BOLD}HoneyTrace Cowrie Log Credential & IP Scrubber${RESET}"
echo -e "${CYAN}======================================================${RESET}"
echo -e "Mode:        $([ "${APPLY_CHANGES}" = true ] && echo -e "${RED}APPLY (In-place with .bak backups)${RESET}" || echo -e "${GREEN}DRY-RUN (Preview & .clean generation)${RESET}")"
echo -e "Target IPs:  ${BOLD}${TARGET_IPS[*]}${RESET}"
echo -e "Log Files:   ${#LOG_FILES[@]} file(s) identified"
echo -e "Preview out: ${BOLD}${PREVIEW_FILE}${RESET}"
echo

# Truncate / initialize preview file
: > "${PREVIEW_FILE}"

TOTAL_SCANNED=0
TOTAL_DROPPED=0
TOTAL_KEPT=0

# Temporary work directory for per-file processing
TMP_DIR="$(mktemp -d /tmp/honeytrace-scrub-XXXXXX)"
trap 'rm -rf -- "${TMP_DIR}"' EXIT

for logfile in "${LOG_FILES[@]}"; do
  echo -e "Processing: ${CYAN}${logfile}${RESET}"

  file_scanned=0
  file_dropped=0
  file_kept=0

  clean_file="${logfile}${CLEAN_SUFFIX}"
  matched_temp="${TMP_DIR}/matched_$(basename "${logfile}").json"
  clean_temp="${TMP_DIR}/clean_$(basename "${logfile}").json"

  # Pass 1: Extract all session IDs associated with the target IPs in this log file
  # Pass 2: Filter lines: if .src_ip is in target_ips OR .session is in matched sessions -> drop & preview, else keep
  jq -c --argjson ips "${TARGET_IPS_JSON}" '
    select(.src_ip as $ip | $ips | index($ip)) | .session // empty
  ' "${logfile}" | sort -u > "${TMP_DIR}/target_sessions.txt" || true

  MATCHED_SESSIONS_COUNT="$(wc -l < "${TMP_DIR}/target_sessions.txt" | xargs)"
  if [[ "${MATCHED_SESSIONS_COUNT}" -gt 0 ]]; then
    SESSIONS_JSON="$(jq -R . "${TMP_DIR}/target_sessions.txt" | jq -s .)"
  else
    SESSIONS_JSON="[]"
  fi

  # Filter with jq
  # Output matching lines to matched_temp and clean lines to clean_temp
  jq -c --argjson ips "${TARGET_IPS_JSON}" --argjson sess "${SESSIONS_JSON}" '
    if ( (.src_ip as $ip | $ips | index($ip)) or (.session as $s | $sess | index($s)) ) then
      {status: "dropped", record: .}
    else
      {status: "kept", record: .}
    end
  ' "${logfile}" > "${TMP_DIR}/processed.jsonl"

  # Separate records
  jq -c 'select(.status == "dropped") | .record' "${TMP_DIR}/processed.jsonl" > "${matched_temp}"
  jq -c 'select(.status == "kept") | .record' "${TMP_DIR}/processed.jsonl" > "${clean_temp}"

  file_scanned=$(wc -l < "${logfile}" | xargs)
  file_dropped=$(wc -l < "${matched_temp}" | xargs)
  file_kept=$(wc -l < "${clean_temp}" | xargs)

  TOTAL_SCANNED=$((TOTAL_SCANNED + file_scanned))
  TOTAL_DROPPED=$((TOTAL_DROPPED + file_dropped))
  TOTAL_KEPT=$((TOTAL_KEPT + file_kept))

  # Append dropped records to overall preview file
  cat "${matched_temp}" >> "${PREVIEW_FILE}"

  # Write clean file
  cp "${clean_temp}" "${clean_file}"

  echo -e "  Scanned: ${file_scanned} | Dropped: ${RED}${file_dropped}${RESET} | Kept: ${GREEN}${file_kept}${RESET}"

  if [[ "${file_dropped}" -gt 0 ]]; then
    echo -e "  ${YELLOW}Dropped entries breakdown for $(basename "${logfile}"):${RESET}"
    jq -r '
      [
        (.timestamp // "-"),
        (.eventid // "-"),
        (.session // "-"),
        (.src_ip // "-"),
        (.username // "-"),
        (.password // "-"),
        (.input // "-")
      ] | @tsv
    ' "${matched_temp}" | while IFS=$'\t' read -r ts eventid sess ip user pass inp; do
      extra=""
      [[ "${user}" != "-" || "${pass}" != "-" ]] && extra=" auth=(${user}:${pass})"
      [[ "${inp}" != "-" ]] && extra="${extra} cmd=(${inp})"
      echo -e "    ${RED}[DROPPED]${RESET} ${ts} | ${CYAN}${eventid}${RESET} | ip=${ip} session=${sess}${extra}"
    done
  fi

  if [[ "${APPLY_CHANGES}" = true && "${file_dropped}" -gt 0 ]]; then
    backup_file="${logfile}.bak.$(date +%Y%m%d%H%M%S)"
    echo -e "  ${YELLOW}Creating backup:${RESET} ${backup_file}"
    cp -p "${logfile}" "${backup_file}"
    mv "${clean_file}" "${logfile}"
    echo -e "  ${GREEN}Applied clean log in-place.${RESET}"
  fi
  echo
done

echo -e "${CYAN}======================================================${RESET}"
echo -e "${BOLD}Summary Statistics${RESET}"
echo -e "${CYAN}======================================================${RESET}"
echo -e "Total Lines Scanned: ${TOTAL_SCANNED}"
echo -e "Total Lines Kept:    ${GREEN}${TOTAL_KEPT}${RESET}"
echo -e "Total Lines Dropped: ${RED}${TOTAL_DROPPED}${RESET}"
echo -e "Preview File:        ${BOLD}${PREVIEW_FILE}${RESET} ($([ -s "${PREVIEW_FILE}" ] && echo -e "${RED}${TOTAL_DROPPED} records recorded${RESET}" || echo "0 records"))"

if [[ "${TOTAL_DROPPED}" -gt 0 ]]; then
  echo
  echo -e "${BOLD}Sample dropped log records (from ${PREVIEW_FILE}):${RESET}"
  head -n 5 "${PREVIEW_FILE}" | jq -C '.' || head -n 5 "${PREVIEW_FILE}"
  if [[ "${TOTAL_DROPPED}" -gt 5 ]]; then
    echo -e "  ... and $((TOTAL_DROPPED - 5)) more dropped entries in ${PREVIEW_FILE}."
  fi
fi

if [[ "${APPLY_CHANGES}" = false && "${TOTAL_DROPPED}" -gt 0 ]]; then
  echo
  echo -e "${YELLOW}DRY-RUN Complete.${RESET} Clean versions generated with suffix '${CLEAN_SUFFIX}'."
  echo -e "To apply in-place with automatic .bak backup creation, run:"
  echo -e "  ${CYAN}$0 -i \"${TARGET_IPS[*]}\" --apply${RESET}"
fi
echo
