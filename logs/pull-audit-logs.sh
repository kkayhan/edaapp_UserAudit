#!/usr/bin/env bash
#
# pull-audit-logs.sh -- Download audit logs from the EDA User Audit app.
#
# Usage:
#   ./pull-audit-logs.sh https://my-eda-host
#   ./pull-audit-logs.sh https://my-eda-host ./output-dir
#   ./pull-audit-logs.sh https://my-eda-host ./output-dir Transaction-2026-04.log
#
# Requires: bash, curl. No other dependencies.
#
set -euo pipefail

EDA_URL="${1:?Usage: $0 <eda-url> [output-dir] [filename]}"
OUTPUT_DIR="${2:-.}"
SINGLE_FILE="${3:-}"

EDA_URL="${EDA_URL%/}"
BASE="${EDA_URL}/core/httpproxy/v1/useraudit"

mkdir -p "$OUTPUT_DIR"

echo "Checking connectivity to ${BASE} ..."
STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "${BASE}/healthz")
if [ "$STATUS" != "200" ]; then
    echo "ERROR: /healthz returned HTTP ${STATUS}. Is the EDA User Audit app installed and reachable?"
    exit 1
fi
echo "OK."
echo ""

if [ -n "$SINGLE_FILE" ]; then
    echo "Downloading ${SINGLE_FILE} ..."
    HTTP_CODE=$(curl -sk -w "%{http_code}" -o "${OUTPUT_DIR}/${SINGLE_FILE}" "${BASE}/logs/${SINGLE_FILE}")
    if [ "$HTTP_CODE" = "200" ]; then
        SIZE=$(wc -c < "${OUTPUT_DIR}/${SINGLE_FILE}")
        LINES=$(wc -l < "${OUTPUT_DIR}/${SINGLE_FILE}")
        echo "  Saved: ${OUTPUT_DIR}/${SINGLE_FILE} (${SIZE} bytes, ${LINES} lines)"
    else
        rm -f "${OUTPUT_DIR}/${SINGLE_FILE}"
        echo "  ERROR: HTTP ${HTTP_CODE} -- file not found"
        exit 1
    fi
    exit 0
fi

echo "Fetching log file list ..."
LIST_JSON=$(curl -sk "${BASE}/logs/")

# Extract file names from the JSON array without requiring jq/python.
NAMES=$(printf '%s' "$LIST_JSON" \
    | grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]+"' \
    | sed -E 's/.*"([^"]+)"$/\1/' || true)

if [ -z "$NAMES" ]; then
    echo "No log files available yet."
    exit 0
fi

COUNT=$(printf '%s\n' "$NAMES" | wc -l)
echo "Found ${COUNT} log file(s)."
echo ""

DONE=0
while IFS= read -r NAME; do
    [ -z "$NAME" ] && continue
    printf '  Downloading %-40s ... ' "$NAME"
    HTTP_CODE=$(curl -sk -w "%{http_code}" -o "${OUTPUT_DIR}/${NAME}" "${BASE}/logs/${NAME}")
    if [ "$HTTP_CODE" = "200" ]; then
        SIZE=$(wc -c < "${OUTPUT_DIR}/${NAME}")
        echo "OK (${SIZE} bytes)"
        DONE=$((DONE + 1))
    else
        rm -f "${OUTPUT_DIR}/${NAME}"
        echo "FAILED (HTTP ${HTTP_CODE})"
    fi
done <<< "$NAMES"

echo ""
echo "Downloaded ${DONE}/${COUNT} file(s) to ${OUTPUT_DIR}/"
