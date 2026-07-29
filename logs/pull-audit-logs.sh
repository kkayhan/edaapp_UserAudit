#!/usr/bin/env bash
#
# pull-audit-logs.sh -- Download audit logs from the EDA User Audit app.
#
# The log endpoint is protected by EDA: the EDA API server authenticates every
# request and authorizes it against EDA RBAC, so this script must present a
# Keycloak bearer token belonging to a member of the `system-administrator`
# user group. (Before v26.4.1-11 the endpoint was unauthenticated.)
#
# Usage:
#   EDA_PASSWORD=... ./pull-audit-logs.sh https://my-eda-host
#   EDA_PASSWORD=... ./pull-audit-logs.sh https://my-eda-host ./output-dir
#   EDA_PASSWORD=... ./pull-audit-logs.sh https://my-eda-host ./output-dir EDA-user-events-2026-05-04.log
#
# Credentials (environment variables):
#   EDA_TOKEN          A bearer token you already hold. If set, nothing else is
#                      needed and no credentials are read.
#   EDA_USERNAME       EDA user to log in as.                     (default: admin)
#   EDA_PASSWORD       That user's password.                      (default: admin)
#   EDA_CLIENT_SECRET  Keycloak client secret for client `eda`. Optional -- if
#                      unset, the script fetches it using the Keycloak admin
#                      credentials below, which is what an EDA administrator
#                      would otherwise do by hand.
#   KC_USERNAME        Keycloak master-realm admin user.          (default: admin)
#   KC_PASSWORD        That admin's password.                     (default: admin)
#
# Requires: bash, curl. No other dependencies.
#
set -euo pipefail

EDA_URL="${1:?Usage: $0 <eda-url> [output-dir] [filename]}"
OUTPUT_DIR="${2:-.}"
SINGLE_FILE="${3:-}"

EDA_URL="${EDA_URL%/}"
BASE="${EDA_URL}/core/httpproxy/v1/useraudit"

EDA_USERNAME="${EDA_USERNAME:-admin}"
EDA_PASSWORD="${EDA_PASSWORD:-admin}"
KC_USERNAME="${KC_USERNAME:-admin}"
KC_PASSWORD="${KC_PASSWORD:-admin}"

mkdir -p "$OUTPUT_DIR"

# ---------------------------------------------------------------- helpers ----

# Extract a string field from a JSON object without jq.
json_str() {
    printf '%s' "$1" \
        | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
        | head -1 \
        | sed -E 's/.*:[[:space:]]*"(.*)"$/\1/'
}

# Keycloak is not always mounted at the same path: most deployments expose it at
# /core/httpproxy/v1/keycloak, some route it natively at /core/proxy/v1/identity.
# Probe once (unauthenticated .well-known) and keep whichever answers.
KC_BASE=""
discover_kc_base() {
    [ -n "$KC_BASE" ] && return 0
    local candidate
    for candidate in "${EDA_URL}/core/httpproxy/v1/keycloak" \
                     "${EDA_URL}/core/proxy/v1/identity"; do
        if [ "$(curl -sk -o /dev/null -w '%{http_code}' \
                "${candidate}/realms/master/.well-known/openid-configuration")" = "200" ]; then
            KC_BASE="$candidate"
            return 0
        fi
    done
    echo "ERROR: could not locate Keycloak under ${EDA_URL}." >&2
    echo "       Tried /core/httpproxy/v1/keycloak and /core/proxy/v1/identity." >&2
    exit 1
}

fetch_client_secret() {
    discover_kc_base
    local admin_token clients client_id secret
    admin_token=$(json_str "$(curl -sk -X POST \
        "${KC_BASE}/realms/master/protocol/openid-connect/token" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode 'grant_type=password' \
        --data-urlencode 'client_id=admin-cli' \
        --data-urlencode "username=${KC_USERNAME}" \
        --data-urlencode "password=${KC_PASSWORD}")" access_token)
    if [ -z "$admin_token" ]; then
        echo "ERROR: could not authenticate to Keycloak as '${KC_USERNAME}'." >&2
        echo "       Set EDA_CLIENT_SECRET directly, or set KC_USERNAME/KC_PASSWORD." >&2
        exit 1
    fi
    clients=$(curl -sk "${KC_BASE}/admin/realms/eda/clients?clientId=eda" \
        -H "Authorization: Bearer ${admin_token}")
    client_id=$(json_str "$clients" id)
    if [ -z "$client_id" ]; then
        echo "ERROR: Keycloak client 'eda' not found in realm 'eda'." >&2
        exit 1
    fi
    secret=$(json_str "$(curl -sk \
        "${KC_BASE}/admin/realms/eda/clients/${client_id}/client-secret" \
        -H "Authorization: Bearer ${admin_token}")" value)
    if [ -z "$secret" ]; then
        echo "ERROR: could not read the client secret for client 'eda'." >&2
        exit 1
    fi
    printf '%s' "$secret"
}

TOKEN=""
acquire_token() {
    if [ -n "${EDA_TOKEN:-}" ]; then
        TOKEN="$EDA_TOKEN"
        return 0
    fi
    discover_kc_base
    if [ -z "${EDA_CLIENT_SECRET:-}" ]; then
        EDA_CLIENT_SECRET=$(fetch_client_secret)
    fi
    local response
    response=$(curl -sk -X POST \
        "${KC_BASE}/realms/eda/protocol/openid-connect/token" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode 'grant_type=password' \
        --data-urlencode 'client_id=eda' \
        --data-urlencode 'scope=openid' \
        --data-urlencode "client_secret=${EDA_CLIENT_SECRET}" \
        --data-urlencode "username=${EDA_USERNAME}" \
        --data-urlencode "password=${EDA_PASSWORD}")
    TOKEN=$(json_str "$response" access_token)
    if [ -z "$TOKEN" ]; then
        echo "ERROR: could not obtain an EDA access token for user '${EDA_USERNAME}'." >&2
        echo "       Keycloak said: $(json_str "$response" error_description)" >&2
        exit 1
    fi
}

# Authenticated GET of $1 into file $2; prints the HTTP status. Re-acquires the
# token once on 401 -- EDA access tokens live ~5 minutes, which a long download
# of many files can outrun.
auth_get() {
    local path="$1" out="$2" code
    code=$(curl -sk -H "Authorization: Bearer ${TOKEN}" -w '%{http_code}' -o "$out" "${BASE}${path}")
    if [ "$code" = "401" ] && [ -z "${EDA_TOKEN:-}" ]; then
        acquire_token
        code=$(curl -sk -H "Authorization: Bearer ${TOKEN}" -w '%{http_code}' -o "$out" "${BASE}${path}")
    fi
    printf '%s' "$code"
}

explain_failure() {
    case "$1" in
        400) echo "  The EDA API server rejected the request as unauthenticated"
             echo "  (HTTP 400 InvalidAuthHeader = no bearer token reached it)." ;;
        401) echo "  The token was rejected. Check EDA_USERNAME / EDA_PASSWORD." ;;
        403) echo "  User '${EDA_USERNAME}' is authenticated but not authorized to read"
             echo "  this URL. Access requires membership of the 'system-administrator'"
             echo "  user group, or a custom EDA ClusterRole with a URL rule covering"
             echo "  /core/httpproxy/v1/useraudit." ;;
        404) echo "  Not found -- is the EDA User Audit app installed?" ;;
        *)   echo "  Unexpected HTTP ${1}." ;;
    esac
}

# ------------------------------------------------------------------- main ----

acquire_token

TMP_HEALTH=$(mktemp)
TMP_LIST=$(mktemp)
trap 'rm -f "$TMP_HEALTH" "$TMP_LIST"' EXIT

echo "Checking connectivity to ${BASE} ..."
STATUS=$(auth_get "/healthz" "$TMP_HEALTH")
if [ "$STATUS" != "200" ]; then
    echo "ERROR: /healthz returned HTTP ${STATUS}."
    explain_failure "$STATUS"
    exit 1
fi
echo "OK (authenticated as ${EDA_USERNAME})."
echo ""

if [ -n "$SINGLE_FILE" ]; then
    echo "Downloading ${SINGLE_FILE} ..."
    HTTP_CODE=$(auth_get "/logs/${SINGLE_FILE}" "${OUTPUT_DIR}/${SINGLE_FILE}")
    if [ "$HTTP_CODE" = "200" ]; then
        SIZE=$(wc -c < "${OUTPUT_DIR}/${SINGLE_FILE}")
        LINES=$(wc -l < "${OUTPUT_DIR}/${SINGLE_FILE}")
        echo "  Saved: ${OUTPUT_DIR}/${SINGLE_FILE} (${SIZE} bytes, ${LINES} lines)"
    else
        rm -f "${OUTPUT_DIR}/${SINGLE_FILE}"
        echo "  ERROR: HTTP ${HTTP_CODE}"
        explain_failure "$HTTP_CODE"
        exit 1
    fi
    exit 0
fi

echo "Fetching log file list ..."
HTTP_CODE=$(auth_get "/logs/" "$TMP_LIST")
if [ "$HTTP_CODE" != "200" ]; then
    echo "ERROR: HTTP ${HTTP_CODE} listing logs."
    explain_failure "$HTTP_CODE"
    exit 1
fi

# Extract file names from the JSON array without requiring jq/python.
NAMES=$(grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]+"' "$TMP_LIST" \
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
    HTTP_CODE=$(auth_get "/logs/${NAME}" "${OUTPUT_DIR}/${NAME}")
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
