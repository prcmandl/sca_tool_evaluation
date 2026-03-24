#!/usr/bin/env bash
set -euo pipefail

# Test only the DTRACK integration (without temporal evaluation) using a pre-generated SBOM and a fixed project name.
#SBOM_PATH=/Users/petermandl/Documents/sca_tool_evaluation/sca_tool_evaluation/build/experiments/20260324T083747Z/mixed_ground_truth_dataset_20260324T083747Z_27_40.sbom.json \
#DTRACK_PROJECT_NAME=eval_test_002 \
#DTRACK_URL=http://dtrack.evaltech.de:8081 \
#DTRACK_API_KEY="odt_flPeugLK_xCkR2iqI3vO0w3odHTEIBLz2Fq7GoFLZ"
# -------------

dtrack_log() {
  echo "[DTRACK $(date '+%H:%M:%S')] $*"
}

# ------------------------------------------------------------
# Validate input
# ------------------------------------------------------------
if [ -z "${SBOM_PATH:-}" ]; then
  echo "ERROR: SBOM_PATH not set"
  exit 1
fi

if [ ! -f "$SBOM_PATH" ]; then
  echo "ERROR: SBOM file not found: $SBOM_PATH"
  exit 1
fi

if [ -z "${DTRACK_PROJECT_NAME:-}" ]; then
  echo "ERROR: DTRACK_PROJECT_NAME not set"
  exit 1
fi

if [ -z "${DTRACK_PROJECT_VERSION:-}" ]; then
  DTRACK_PROJECT_VERSION="1.0"
fi

if [ -z "${DTRACK_URL:-}" ] || [ -z "${DTRACK_API_KEY:-}" ]; then
  echo "ERROR: DTRACK config missing"
  exit 1
fi

DTRACK_API="${DTRACK_URL}/api/v1"

dtrack_log "SBOM_PATH=${SBOM_PATH}"
dtrack_log "DTRACK_PROJECT_NAME=${DTRACK_PROJECT_NAME}"
dtrack_log "DTRACK_PROJECT_VERSION=${DTRACK_PROJECT_VERSION}"
dtrack_log "DTRACK_URL=${DTRACK_URL}"

# ------------------------------------------------------------
# Helper: curl
# ------------------------------------------------------------
dtrack_call() {
  local method="$1"
  local url="$2"
  local data="${3:-}"

  if [ -n "$data" ]; then
    curl --max-time 20 -s -w "\n%{http_code}" \
      -X "$method" \
      -H "Content-Type: application/json" \
      -H "X-Api-Key: ${DTRACK_API_KEY}" \
      -d "$data" \
      "$url"
  else
    curl --max-time 20 -s -w "\n%{http_code}" \
      -H "X-Api-Key: ${DTRACK_API_KEY}" \
      "$url"
  fi
}

split_response() {
  local response="$1"
  STATUS="$(printf "%s\n" "$response" | tail -n1)"
  BODY="$(printf "%s\n" "$response" | sed '$d')"
}

# ------------------------------------------------------------
# Lookup existing project by exact name/version
# ------------------------------------------------------------
dtrack_log "Looking up project"

LOOKUP_RESPONSE="$(dtrack_call GET \
  "${DTRACK_API}/project/lookup?name=${DTRACK_PROJECT_NAME}&version=${DTRACK_PROJECT_VERSION}")"

split_response "$LOOKUP_RESPONSE"
dtrack_log "Lookup status: $STATUS"

PROJECT_UUID=""

if [ "$STATUS" = "200" ]; then
  if ! printf "%s" "$BODY" | jq . >/dev/null 2>&1; then
    echo "ERROR: Invalid JSON from lookup"
    echo "$BODY"
    exit 1
  fi

  PROJECT_UUID="$(printf "%s" "$BODY" | jq -r '.uuid // empty')"
  if [ -n "$PROJECT_UUID" ]; then
    dtrack_log "Reusing existing project UUID: $PROJECT_UUID"
  fi
elif [ "$STATUS" = "404" ]; then
  dtrack_log "Project not found -> creating"
else
  echo "ERROR: Unexpected response from DTrack lookup (HTTP $STATUS)"
  echo "$BODY"
  exit 1
fi

# ------------------------------------------------------------
# Create project if missing
# ------------------------------------------------------------
if [ -z "$PROJECT_UUID" ]; then
  CREATE_RESPONSE="$(dtrack_call PUT "${DTRACK_API}/project" \
    "{\"name\":\"${DTRACK_PROJECT_NAME}\",\"version\":\"${DTRACK_PROJECT_VERSION}\"}")"

  split_response "$CREATE_RESPONSE"
  dtrack_log "Create status: $STATUS"

  if [ "$STATUS" != "200" ] && [ "$STATUS" != "201" ]; then
    echo "ERROR: Failed to create project"
    echo "$BODY"
    exit 1
  fi

  if ! printf "%s" "$BODY" | jq . >/dev/null 2>&1; then
    echo "ERROR: Invalid JSON from create response"
    echo "$BODY"
    exit 1
  fi

  PROJECT_UUID="$(printf "%s" "$BODY" | jq -r '.uuid // empty')"
  if [ -z "$PROJECT_UUID" ]; then
    echo "ERROR: Could not extract UUID from create response"
    exit 1
  fi

  dtrack_log "Created project UUID: $PROJECT_UUID"
fi

export DTRACK_PROJECT_UUID="$PROJECT_UUID"

# ------------------------------------------------------------
# Upload SBOM (multipart is more reliable than base64 JSON)
# ------------------------------------------------------------
dtrack_log "Uploading SBOM"

UPLOAD_RESPONSE="$(curl --max-time 30 -s -w "\n%{http_code}" \
  -X POST "${DTRACK_API}/bom" \
  -H "X-Api-Key: ${DTRACK_API_KEY}" \
  -F "project=${PROJECT_UUID}" \
  -F "bom=@${SBOM_PATH}")"

split_response "$UPLOAD_RESPONSE"
dtrack_log "Upload status: $STATUS"

if [ "$STATUS" != "200" ] && [ "$STATUS" != "201" ]; then
  echo "ERROR: SBOM upload failed (HTTP $STATUS)"
  echo "$BODY"
  exit 1
fi

UPLOAD_TOKEN=""
if printf "%s" "$BODY" | jq . >/dev/null 2>&1; then
  UPLOAD_TOKEN="$(printf "%s" "$BODY" | jq -r '.token // empty')"
fi

if [ -n "$UPLOAD_TOKEN" ]; then
  dtrack_log "Upload token: $UPLOAD_TOKEN"
else
  dtrack_log "No upload token returned -> falling back to vulnerability polling"
fi

# ------------------------------------------------------------
# Wait for analysis
# Prefer BOM token polling if token is available
# ------------------------------------------------------------
dtrack_log "Waiting for analysis"

MAX_WAIT=180
SLEEP=5
ELAPSED=0

if [ -n "$UPLOAD_TOKEN" ]; then
  while [ "$ELAPSED" -lt "$MAX_WAIT" ]; do
    TOKEN_RESPONSE="$(dtrack_call GET "${DTRACK_API}/bom/token/${UPLOAD_TOKEN}")"
    split_response "$TOKEN_RESPONSE"

    if [ "$STATUS" = "200" ] && printf "%s" "$BODY" | jq . >/dev/null 2>&1; then
      PROCESSING="$(printf "%s" "$BODY" | jq -r '.processing // empty')"

      if [ "$PROCESSING" = "false" ]; then
        dtrack_log "BOM processing complete"
        break
      fi
    fi

    dtrack_log "waiting... (${ELAPSED}s)"
    sleep "$SLEEP"
    ELAPSED=$((ELAPSED + SLEEP))
  done
else
  while [ "$ELAPSED" -lt "$MAX_WAIT" ]; do
    VULN_RESPONSE="$(dtrack_call GET \
      "${DTRACK_API}/vulnerability/project/${PROJECT_UUID}")"

    split_response "$VULN_RESPONSE"

    if [ "$STATUS" = "200" ] && printf "%s" "$BODY" | jq . >/dev/null 2>&1; then
      COUNT="$(printf "%s" "$BODY" | jq 'length')"
      if [ "$COUNT" -gt 0 ]; then
        dtrack_log "Ready (${COUNT} vulnerabilities)"
        break
      fi
    fi

    dtrack_log "waiting... (${ELAPSED}s)"
    sleep "$SLEEP"
    ELAPSED=$((ELAPSED + SLEEP))
  done
fi

# ------------------------------------------------------------
# Final vulnerability count for logging
# ------------------------------------------------------------
FINAL_VULN_RESPONSE="$(dtrack_call GET \
  "${DTRACK_API}/vulnerability/project/${PROJECT_UUID}")"

split_response "$FINAL_VULN_RESPONSE"

if [ "$STATUS" = "200" ] && printf "%s" "$BODY" | jq . >/dev/null 2>&1; then
  FINAL_COUNT="$(printf "%s" "$BODY" | jq 'length')"
  dtrack_log "Final vulnerability count: ${FINAL_COUNT}"
else
  dtrack_log "Final vulnerability count unavailable"
fi

# ------------------------------------------------------------
# Export for caller shell
# ------------------------------------------------------------
export DTRACK_PROJECT_NAME
export DTRACK_PROJECT_UUID

dtrack_log "Exported:"
dtrack_log "  DTRACK_PROJECT_NAME=${DTRACK_PROJECT_NAME}"
dtrack_log "  DTRACK_PROJECT_UUID=${DTRACK_PROJECT_UUID}"