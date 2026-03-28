#!/usr/bin/env bash
set -euo pipefail

SBOM_FILE="$1"
SNYK_BIN="${SNYK_BIN:-/usr/local/bin/snyk}"
TIMEOUT_BIN="${TIMEOUT_BIN:-timeout}"
TIMEOUT_SECONDS="${SNYK_TIMEOUT_SECONDS:-120}"

# ------------------------------------------------------------
# Logging -> STDERR
# ------------------------------------------------------------
echo "[SNYK] ===== START =====" >&2
echo "[SNYK] File: $SBOM_FILE" >&2
date >&2

# ------------------------------------------------------------
# Validate input
# ------------------------------------------------------------
if [ ! -f "$SBOM_FILE" ]; then
  echo "[SNYK] ERROR: SBOM file not found" >&2
  exit 2
fi

if ! command -v "$SNYK_BIN" >/dev/null 2>&1; then
  echo "[SNYK] ERROR: Snyk binary not found: $SNYK_BIN" >&2
  exit 2
fi

if ! command -v "$TIMEOUT_BIN" >/dev/null 2>&1; then
  echo "[SNYK] ERROR: timeout binary not found: $TIMEOUT_BIN" >&2
  exit 2
fi

TMP_JSON="$(mktemp)"
TMP_ERR="$(mktemp)"
cleanup() {
  rm -f "$TMP_JSON" "$TMP_ERR"
}
trap cleanup EXIT

# ------------------------------------------------------------
# Run Snyk (JSON -> temp file)
# Important: rc=1 can mean "vulnerabilities found"
# ------------------------------------------------------------
set +e
"$TIMEOUT_BIN" "${TIMEOUT_SECONDS}s" \
  "$SNYK_BIN" sbom test \
  --experimental \
  --file="$SBOM_FILE" \
  --json \
  >"$TMP_JSON" 2>"$TMP_ERR"
RC=$?
set -e

# Forward STDERR for diagnostics
if [ -s "$TMP_ERR" ]; then
  cat "$TMP_ERR" >&2
fi

# ------------------------------------------------------------
# Logging -> STDERR
# ------------------------------------------------------------
echo "[SNYK] Exit code: $RC" >&2
date >&2
echo "[SNYK] ===== END =====" >&2

# ------------------------------------------------------------
# Normalize exit codes for Python caller
# 0 = no vulns, 1 = vulns found, 2/124/other = technical failure
# ------------------------------------------------------------
case "$RC" in
  0|1)
    if [ ! -s "$TMP_JSON" ]; then
      echo "[SNYK] ERROR: Snyk returned no JSON output" >&2
      exit 2
    fi
    cat "$TMP_JSON"
    exit 0
    ;;
  124)
    echo "[SNYK] ERROR: Snyk timed out after ${TIMEOUT_SECONDS}s" >&2
    exit 2
    ;;
  2)
    echo "[SNYK] ERROR: Snyk reported execution failure" >&2
    exit 2
    ;;
  *)
    echo "[SNYK] ERROR: Unexpected Snyk exit code: $RC" >&2
    exit 2
    ;;
esac
