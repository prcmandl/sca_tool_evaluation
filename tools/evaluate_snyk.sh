#!/usr/bin/env bash
set -euo pipefail

SBOM_FILE="$1"

# ------------------------------------------------------------
# Logging → STDERR (!)
# ------------------------------------------------------------
echo "[SNYK] ===== START =====" >&2
echo "[SNYK] File: $SBOM_FILE" >&2
date >&2

# ------------------------------------------------------------
# Validate input
# ------------------------------------------------------------
if [ ! -f "$SBOM_FILE" ]; then
  echo "[SNYK] ERROR: SBOM file not found" >&2
  exit 1
fi

# ------------------------------------------------------------
# Run Snyk (JSON → STDOUT!)
# ------------------------------------------------------------
timeout 120s /usr/local/bin/snyk sbom test \
  --experimental \
  --file="$SBOM_FILE" \
  --json

RC=$?

# ------------------------------------------------------------
# Logging → STDERR
# ------------------------------------------------------------
echo "[SNYK] Exit code: $RC" >&2
date >&2
echo "[SNYK] ===== END =====" >&2

exit $RC