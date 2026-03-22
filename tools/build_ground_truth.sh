#!/usr/bin/env bash
set -euo pipefail


 ------------------------------------------------------------
# Paths
# ------------------------------------------------------------
export CODEBASE=/Users/petermandl/Documents/sca_tool_evaluation/sca_tool_evaluation
export CODEBASE_BUILD_PATH="${CODEBASE}/build"
export GROUND_TRUTH_BUILD_PATH="${CODEBASE}/build/ground_truth"

# ---------------

if [ -f "$CODEBASE/.env" ]; then
  set -a
  . "$CODEBASE/.env"
  set +a
fi

# ------------------------------------------------------------
# REQUIRED ENV VARS (fail fast)
# ------------------------------------------------------------
require_env() {
  local var="$1"
  if [ -z "${!var:-}" ]; then
    echo "ERROR: Required environment variable '$var' is not set"
    exit 1
  fi
}

require_env GITHUB_TOKEN
require_env NVD_API_KEY

# optional (nur wenn genutzt)
# require_env FOSSA_API_KEY
# require_env OSSINDEX_TOKEN

#---------------------------------------------
# APIs (nur Referenz, KEINE Werte!)
# ------------------------------------------------------------
export OSV_ROOT_PATH=/Users/petermandl/Documents/OSV/OSV/vulnfeeds

# Tokens kommen aus ENV:
# export GITHUB_TOKEN
# export NVD_API_KEY

# ------------------------------------------------------------
# Config
# ------------------------------------------------------------
export MAVEN_MAX_VERSIONS_PER_PACKAGE=30
export PYPI_MAX_VERSIONS_PER_PACKAGE=10
export NPM_MAX_VERSIONS_PER_PACKAGE=20
export NUGET_MAX_VERSIONS_PER_PACKAGE=40

export MAX_OSV_ENTRIES_PER_COMPONENT=30
export TARGET_VULNS_PER_ECOSYSTEM=250

export SAMPLES=1000
export START_DATE="2020-01-01"
export END_DATE="2026-01-25"

export BALANCE=false
export BALANCE_STRATEGY=min

export ECOSYSTEMS="maven pypi npm nuget"

# ------------------------------------------------------------
# Run
# ------------------------------------------------------------
echo "=== Starting dataset generation ==="
poetry run python -m new_ground_truth_generation.build_multi_ground_truth_dataset
echo "=== Done ==="