#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# EXPERIMENT RUNNER (FULL PIPELINE WITH STATISTICS)
# ============================================================
#
# DESCRIPTION
# ------------------------------------------------------------
# End-to-end experimental pipeline for evaluating SCA tools
# under temporal consistency constraints.
#
# Pipeline:
#   1. Load configuration from .env
#   2. Generate fresh ground truth dataset
#   3. Run evaluation multiple times (NUM_RUNS)
#   4. Perform temporal consistency validation
#   5. Aggregate results across runs
#   6. Compute statistics:
#        - mean
#        - standard deviation
#        - confidence intervals (95%)
#        - paired t-tests
#   7. Generate outputs:
#        - LaTeX (paper-ready)
#        - JSON (analysis)
#        - plots (PNG)
#
# OUTPUT STRUCTURE
# ------------------------------------------------------------
# build/experiments/<RUN_ID>/
#   ├── ground_truth.csv
#   ├── sbom.json
#   ├── run_1/
#   ├── run_2/
#   ├── run_3/
#   ├── aggregated_results.tex
#   ├── stats.json
#   ├── recall_*.png
#
# USAGE
# ------------------------------------------------------------
# ./run_experiment.sh
#
# ============================================================


# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------
log() { echo "[$(date '+%H:%M:%S')] $*"; }

section() {
  echo
  echo "============================================================"
  echo "$*"
  echo "============================================================"
}

# ------------------------------------------------------------
# Load ENV
# ------------------------------------------------------------
# ------------------------------------------------------------
# Locate project root + .env
# ------------------------------------------------------------
section "Loading environment"

# Script directory (robust)
if [ -n "${BASH_SOURCE[0]:-}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  SCRIPT_DIR="$(pwd)"
fi

PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ENV_FILE="${PROJECT_ROOT}/.env"

log "Looking for .env at: $ENV_FILE"

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: .env file not found at $ENV_FILE"
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

log "Environment loaded"

# ------------------------------------------------------------
# Check snyk authentication
# ------------------------------------------------------------
echo "[INIT] Checking Snyk authentication..."

echo "[INIT] Snyk setup (no enforced auth)"

if ! command -v snyk >/dev/null 2>&1; then
  echo "ERROR: snyk CLI not installed"
  exit 1
fi

echo "[INIT] Using local Snyk configuration (no token required)"

# ------------------------------------------------------------
# Validate ENV
# ------------------------------------------------------------
require_env() {
  local var="$1"
  if [ -z "${!var:-}" ]; then
    echo "ERROR: Missing env variable: $var"
    exit 1
  fi
}

section "Validating environment"

require_env CODEBASE
require_env GITHUB_TOKEN
require_env NVD_API_KEY
require_env EXPERIMENT_PATH
require_env GROUND_TRUTH_BUILD_PATH

log "Environment OK"

# ------------------------------------------------------------
# Run ID + dirs
# ------------------------------------------------------------
RUN_ID=$(date -u +"%Y%m%dT%H%M%SZ")
EXPERIMENT_DIR="${EXPERIMENT_PATH}/${RUN_ID}"

mkdir -p "$EXPERIMENT_DIR"

log "RUN_ID=$RUN_ID"
log "Experiment dir: $EXPERIMENT_DIR"

# ------------------------------------------------------------
# Config overview
# ------------------------------------------------------------
section "Configuration"

log "ECOSYSTEMS=$ECOSYSTEMS"
log "SAMPLES=$SAMPLES"
log "DATE RANGE=$START_DATE → $END_DATE"
log "TARGET_VULNS_PER_ECOSYSTEM=$TARGET_VULNS_PER_ECOSYSTEM"
log "BALANCE=$BALANCE ($BALANCE_STRATEGY)"
log "NUM_RUNS=$NUM_RUNS"

# ------------------------------------------------------------
# Ground Truth generation
# ------------------------------------------------------------
section "Generating ground truth"

START_GT=$(date +%s)

poetry run python -m new_ground_truth_generation.build_multi_ground_truth_dataset

END_GT=$(date +%s)

log "Ground truth generated in $((END_GT - START_GT))s"

# ------------------------------------------------------------
# Select dataset
# ------------------------------------------------------------
section "Selecting dataset"

GROUND_TRUTH=$(ls -t "${GROUND_TRUTH_BUILD_PATH}"/*.csv | head -n1)
SBOM_PATH="${GROUND_TRUTH%.csv}.sbom.json"

export GROUND_TRUTH
export SBOM_PATH
export SNYK_SBOM_FILE="$SBOM_PATH"
export TRIVY_SBOM_FILE="$SBOM_PATH"

log "GT:   $GROUND_TRUTH"
log "SBOM: $SBOM_PATH"

# Archive input data
cp "$GROUND_TRUTH" "$EXPERIMENT_DIR/"
[ -f "$SBOM_PATH" ] && cp "$SBOM_PATH" "$EXPERIMENT_DIR/"

# ------------------------------------------------------------
# Run experiments
# ------------------------------------------------------------
section "Running experiments (${NUM_RUNS} runs)"

for i in $(seq 1 "$NUM_RUNS"); do
  log "Run $i/$NUM_RUNS"

  RUN_DIR="${EXPERIMENT_DIR}/run_${i}"
  mkdir -p "$RUN_DIR"

  poetry run python -m evaluation.temporal_runner \
    --ground-truth "$GROUND_TRUTH" \
    --output "${RUN_DIR}/results.tex"

done

# ------------------------------------------------------------
# Statistical analysis
# ------------------------------------------------------------
section "Statistical analysis"

poetry run python - <<EOF
import glob
import json
from pathlib import Path

from evaluation.analysis.statistics import (
    load_runs,
    aggregate,
    add_confidence_intervals,
    compute_significance,
    write_latex_stats,
    write_ecosystem_summary_table,
    build_gt_summary,
)

from evaluation.analysis.plots import plot_tool_comparison
from evaluation.core.ground_truth import load_ground_truth

# ------------------------------------------------------------
# Load run results
# ------------------------------------------------------------
run_dirs = glob.glob("${EXPERIMENT_DIR}/run_*")

data = load_runs(run_dirs)

if not data:
    print("ERROR: No run data found")
    exit(1)

# ------------------------------------------------------------
# Aggregate statistics
# ------------------------------------------------------------
agg = aggregate(data)
agg = add_confidence_intervals(agg)
sig = compute_significance(agg)

# ------------------------------------------------------------
# Ground truth summary
# ------------------------------------------------------------
gt = load_ground_truth(Path("${GROUND_TRUTH}"))
gt_summary = build_gt_summary(gt)

# ------------------------------------------------------------
# Write JSON stats
# ------------------------------------------------------------
stats_path = Path("${EXPERIMENT_DIR}") / "stats.json"

with open(stats_path, "w") as f:
    json.dump({
        "metrics": agg,
        "significance": sig,
    }, f, indent=2)

print(f"[STATS] Written: {stats_path}")

# ------------------------------------------------------------
# Plot: Tool comparison (Recall vs Overlap)
# ------------------------------------------------------------
plot_tool_comparison(
    agg,
    "${EXPERIMENT_DIR}"
)

# ------------------------------------------------------------
# LaTeX tables
# ------------------------------------------------------------
write_latex_stats(
    agg,
    gt_summary,
    "${EXPERIMENT_DIR}/aggregated_results.tex"
)

write_ecosystem_summary_table(
    agg,
    gt_summary,
    "${EXPERIMENT_DIR}/ecosystem_summary.tex"
)

print("[STATS] All outputs generated")
EOF

# ------------------------------------------------------------
# Done
# ------------------------------------------------------------
section "Finished"

log "Experiment completed"
log "Results stored in: $EXPERIMENT_DIR"

echo
echo "============================================================"
echo "Use in paper:"
echo "  ${EXPERIMENT_DIR}/aggregated_results.tex"
echo "============================================================"
