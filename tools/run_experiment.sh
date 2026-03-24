#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# EXPERIMENT RUNNER (TEMPORAL + DTRACK + STATISTICS)
# ============================================================
#
# DESCRIPTION
# ------------------------------------------------------------
# End-to-end experimental pipeline for evaluating SCA tools
# under temporal consistency constraints.
#
# This script orchestrates the full workflow:
#
#   1. Load environment variables from .env
#   2. Validate required configuration
#   3. Build dynamic experiment-local paths
#   4. Generate a fresh ground-truth dataset (snapshot GT0)
#   5. Prepare a Dependency-Track project:
#        -> Name: eval_<RUN_ID>
#        -> UUID exported into current shell
#        -> SBOM uploaded
#        -> wait until BOM processing is complete
#   6. Run temporal evaluation:
#        -> Each tool executed 3 times
#        -> Results must be identical (determinism check)
#        -> Ground truth must remain unchanged (GT0 == GT1)
#   7. Compute statistics:
#        - mean
#        - standard deviation
#        - confidence intervals (95%)
#   8. Generate outputs:
#        - JSON (machine-readable)
#        - LaTeX tables (paper-ready)
#        - plots (Recall vs Overlap)
#
#
# TEMPORAL CONSISTENCY GUARANTEE
# ------------------------------------------------------------
# The evaluation is only accepted if:
#
#   (R1 = R2 = R3) AND (GT0 = GT1)
#
# Otherwise:
#   -> the entire evaluation is repeated
#
#
# OUTPUT STRUCTURE
# ------------------------------------------------------------
# build/experiments/<RUN_ID>/
#
#   ├── experiment.log
#   ├── ground_truth_build/
#   │     ├── *.csv
#   │     └── *.sbom.json
#   ├── ground_truth.csv
#   ├── sbom.json
#   ├── run_1/
#   │     ├── run.log
#   │     ├── results.json
#   │     ├── recall_significance.tex
#   │     ├── recall_significance.json
#   │     ├── aggregated_results.tex
#   │     ├── ecosystem_summary.tex
#   │     ├── tool_comparison.png
#   │     └── artifacts/
#   │           └── repeat_<n>/<tool>/
#   │
#   ├── run_2/
#   ├── run_3/
#   │
#   ├── aggregated_results.tex
#   ├── ecosystem_summary.tex
#   ├── stats.json
#   └── tool_comparison.png
#
#
# REQUIREMENTS
# ------------------------------------------------------------
# Required environment variables (.env):
#
#   CODEBASE
#   EXPERIMENT_PATH
#   NUM_RUNS
#   GITHUB_TOKEN
#   NVD_API_KEY
#   DTRACK_URL
#   DTRACK_API_KEY
#
# Optional:
#   OSSINDEX_TOKEN
#   FOSSA_API_KEY
#   EVAL_TOOLS
#
#
# NOTES
# ------------------------------------------------------------
# - Execute this script with bash:
#       bash tools/run_experiment.sh
# - Do not source it from zsh.
# - GROUND_TRUTH_BUILD_PATH is derived dynamically per RUN_ID.
# - If dtrack is part of EVAL_TOOLS, DTrack preparation runs
#   before the temporal evaluation.
# - Statistical significance is computed per run (instance-level,
#   inside temporal_runner), not on aggregated summary values.
#
#
# USAGE
# ------------------------------------------------------------
# bash tools/run_experiment.sh
#
# ============================================================


if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: This script must be run with bash"
  exit 1
fi

EXPERIMENT_LOG=""

log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S %Z')] $*"
  echo "$msg"
  if [ -n "${EXPERIMENT_LOG:-}" ]; then
    echo "$msg" >> "$EXPERIMENT_LOG"
  fi
}

section() {
  local line="============================================================"
  echo
  echo "$line"
  echo "$*"
  echo "$line"

  if [ -n "${EXPERIMENT_LOG:-}" ]; then
    {
      echo
      echo "$line"
      echo "$*"
      echo "$line"
    } >> "$EXPERIMENT_LOG"
  fi
}

require_env() {
  local var="$1"
  local val=""
  eval "val=\${$var:-}"
  if [ -z "$val" ]; then
    echo "ERROR: Missing env variable: $var"
    exit 1
  fi
}

reset_run_dir() {
  local run_dir="$1"

  mkdir -p "$run_dir"
  rm -f \
    "$run_dir/run.log" \
    "$run_dir/results.json" \
    "$run_dir/recall_significance.tex" \
    "$run_dir/recall_significance.json" \
    "$run_dir/recall_significance_matrix.png" \
    "$run_dir/significance_matrix.png" \
    "$run_dir/aggregated_results.tex" \
    "$run_dir/ecosystem_summary.tex" \
    "$run_dir/tool_comparison.png"
  rm -rf "$run_dir/artifacts"
  mkdir -p "$run_dir/artifacts"
}

build_ground_truth_snapshot() {
  local build_dir="$1"
  local out_dir="$2"
  local prefix="$3"

  rm -rf "$build_dir"
  mkdir -p "$build_dir"
  mkdir -p "$out_dir"

  export GROUND_TRUTH_BUILD_PATH="$build_dir"

  local gt_start_ts
  gt_start_ts="$(date +%s)"
  poetry run python -m new_ground_truth_generation.build_multi_ground_truth_dataset
  local gt_end_ts
  gt_end_ts="$(date +%s)"

  local gt
  gt="$(ls -t "${GROUND_TRUTH_BUILD_PATH}"/*.csv 2>/dev/null | head -n1 || true)"
  if [ -z "${gt:-}" ] || [ ! -f "$gt" ]; then
    echo "ERROR: No ground truth CSV found in ${GROUND_TRUTH_BUILD_PATH}"
    exit 1
  fi

  local sbom="${gt%.csv}.sbom.json"
  if [ ! -f "$sbom" ]; then
    echo "ERROR: Matching SBOM not found: $sbom"
    exit 1
  fi

  cp "$gt" "$out_dir/${prefix}.csv"
  cp "$sbom" "$out_dir/${prefix}.sbom.json"

  log "${prefix}: build completed in $((gt_end_ts - gt_start_ts))s"
  log "${prefix}: GT   -> $out_dir/${prefix}.csv"
  log "${prefix}: SBOM -> $out_dir/${prefix}.sbom.json"
}

gt_hash() {
  local gt_path="$1"

  poetry run python - "$gt_path" <<'PY'
import hashlib
import sys
from pathlib import Path
from evaluation.core.ground_truth import load_ground_truth

gt = load_ground_truth(Path(sys.argv[1]))
payload = sorted((g.ecosystem, g.component, g.version, g.cve or g.osv_id or "") for g in gt)
print(hashlib.sha256(str(payload).encode()).hexdigest())
PY
}

section "Loading environment"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/.env"

log "Looking for .env at: $ENV_FILE"
if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: .env file not found at $ENV_FILE"
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

log "Environment loaded"

section "Validating environment"
require_env CODEBASE
require_env EXPERIMENT_PATH
require_env NUM_RUNS
require_env GITHUB_TOKEN
require_env NVD_API_KEY

EVAL_TOOLS_EFFECTIVE="${EVAL_TOOLS:-dtrack oss-index github snyk trivy}"
case " ${EVAL_TOOLS_EFFECTIVE} " in
  *" dtrack "*)
    require_env DTRACK_URL
    require_env DTRACK_API_KEY
    ;;
esac

log "Environment OK"

RUN_ID="$(date -u +"%Y%m%dT%H%M%SZ")"
export RUN_ID

EXPERIMENT_DIR="${EXPERIMENT_PATH}/${RUN_ID}"
GROUND_TRUTH_ROOT="${EXPERIMENT_DIR}/ground_truth_build"
export EXPERIMENT_DIR
export GROUND_TRUTH_ROOT

mkdir -p "$EXPERIMENT_DIR"
mkdir -p "$GROUND_TRUTH_ROOT"

EXPERIMENT_LOG="${EXPERIMENT_DIR}/experiment.log"
touch "$EXPERIMENT_LOG"

EXPERIMENT_DATE="$(date '+%Y-%m-%d')"
EXPERIMENT_START_ISO="$(date '+%Y-%m-%d %H:%M:%S %Z')"
EXPERIMENT_START_TS="$(date +%s)"

log "RUN_ID=$RUN_ID"
log "RUN_DATE=$EXPERIMENT_DATE"
log "EXPERIMENT_START=$EXPERIMENT_START_ISO"
log "PROJECT_ROOT=$PROJECT_ROOT"
log "CODEBASE=$CODEBASE"
log "Experiment dir: $EXPERIMENT_DIR"
log "GROUND_TRUTH_ROOT=$GROUND_TRUTH_ROOT"

export DTRACK_PROJECT_NAME="eval_${RUN_ID}"
export DTRACK_PROJECT_VERSION="1.0"
log "[DTRACK] Project name: $DTRACK_PROJECT_NAME"

MAX_FULL_ATTEMPTS="${MAX_FULL_ATTEMPTS:-2}"
log "MAX_FULL_ATTEMPTS=${MAX_FULL_ATTEMPTS}"

section "Configuration"
log "EVAL_TOOLS=${EVAL_TOOLS_EFFECTIVE}"
log "NUM_RUNS=${NUM_RUNS}"
log "EXPERIMENT_PATH=${EXPERIMENT_PATH}"

if [ -n "${ECOSYSTEMS:-}" ]; then
  log "ECOSYSTEMS=${ECOSYSTEMS}"
fi
if [ -n "${SAMPLES:-}" ]; then
  log "SAMPLES=${SAMPLES}"
fi
if [ -n "${START_DATE:-}" ] || [ -n "${END_DATE:-}" ]; then
  log "DATE RANGE=${START_DATE:-<unset>} -> ${END_DATE:-<unset>}"
fi
if [ -n "${TARGET_VULNS_PER_ECOSYSTEM:-}" ]; then
  log "TARGET_VULNS_PER_ECOSYSTEM=${TARGET_VULNS_PER_ECOSYSTEM}"
fi
if [ -n "${BALANCE:-}" ]; then
  log "BALANCE=${BALANCE} (${BALANCE_STRATEGY:-<unset>})"
fi

section "Checking tool setup"
case " ${EVAL_TOOLS_EFFECTIVE} " in
  *" snyk "*)
    if ! command -v snyk >/dev/null 2>&1; then
      echo "ERROR: snyk CLI not installed"
      exit 1
    fi
    log "Snyk CLI available"
    ;;
esac

case " ${EVAL_TOOLS_EFFECTIVE} " in
  *" dtrack "*)
    if ! command -v jq >/dev/null 2>&1; then
      echo "ERROR: jq not installed"
      exit 1
    fi
    log "jq available"
    ;;
esac

section "Running temporal evaluation"

for i in $(seq 1 "$NUM_RUNS"); do
  RUN_DIR="${EXPERIMENT_DIR}/run_${i}"
  ATTEMPT=0
  RUN_ACCEPTED=0

  while [ "$ATTEMPT" -lt "$MAX_FULL_ATTEMPTS" ]; do
    ATTEMPT=$((ATTEMPT + 1))
    reset_run_dir "$RUN_DIR"

    ATTEMPT_START_ISO="$(date '+%Y-%m-%d %H:%M:%S %Z')"
    ATTEMPT_START_TS="$(date +%s)"

    GT_ATTEMPT_ROOT="${GROUND_TRUTH_ROOT}/run_${i}/attempt_${ATTEMPT}"
    GT0_BUILD_DIR="${GT_ATTEMPT_ROOT}/gt0/build"
    GT0_OUT_DIR="${GT_ATTEMPT_ROOT}/gt0"
    GT1_BUILD_DIR="${GT_ATTEMPT_ROOT}/gt1/build"
    GT1_OUT_DIR="${GT_ATTEMPT_ROOT}/gt1"

    log "Starting temporal run ${i}/${NUM_RUNS} (attempt ${ATTEMPT})"
    log "RUN_${i}_ATTEMPT_${ATTEMPT}_DATE=$(date '+%Y-%m-%d')"
    log "RUN_${i}_ATTEMPT_${ATTEMPT}_START=$ATTEMPT_START_ISO"

    build_ground_truth_snapshot "$GT0_BUILD_DIR" "$GT0_OUT_DIR" "ground_truth_gt0"

    GT0_PATH="$GT0_OUT_DIR/ground_truth_gt0.csv"
    SBOM_PATH="$GT0_OUT_DIR/ground_truth_gt0.sbom.json"
    GT0_HASH="$(gt_hash "$GT0_PATH")"

    export GROUND_TRUTH="$GT0_PATH"
    export SBOM_PATH
    export SNYK_SBOM_FILE="$SBOM_PATH"
    export TRIVY_SBOM_FILE="$SBOM_PATH"

    case " ${EVAL_TOOLS_EFFECTIVE} " in
      *" dtrack "*)
        log "Preparing Dependency-Track for temporal run ${i}, attempt ${ATTEMPT}"
        # shellcheck disable=SC1091
        source "${PROJECT_ROOT}/tools/dtrack_prepare.sh"

        if [ -z "${DTRACK_PROJECT_UUID:-}" ]; then
          echo "ERROR: DTRACK_PROJECT_UUID not exported by dtrack_prepare.sh"
          exit 1
        fi
        ;;
    esac

    if ! poetry run python -m evaluation.temporal_runner \
      --ground-truth "$GT0_PATH" \
      --output "$RUN_DIR"; then
      ATTEMPT_END_ISO="$(date '+%Y-%m-%d %H:%M:%S %Z')"
      ATTEMPT_END_TS="$(date +%s)"
      log "RUN_${i}_ATTEMPT_${ATTEMPT}_END=$ATTEMPT_END_ISO"
      log "RUN_${i}_ATTEMPT_${ATTEMPT}_DURATION_SECONDS=$((ATTEMPT_END_TS - ATTEMPT_START_TS))"
      log "Temporal run ${i} failed repeat consistency on attempt ${ATTEMPT} -> restarting from scratch"
      continue
    fi

    build_ground_truth_snapshot "$GT1_BUILD_DIR" "$GT1_OUT_DIR" "ground_truth_gt1"
    GT1_PATH="$GT1_OUT_DIR/ground_truth_gt1.csv"
    GT1_HASH="$(gt_hash "$GT1_PATH")"

    if [ "$GT0_HASH" != "$GT1_HASH" ]; then
      ATTEMPT_END_ISO="$(date '+%Y-%m-%d %H:%M:%S %Z')"
      ATTEMPT_END_TS="$(date +%s)"
      log "RUN_${i}_ATTEMPT_${ATTEMPT}_END=$ATTEMPT_END_ISO"
      log "RUN_${i}_ATTEMPT_${ATTEMPT}_DURATION_SECONDS=$((ATTEMPT_END_TS - ATTEMPT_START_TS))"
      log "Temporal run ${i} failed GT stability on attempt ${ATTEMPT} -> GT0 != GT1"
      continue
    fi

    cp "$GT0_PATH" "${EXPERIMENT_DIR}/ground_truth.csv"
    cp "$SBOM_PATH" "${EXPERIMENT_DIR}/sbom.json"
    export GROUND_TRUTH="${EXPERIMENT_DIR}/ground_truth.csv"
    export SBOM_PATH="${EXPERIMENT_DIR}/sbom.json"

    ATTEMPT_END_ISO="$(date '+%Y-%m-%d %H:%M:%S %Z')"
    ATTEMPT_END_TS="$(date +%s)"
    log "RUN_${i}_ATTEMPT_${ATTEMPT}_END=$ATTEMPT_END_ISO"
    log "RUN_${i}_ATTEMPT_${ATTEMPT}_DURATION_SECONDS=$((ATTEMPT_END_TS - ATTEMPT_START_TS))"
    log "Temporal run ${i} accepted on attempt ${ATTEMPT}"

    RUN_ACCEPTED=1
    break
  done

  if [ "$RUN_ACCEPTED" -ne 1 ]; then
    echo "ERROR: Temporal run ${i} failed after ${MAX_FULL_ATTEMPTS} full attempts"
    exit 1
  fi
done

section "Statistical analysis"

poetry run python - <<EOF
import json
from pathlib import Path

from evaluation.analysis.statistics import (
    aggregate,
    add_confidence_intervals,
    write_latex_stats,
    write_ecosystem_summary_table,
    build_gt_summary,
)
from evaluation.core.ground_truth import load_ground_truth

try:
    from evaluation.analysis.plots import plot_tool_comparison
except Exception:
    plot_tool_comparison = None

experiment_dir = Path("${EXPERIMENT_DIR}")
run_dirs = sorted(p for p in experiment_dir.glob("run_*") if p.is_dir())

data = []
for rd in run_dirs:
    result_file = rd / "results.json"
    if result_file.exists():
        with result_file.open("r", encoding="utf-8") as f:
            payload = json.load(f)
            if payload:
                data.append(payload)

if not data:
    print("[STATS] No run data found -> skipping aggregation")
    raise SystemExit(0)

agg = aggregate(data)
agg = add_confidence_intervals(agg)

gt = load_ground_truth(Path("${GROUND_TRUTH}"))
gt_summary = build_gt_summary(gt)

with (experiment_dir / "stats.json").open("w", encoding="utf-8") as f:
    json.dump({"metrics": agg}, f, indent=2)

write_latex_stats(
    agg,
    gt_summary,
    experiment_dir / "aggregated_results.tex"
)

write_ecosystem_summary_table(
    agg,
    gt_summary,
    experiment_dir / "ecosystem_summary.tex"
)

if plot_tool_comparison is not None:
    plot_tool_comparison(agg, str(experiment_dir))
    print("[STATS] Plot written")
else:
    print("[STATS] plot_tool_comparison not available -> plot skipped")

print("[STATS] Aggregation complete")
EOF

section "Finished"
EXPERIMENT_END_ISO="$(date '+%Y-%m-%d %H:%M:%S %Z')"
EXPERIMENT_END_TS="$(date +%s)"
log "EXPERIMENT_END=$EXPERIMENT_END_ISO"
log "EXPERIMENT_DURATION_SECONDS=$((EXPERIMENT_END_TS - EXPERIMENT_START_TS))"
log "Experiment completed"
log "Results stored in: $EXPERIMENT_DIR"