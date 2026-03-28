#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# EXPERIMENT RUNNER (SIMPLIFIED TEMPORAL WORKFLOW)
# ============================================================
#
# Ablauf pro unabhängigen Run:
#   1) GT0 erzeugen
#   2) Alle Tools einmal evaluieren
#   3) Alle Tools ein zweites Mal evaluieren
#   4) GT1 erzeugen
#   5) GT0 und GT1 vergleichen und Vergleichsdaten ausgeben
#   6) Wenn GT0 == GT1 und die Tool-Ergebnisse konsistent sind -> Erfolg
#   7) Wenn die Tool-Evaluationen nicht konsistent sind -> gesamten Vorgang
#      genau einmal wiederholen
#   8) Am Ende klare Statusmeldung: SUCCESS oder Fehlerursache
#
# Ausgabe:
#   <EXPERIMENT_DIR>/
#   ├── experiment.log
#   ├── experiment_status.txt
#   ├── ground_truth_build/
#   │   └── run_<i>/
#   │       └── attempt_<j>/
#   │           ├── gt0/
#   │           │   ├── ground_truth_gt0.csv
#   │           │   └── ground_truth_gt0.sbom.json
#   │           └── gt1/
#   │               ├── ground_truth_gt1.csv
#   │               └── ground_truth_gt1.sbom.json
#   ├── run_1/
#   │   ├── run.log
#   │   ├── temporal_consistency.json
#   │   ├── gt_comparison/
#   │   │   ├── gt_comparison_summary.json
#   │   │   ├── gt_only_in_gt0.csv
#   │   │   ├── gt_only_in_gt1.csv
#   │   │   └── gt_comparison_report.txt
#   │   ├── results.json
#   │   ├── recall_significance.tex
#   │   ├── recall_significance.json
#   │   ├── recall_significance_matrix.png
#   │   ├── aggregated_results.tex
#   │   ├── ecosystem_summary.tex
#   │   ├── tool_comparison.png
#   │   └── artifacts/
#   │       ├── repeat_1/<tool>/
#   │       └── repeat_2/<tool>/
#   └── ...
#
# Wichtige Architektur:
#   - Bash orchestriert nur den Gesamtfluss.
#   - Die Tool-Läufe erfolgen im temporal_runner_save5.py.
#   - Vor jedem Toolaufruf setzt temporal_runner_save5.py die Ausgabepfade auf
#     run_<x>/artifacts/repeat_<n>/<tool>/.
#
# ============================================================


if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: This script must be run with bash"
  exit 1
fi

EXPERIMENT_LOG=""

log() {
  local msg="[$(date '+%H:%M:%S %Z')] $*"
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
    "$run_dir/tool_comparison.png" \
    "$run_dir/run_status.json"

  rm -rf "$run_dir/artifacts"
  mkdir -p "$run_dir/artifacts"
}

build_ground_truth_snapshot() {
  local tmp_build_dir="$1"
  local out_dir="$2"
  local prefix="$3"

  rm -rf "$tmp_build_dir"
  mkdir -p "$tmp_build_dir"
  mkdir -p "$out_dir"

  export GROUND_TRUTH_BUILD_PATH="$tmp_build_dir"

  local gt_start_ts
  gt_start_ts="$(date +%s)"
  poetry run python -m ground_truth_generation.build_multi_ground_truth_dataset
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

  rm -rf "$tmp_build_dir"

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
TMP_GT_BUILD_ROOT="${EXPERIMENT_DIR}/.tmp_ground_truth_build"

export EXPERIMENT_DIR
export GROUND_TRUTH_ROOT
export TMP_GT_BUILD_ROOT

mkdir -p "$EXPERIMENT_DIR"
mkdir -p "$GROUND_TRUTH_ROOT"
mkdir -p "$TMP_GT_BUILD_ROOT"

EXPERIMENT_LOG="${EXPERIMENT_DIR}/experiment.log"
touch "$EXPERIMENT_LOG"

log "RUN_ID=$RUN_ID"
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

    ATTEMPT_START_TS="$(date +%s)"
    log "Starting temporal run ${i}/${NUM_RUNS} (attempt ${ATTEMPT})"

    GT_ATTEMPT_ROOT="${GROUND_TRUTH_ROOT}/run_${i}/attempt_${ATTEMPT}"

    GT0_OUT_DIR="${GT_ATTEMPT_ROOT}/gt0"
    GT1_OUT_DIR="${GT_ATTEMPT_ROOT}/gt1"

    GT0_TMP_BUILD_DIR="${TMP_GT_BUILD_ROOT}/run_${i}/attempt_${ATTEMPT}/gt0"
    GT1_TMP_BUILD_DIR="${TMP_GT_BUILD_ROOT}/run_${i}/attempt_${ATTEMPT}/gt1"

    build_ground_truth_snapshot "$GT0_TMP_BUILD_DIR" "$GT0_OUT_DIR" "ground_truth_gt0"

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
      --sbom "$SBOM_PATH" \
      --output "$RUN_DIR"; then
      ATTEMPT_END_TS="$(date +%s)"
      log "Temporal run ${i} failed during tool execution on attempt ${ATTEMPT}"
      log "RUN_${i}_ATTEMPT_${ATTEMPT}_DURATION_SECONDS=$((ATTEMPT_END_TS - ATTEMPT_START_TS))"
      continue
    fi

    build_ground_truth_snapshot "$GT1_TMP_BUILD_DIR" "$GT1_OUT_DIR" "ground_truth_gt1"
    GT1_PATH="$GT1_OUT_DIR/ground_truth_gt1.csv"
    GT1_HASH="$(gt_hash "$GT1_PATH")"

    if [ "$GT0_HASH" != "$GT1_HASH" ]; then
      GT_COMPARE_DIR="${RUN_DIR}/gt_comparison"
      mkdir -p "$GT_COMPARE_DIR"

      if poetry run python -m evaluation.orchestration.ground_truth_diff \
        --gt0 "$GT0_PATH" \
        --gt1 "$GT1_PATH" \
        --output-dir "$GT_COMPARE_DIR" \
        > "${GT_COMPARE_DIR}/gt_comparison_stdout.json"; then
        log "GT comparison artifacts written to: $GT_COMPARE_DIR"
      else
        log "WARNING: GT comparison generation failed"
      fi

      ATTEMPT_END_TS="$(date +%s)"
      log "Temporal run ${i} failed GT stability on attempt ${ATTEMPT} -> GT0 != GT1"
      log "RUN_${i}_ATTEMPT_${ATTEMPT}_DURATION_SECONDS=$((ATTEMPT_END_TS - ATTEMPT_START_TS))"
      continue
    fi

    cp "$GT0_PATH" "${EXPERIMENT_DIR}/ground_truth.csv"
    cp "$SBOM_PATH" "${EXPERIMENT_DIR}/sbom.json"

    export GROUND_TRUTH="${EXPERIMENT_DIR}/ground_truth.csv"
    export SBOM_PATH="${EXPERIMENT_DIR}/sbom.json"

    ATTEMPT_END_TS="$(date +%s)"
    log "Temporal run ${i} accepted on attempt ${ATTEMPT}"
    log "RUN_${i}_ATTEMPT_${ATTEMPT}_DURATION_SECONDS=$((ATTEMPT_END_TS - ATTEMPT_START_TS))"

    RUN_ACCEPTED=1
    break
  done

  if [ "$RUN_ACCEPTED" -ne 1 ]; then
    echo "ERROR: Temporal run ${i} failed after ${MAX_FULL_ATTEMPTS} full attempts"
    echo "FAILED: run_${i}" > "${EXPERIMENT_DIR}/experiment_status.txt"
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
EOF

echo "SUCCESS" > "${EXPERIMENT_DIR}/experiment_status.txt"

section "Finished"
log "Experiment completed"
log "Results stored in: $EXPERIMENT_DIR"
