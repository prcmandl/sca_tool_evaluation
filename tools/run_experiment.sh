#!/usr/bin/env bash
set -euo pipefail

if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: This script must be run with bash"
  exit 1
fi

EXPERIMENT_LOG=""

cleanup() {
  if [ -n "${TMP_GT_BUILD_ROOT:-}" ] && [ -d "${TMP_GT_BUILD_ROOT:-}" ]; then
    rm -rf "${TMP_GT_BUILD_ROOT}"
  fi
}
trap cleanup EXIT
log() {
  local msg="[$(date '+%H:%M:%S %Z')] $*"
  echo "$msg"
}

section() {
  local line="============================================================"
  echo
  echo "$line"
  echo "$*"
  echo "$line"
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
  rm -f     "$run_dir/run.log"     "$run_dir/results.json"     "$run_dir/recall_significance.tex"     "$run_dir/recall_significance.json"     "$run_dir/recall_significance_matrix.png"     "$run_dir/significance_matrix.png"     "$run_dir/aggregated_results.tex"     "$run_dir/ecosystem_summary.tex"     "$run_dir/tool_comparison.png"     "$run_dir/tool_comparison.tex"     "$run_dir/tool_repeat_comparison.json"     "$run_dir/tool_repeat_comparison.txt"     "$run_dir/tool_comparison_summary.json"     "$run_dir/tool_comparison_summary.txt"     "$run_dir/run_status.json"

  rm -rf "$run_dir/artifacts"
  mkdir -p "$run_dir/artifacts"
}

copy_optional_sidecars() {
  local gt_csv="$1"
  local out_dir="$2"
  local prefix="$3"

  local base="${gt_csv%.csv}"

  # explizite Kandidaten
  local candidates=(
    "${base}.stat.txt"
    "${base}.txt"
    "${base}.log"
    "${base}.json"
  )

  for src in "${candidates[@]}"; do
    if [ -f "$src" ]; then
      local suffix="${src#$base}"
      cp "$src" "$out_dir/${prefix}${suffix}"
    fi
  done
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
  copy_optional_sidecars "$gt" "$out_dir" "$prefix"

  rm -rf "$tmp_build_dir"

  log "${prefix}: build completed in $((gt_end_ts - gt_start_ts))s"
  log "${prefix}: GT   -> $out_dir/${prefix}.csv"
  log "${prefix}: SBOM -> $out_dir/${prefix}.sbom.json"
}

gt_hash() {
  local gt_path="$1"

  poetry run python "$GT_HASH_SCRIPT" "$gt_path"
}

section "Loading environment"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GT_HASH_SCRIPT="${PROJECT_ROOT}/tools/gt_hash.py"
AGGREGATE_EXPERIMENT_SCRIPT="${PROJECT_ROOT}/tools/aggregate_experiment.py"
ENV_FILE="${PROJECT_ROOT}/.env"

if [ ! -f "$GT_HASH_SCRIPT" ]; then
  echo "ERROR: Missing helper script: $GT_HASH_SCRIPT"
  exit 1
fi

if [ ! -f "$AGGREGATE_EXPERIMENT_SCRIPT" ]; then
  echo "ERROR: Missing helper script: $AGGREGATE_EXPERIMENT_SCRIPT"
  exit 1
fi

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
export EVAL_TOOLS="${EVAL_TOOLS_EFFECTIVE}"

mkdir -p "$EXPERIMENT_DIR"
mkdir -p "$GROUND_TRUTH_ROOT"
mkdir -p "$TMP_GT_BUILD_ROOT"

EXPERIMENT_LOG="${EXPERIMENT_DIR}/${RUN_ID}.log"
touch "$EXPERIMENT_LOG"
exec > >(tee -a "$EXPERIMENT_LOG") 2>&1

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

    set +e
    poetry run python -m evaluation.temporal_runner       --ground-truth "$GT0_PATH"       --sbom "$SBOM_PATH"       --output "$RUN_DIR"
    TEMPORAL_STATUS=$?

    set -e

    if [ "$TEMPORAL_STATUS" -eq 2 ]; then
        log "[RETRY] Tool failure detected (likely empty results)"
    fi

    if [ "$TEMPORAL_STATUS" -ne 0 ]; then
      ATTEMPT_END_TS="$(date +%s)"

      if [ "$TEMPORAL_STATUS" -eq 2 ]; then
        log "Temporal run ${i} detected tool mismatch on attempt ${ATTEMPT}; retrying full attempt"
        log "RUN_${i}_ATTEMPT_${ATTEMPT}_DURATION_SECONDS=$((ATTEMPT_END_TS - ATTEMPT_START_TS))"
        continue
      fi

      log "Temporal run ${i} failed with hard error (exit=${TEMPORAL_STATUS}) on attempt ${ATTEMPT}"
      log "RUN_${i}_ATTEMPT_${ATTEMPT}_DURATION_SECONDS=$((ATTEMPT_END_TS - ATTEMPT_START_TS))"
      echo "FAILED: run_${i} hard error on attempt ${ATTEMPT} (exit=${TEMPORAL_STATUS})" > "${EXPERIMENT_DIR}/experiment_status.txt"
      exit "$TEMPORAL_STATUS"
    fi

    build_ground_truth_snapshot "$GT1_TMP_BUILD_DIR" "$GT1_OUT_DIR" "ground_truth_gt1"
    GT1_PATH="$GT1_OUT_DIR/ground_truth_gt1.csv"
    GT1_HASH="$(gt_hash "$GT1_PATH")"

    # Compare GT0 with GT1 and generate diff artifacts if they differ
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

    # ------------------------------------------------------------
    # ALWAYS perform GT comparison
    # ------------------------------------------------------------
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

    echo "$GT0_HASH" > "${GT_COMPARE_DIR}/gt0.hash"
    echo "$GT1_HASH" > "${GT_COMPARE_DIR}/gt1.hash"

    # ------------------------------------------------------------
    # check stability of GT (UNVERÄNDERT)
    # ------------------------------------------------------------
    if [ "$GT0_HASH" != "$GT1_HASH" ]; then
      ATTEMPT_END_TS="$(date +%s)"
      log "Temporal run ${i} failed GT stability on attempt ${ATTEMPT} -> GT0 != GT1"
      log "RUN_${i}_ATTEMPT_${ATTEMPT}_DURATION_SECONDS=$((ATTEMPT_END_TS - ATTEMPT_START_TS))"
      continue
    fi

    cp "$GT0_PATH" "${EXPERIMENT_DIR}/ground_truth.csv"
    cp "$SBOM_PATH" "${EXPERIMENT_DIR}/sbom.json"
    copy_optional_sidecars "$GT0_PATH" "${EXPERIMENT_DIR}" "ground_truth"

    export GROUND_TRUTH="${EXPERIMENT_DIR}/ground_truth.csv"
    export SBOM_PATH="${EXPERIMENT_DIR}/sbom.json"
    export SNYK_SBOM_FILE="${EXPERIMENT_DIR}/sbom.json"
    export TRIVY_SBOM_FILE="${EXPERIMENT_DIR}/sbom.json"

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

poetry run python "$AGGREGATE_EXPERIMENT_SCRIPT" \
  --experiment-dir "$EXPERIMENT_DIR" \
  --ground-truth "$GROUND_TRUTH"

echo "SUCCESS" > "${EXPERIMENT_DIR}/experiment_status.txt"

section "Finished"
log "Experiment completed"
log "Results stored in: $EXPERIMENT_DIR"
