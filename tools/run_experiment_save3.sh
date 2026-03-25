#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# EXPERIMENT ORCHESTRATOR
# ============================================================
#
# PURPOSE
# ------------------------------------------------------------
# End-to-end orchestration for the simplified temporal SCA
# evaluation workflow.
#
# SIMPLIFIED WORKFLOW
# ------------------------------------------------------------
# For each independent run_i:
#
#   1) Build GT0 + SBOM
#   2) Evaluate all tools once   (repeat_1)
#   3) Evaluate all tools again  (repeat_2)
#   4) Build GT1 + SBOM
#   5) Compare GT0 vs GT1 and write comparison artifacts
#   6) Success only if:
#        - tool findings are identical across repeat_1/repeat_2
#        - GT0 == GT1
#   7) If tool findings differ, repeat the complete workflow
#      starting from GT creation at most one additional time
#   8) If GT0 != GT1, stop with a clear GT_MISMATCH status
#
# RETRY POLICY
# ------------------------------------------------------------
# Only TOOL_MISMATCH triggers a full retry.
# GT_MISMATCH does NOT trigger another retry.
#
# OUTPUT STRUCTURE
# ------------------------------------------------------------
# <EXPERIMENT_DIR>/
#   experiment.log
#   experiment_status.txt
#   ground_truth.csv
#   sbom.json
#   aggregated_results.tex
#   ecosystem_summary.tex
#   stats.json
#   tool_comparison.png
#
#   ground_truth_build/
#     run_<i>/
#       attempt_<j>/
#         gt0/
#           ground_truth_gt0.csv
#           ground_truth_gt0.sbom.json
#         gt1/
#           ground_truth_gt1.csv
#           ground_truth_gt1.sbom.json
#
#   run_<i>/
#     run.log
#     run_status.json
#     results.json
#     recall_significance.tex
#     recall_significance.json
#     recall_significance_matrix.png
#     aggregated_results.tex
#     ecosystem_summary.tex
#     tool_comparison.png
#     gt_comparison/
#       gt_diff_summary.json
#       gt_diff_report.txt
#       gt_diff_added.csv
#       gt_diff_removed.csv
#       gt_comparison_stdout.json
#     artifacts/
#       repeat_1/<tool>/...
#       repeat_2/<tool>/...
#
# DESIGN NOTES
# ------------------------------------------------------------
# - Tool-specific artifacts must be written directly into the
#   per-tool artifact directories. This is achieved inside the
#   Python temporal runner by:
#     * creating a tool-local working directory
#     * copying GT/SBOM into that directory
#     * setting output-related environment variables immediately
#       before each tool invocation
# - This shell script remains responsible for experiment-level
#   orchestration, GT generation, GT comparison, and final
#   aggregation.
#
# USAGE
# ------------------------------------------------------------
# bash tools/run_experiment_save3.sh
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
    "$run_dir/aggregated_results.tex" \
    "$run_dir/ecosystem_summary.tex" \
    "$run_dir/tool_comparison.png" \
    "$run_dir/run_status.json"

  rm -rf "$run_dir/artifacts"
  rm -rf "$run_dir/gt_comparison"
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

write_gt_comparison_artifacts() {
  local gt0_path="$1"
  local gt1_path="$2"
  local output_dir="$3"

  mkdir -p "$output_dir"

  poetry run python - "$gt0_path" "$gt1_path" "$output_dir" > "${output_dir}/gt_comparison_stdout.json" <<'PY'
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from evaluation.core.ground_truth import load_ground_truth


def row_key(f):
    vuln_id = f.cve or f.osv_id or ""
    return (f.ecosystem, f.component, f.version, vuln_id)


def expand_difference(a: Counter, b: Counter):
    out = []
    for key, count_a in a.items():
        count_b = b.get(key, 0)
        if count_a > count_b:
            out.extend([key] * (count_a - count_b))
    return out


def summarize(keys):
    stats = defaultdict(lambda: {"rows": 0, "components": set(), "vuln_ids": set()})
    for eco, comp, ver, vuln_id in keys:
        stats[eco]["rows"] += 1
        stats[eco]["components"].add((comp, ver))
        if vuln_id:
            stats[eco]["vuln_ids"].add(vuln_id)

    result = {}
    for eco, data in sorted(stats.items()):
        result[eco] = {
            "rows": data["rows"],
            "unique_components": len(data["components"]),
            "unique_vuln_ids": len(data["vuln_ids"]),
        }
    return result


def write_csv(path: Path, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ecosystem", "component", "version", "vuln_id"])
        for row in rows:
            writer.writerow(row)


gt0_path = Path(sys.argv[1])
gt1_path = Path(sys.argv[2])
out_dir = Path(sys.argv[3])
out_dir.mkdir(parents=True, exist_ok=True)

gt0 = load_ground_truth(gt0_path)
gt1 = load_ground_truth(gt1_path)

rows0 = [row_key(x) for x in gt0]
rows1 = [row_key(x) for x in gt1]

c0 = Counter(rows0)
c1 = Counter(rows1)

added = expand_difference(c1, c0)
removed = expand_difference(c0, c1)

s0 = set(c0.keys())
s1 = set(c1.keys())
shared = s0 & s1
union = s0 | s1

summary = {
    "gt0_path": str(gt0_path),
    "gt1_path": str(gt1_path),
    "gt0_total_rows": len(rows0),
    "gt1_total_rows": len(rows1),
    "gt0_unique_findings": len(s0),
    "gt1_unique_findings": len(s1),
    "shared_unique_findings": len(shared),
    "added_rows": len(added),
    "removed_rows": len(removed),
    "net_row_delta": len(rows1) - len(rows0),
    "jaccard_unique_findings": (len(shared) / len(union) if union else 1.0),
    "added_by_ecosystem": summarize(added),
    "removed_by_ecosystem": summarize(removed),
    "top_added_examples": [list(x) for x in added[:25]],
    "top_removed_examples": [list(x) for x in removed[:25]],
}

(out_dir / "gt_diff_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
write_csv(out_dir / "gt_diff_added.csv", added)
write_csv(out_dir / "gt_diff_removed.csv", removed)

with (out_dir / "gt_diff_report.txt").open("w", encoding="utf-8") as f:
    f.write("GROUND TRUTH DIFFERENCE REPORT\n")
    f.write("========================================\n\n")
    f.write(f"GT0: {gt0_path}\n")
    f.write(f"GT1: {gt1_path}\n\n")
    f.write(f"GT0 total rows:         {summary['gt0_total_rows']}\n")
    f.write(f"GT1 total rows:         {summary['gt1_total_rows']}\n")
    f.write(f"GT0 unique findings:    {summary['gt0_unique_findings']}\n")
    f.write(f"GT1 unique findings:    {summary['gt1_unique_findings']}\n")
    f.write(f"Shared unique findings: {summary['shared_unique_findings']}\n")
    f.write(f"Added rows:             {summary['added_rows']}\n")
    f.write(f"Removed rows:           {summary['removed_rows']}\n")
    f.write(f"Net row delta:          {summary['net_row_delta']}\n")
    f.write(f"Jaccard(unique):        {summary['jaccard_unique_findings']:.4f}\n\n")

    f.write("ADDED BY ECOSYSTEM\n")
    f.write("----------------------------------------\n")
    for eco, vals in summary["added_by_ecosystem"].items():
        f.write(
            f"{eco}: rows={vals['rows']}, components={vals['unique_components']}, vuln_ids={vals['unique_vuln_ids']}\n"
        )

    f.write("\nREMOVED BY ECOSYSTEM\n")
    f.write("----------------------------------------\n")
    for eco, vals in summary["removed_by_ecosystem"].items():
        f.write(
            f"{eco}: rows={vals['rows']}, components={vals['unique_components']}, vuln_ids={vals['unique_vuln_ids']}\n"
        )

print(json.dumps(summary, indent=2))
PY
}

write_run_status() {
  local path="$1"
  local status="$2"
  local message="$3"

  cat > "$path" <<EOFJSON
{
  "status": "${status}",
  "message": "${message}"
}
EOFJSON
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

MAX_TOOL_RETRIES="${MAX_TOOL_RETRIES:-1}"
TOTAL_ATTEMPTS=$((MAX_TOOL_RETRIES + 1))
log "MAX_TOOL_RETRIES=${MAX_TOOL_RETRIES}"
log "TOTAL_ATTEMPTS_PER_RUN=${TOTAL_ATTEMPTS}"

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
  RUN_ACCEPTED=0

  for ATTEMPT in $(seq 1 "$TOTAL_ATTEMPTS"); do
    reset_run_dir "$RUN_DIR"

    ATTEMPT_START_TS="$(date +%s)"
    log "Starting temporal run ${i}/${NUM_RUNS} (attempt ${ATTEMPT}/${TOTAL_ATTEMPTS})"

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
    poetry run python -m evaluation.temporal_runner \
      --ground-truth "$GT0_PATH" \
      --sbom "$SBOM_PATH" \
      --output "$RUN_DIR"
    RUNNER_RC=$?
    set -e

    if [ "$RUNNER_RC" -eq 2 ]; then
      ATTEMPT_END_TS="$(date +%s)"
      log "Temporal run ${i}: TOOL_MISMATCH on attempt ${ATTEMPT}"
      log "RUN_${i}_ATTEMPT_${ATTEMPT}_DURATION_SECONDS=$((ATTEMPT_END_TS - ATTEMPT_START_TS))"

      if [ "$ATTEMPT" -lt "$TOTAL_ATTEMPTS" ]; then
        log "Retrying full workflow for run_${i} because tool findings differ"
        continue
      fi

      write_run_status "${RUN_DIR}/run_status.json" \
        "TOOL_MISMATCH" \
        "Tool findings differ between repeat_1 and repeat_2 after all allowed attempts."
      echo "FAILED: TOOL_MISMATCH in run_${i}" > "${EXPERIMENT_DIR}/experiment_status.txt"
      exit 1
    elif [ "$RUNNER_RC" -ne 0 ]; then
      ATTEMPT_END_TS="$(date +%s)"
      log "Temporal run ${i}: TEMPORAL_RUNNER_ERROR on attempt ${ATTEMPT} (rc=${RUNNER_RC})"
      log "RUN_${i}_ATTEMPT_${ATTEMPT}_DURATION_SECONDS=$((ATTEMPT_END_TS - ATTEMPT_START_TS))"
      write_run_status "${RUN_DIR}/run_status.json" \
        "TEMPORAL_RUNNER_ERROR" \
        "Temporal runner failed with exit code ${RUNNER_RC}."
      echo "FAILED: TEMPORAL_RUNNER_ERROR in run_${i}" > "${EXPERIMENT_DIR}/experiment_status.txt"
      exit 1
    fi

    build_ground_truth_snapshot "$GT1_TMP_BUILD_DIR" "$GT1_OUT_DIR" "ground_truth_gt1"
    GT1_PATH="$GT1_OUT_DIR/ground_truth_gt1.csv"
    GT1_HASH="$(gt_hash "$GT1_PATH")"

    GT_COMPARE_DIR="${RUN_DIR}/gt_comparison"
    write_gt_comparison_artifacts "$GT0_PATH" "$GT1_PATH" "$GT_COMPARE_DIR"
    log "GT comparison artifacts written to: $GT_COMPARE_DIR"

    if [ "$GT0_HASH" != "$GT1_HASH" ]; then
      ATTEMPT_END_TS="$(date +%s)"
      log "Temporal run ${i}: GT_MISMATCH on attempt ${ATTEMPT}"
      log "RUN_${i}_ATTEMPT_${ATTEMPT}_DURATION_SECONDS=$((ATTEMPT_END_TS - ATTEMPT_START_TS))"
      write_run_status "${RUN_DIR}/run_status.json" \
        "GT_MISMATCH" \
        "GT0 and GT1 differ. See gt_comparison for details."
      echo "FAILED: GT_MISMATCH in run_${i}" > "${EXPERIMENT_DIR}/experiment_status.txt"
      exit 1
    fi

    cp "$GT0_PATH" "${EXPERIMENT_DIR}/ground_truth.csv"
    cp "$SBOM_PATH" "${EXPERIMENT_DIR}/sbom.json"

    export GROUND_TRUTH="${EXPERIMENT_DIR}/ground_truth.csv"
    export SBOM_PATH="${EXPERIMENT_DIR}/sbom.json"

    ATTEMPT_END_TS="$(date +%s)"
    log "Temporal run ${i} accepted on attempt ${ATTEMPT}"
    log "RUN_${i}_ATTEMPT_${ATTEMPT}_DURATION_SECONDS=$((ATTEMPT_END_TS - ATTEMPT_START_TS))"

    write_run_status "${RUN_DIR}/run_status.json" \
      "SUCCESS" \
      "Tool findings are stable across both repeats and GT0 equals GT1."

    RUN_ACCEPTED=1
    break
  done

  if [ "$RUN_ACCEPTED" -ne 1 ]; then
    echo "FAILED: run_${i}" > "${EXPERIMENT_DIR}/experiment_status.txt"
    exit 1
  fi
done

section "Statistical analysis"

poetry run python - <<PY
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
PY

echo "SUCCESS" > "${EXPERIMENT_DIR}/experiment_status.txt"

if plot_tool_comparison is not None:
    plot_tool_comparison(agg, str(experiment_dir))
PY

echo "SUCCESS" > "${EXPERIMENT_DIR}/experiment_status.txt"

# temporäres GT-Build-Verzeichnis entfernen
log "Removing temporary ground-truth build directory: ${TMP_GT_BUILD_ROOT}"
rm -rf "${TMP_GT_BUILD_ROOT}"


section "Finished"
log "Experiment completed"
log "Results stored in: $EXPERIMENT_DIR"