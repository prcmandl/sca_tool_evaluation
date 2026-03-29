#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] $*"
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "ERROR: Environment-Variable ${name} ist nicht gesetzt." >&2
    exit 1
  fi
}

ENV_FILE="${ENV_FILE:-/Users/petermandl/Documents/sca_tool_evaluation/sca_tool_evaluation/.env}"

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
else
  echo "ERROR: .env-Datei nicht gefunden: ${ENV_FILE}" >&2
  exit 1
fi

# Pflichtvariablen prüfen
require_env CODEBASE
require_env CODEBASE_BUILD_PATH
require_env REPORT_PATH
require_env EXPERIMENT_PATH
require_env RUN_ID
require_env RUN_NO
require_env REPEAT_NO
require_env GROUND_TRUTH_NAME
require_env VOTING_THRESHOLD

# Optionale Variablen mit Fallback
PYTHON_BIN="${PYTHON_BIN:-python3}"
VOTING_SCRIPT="${VOTING_SCRIPT:-${CODEBASE}/src/voting_evaluation/voting_from_evaluations_env.py}"

[[ -f "${VOTING_SCRIPT}" ]] || {
  echo "ERROR: Voting-Skript nicht gefunden: ${VOTING_SCRIPT}" >&2
  exit 1
}

EXPERIMENT_DIR="${EXPERIMENT_PATH}/${RUN_ID}"
[[ -d "${EXPERIMENT_DIR}" ]] || {
  echo "ERROR: Experiment-Verzeichnis nicht gefunden: ${EXPERIMENT_DIR}" >&2
  exit 1
}

ARTIFACT_BASE="${EXPERIMENT_DIR}/run_${RUN_NO}/artifacts/repeat_${REPEAT_NO}"

export DTRACK_EVAL_FILE="${ARTIFACT_BASE}/dtrack/${GROUND_TRUTH_NAME}_dtrack_evaluation.txt"
export GITHUB_EVAL_FILE="${ARTIFACT_BASE}/github/${GROUND_TRUTH_NAME}_github_evaluation.txt"
export OSS_INDEX_EVAL_FILE="${ARTIFACT_BASE}/oss-index/${GROUND_TRUTH_NAME}_oss-index_evaluation.txt"
export SNYK_EVAL_FILE="${ARTIFACT_BASE}/snyk/${GROUND_TRUTH_NAME}_snyk_evaluation.txt"
export TRIVY_EVAL_FILE="${ARTIFACT_BASE}/trivy/${GROUND_TRUTH_NAME}_trivy_evaluation.txt"

for f in \
  "${DTRACK_EVAL_FILE}" \
  "${GITHUB_EVAL_FILE}" \
  "${OSS_INDEX_EVAL_FILE}" \
  "${SNYK_EVAL_FILE}" \
  "${TRIVY_EVAL_FILE}"
do
  [[ -f "${f}" ]] || {
    echo "ERROR: Evaluationsdatei nicht gefunden: ${f}" >&2
    exit 1
  }
done

mkdir -p "${REPORT_PATH}/voting"

export VOTING_OUTPUT_TXT="${REPORT_PATH}/voting/${RUN_ID}_run${RUN_NO}_repeat${REPEAT_NO}_voting_${VOTING_THRESHOLD}of5.txt"

log "Starte Voting-Auswertung"
log "CODEBASE             : ${CODEBASE}"
log "EXPERIMENT_DIR       : ${EXPERIMENT_DIR}"
log "RUN_ID               : ${RUN_ID}"
log "RUN_NO               : ${RUN_NO}"
log "REPEAT_NO            : ${REPEAT_NO}"
log "GROUND_TRUTH_NAME    : ${GROUND_TRUTH_NAME}"
log "VOTING_THRESHOLD     : ${VOTING_THRESHOLD}/5"
log "VOTING_SCRIPT        : ${VOTING_SCRIPT}"
log "OUTPUT               : ${VOTING_OUTPUT_TXT}"

"${PYTHON_BIN}" "${VOTING_SCRIPT}"

log "Voting-Report geschrieben: ${VOTING_OUTPUT_TXT}"
