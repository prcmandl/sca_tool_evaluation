#!/usr/bin/env bash
#set -euo pipefail
set +e
# ------------------------------------------------------------
# Argumente prüfen
# ------------------------------------------------------------
if [ "$#" -ne 1 ]; then
  echo " Usage: $0 tool ∈ {dtrack, evaltech, osv, github, nvd, snyk, fossa, oss-index, trivy}"
  exit 1
fi

if [ "$1" = "snyk" ]; then
  snyk whoami >/dev/null 2>&1 || \
    echo "WARNING: snyk auth not verified; SBOM scan may still work"
fi


# ------------------------------------------------------------
# Load .env (optional, lokal)
# ------------------------------------------------------------
if [ -f ".env" ]; then
  export $(grep -v '^#' .env | xargs)
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
require_env FOSSA_API_KEY
require_env OSSINDEX_TOKEN


# ------------------------------------------------------------
# Umgebungsvariablen (identisch zu Build-Script)
# ------------------------------------------------------------
# iMac
# export CODEBASE=/Users/petermandl/Documents/evaltech-report/evaltech-report_v3/evaltech-report
# MacBook
export CODEBASE=/Users/petermandl/Documents/sca_tool_evaluation/sca_tool_evaluation

export CODEBASE_BUILD_PATH="${CODEBASE}/build"
export GROUND_TRUTH_BUILD_PATH="${CODEBASE}/build/ground_truth"


# ------------------------------------------------------------
# For Dependency-Track Access
# ------------------------------------------------------------
export DTRACK_URL=http://dtrackapi.evaltech.de:8081
export DTRACK_API_KEY="odt_flPeugLK_xCkR2iqI3vO0w3odHTEIBLz2Fq7GoFLZ"


# Achtung: Die UUID muss mit dem Namen zusammenpassen, d. h. die erzeugte SBOM muss in das richtige Projekt geladen werden!!!

#export DTRACK_PROJECT_UUID=84898651-954e-4222-a317-570ff7480228
#export DTRACK_PROJECT_NAME=mixed_vulnerability_evaluation_00



export DTRACK_PROJECT_UUID=c11fe004-1dca-4e23-8ba2-bede5f7156cc
export DTRACK_PROJECT_NAME=mixed_vulnerability_evaluation_01

export DTRACK_PROJECT_UUID=507a9470-5e50-4529-967b-c2ac3a28bc2a
export DTRACK_PROJECT_NAME=mixed_vulnerability_evaluation_02

export DTRACK_PROJECT_UUID=4c659145-d376-4cea-bd59-3259eb40b3d7
export DTRACK_PROJECT_NAME=mixed_vulnerability_evaluation_04

export DTRACK_PROJECT_UUID=4c659145-d376-4cea-bd59-3259eb40b3d7
export DTRACK_PROJECT_NAME=tool_evaluation_589_1496

export DTRACK_PROJECT_UUID=69720014-b766-4d4e-ba56-e44fc925
export DTRACK_PROJECT_NAME=tool_evaluation_496_1224

export DTRACK_PROJECT_VERSION=1.0


# ------------------------------------------------------------
# OSV / GitHub Advisory APIs
# ------------------------------------------------------------
export OSV_ROOT_PATH=/Users/petermandl/Documents/OSV/OSV/vulnfeeds

# ------------------------------------------------------------
# NVD API
# -----------------------------------------------------------
# kommt aus .env, siehe require_env weiter oben


#-----------------------------------------------------------------------------------
# Parameter for FOSSA API
#-----------------------------------------------------------------------------------
# Vorher Projekt anlegen und SBOM hochladen
# erste SBOM: mixed_ground_truth_dataset_20260106T105731Z_198_64.sbom
export FOSSA_BASE_URL=https://app.fossa.com
# Suche Project Locator, letzter Teil nach dem Slasj = Project Id
export FOSSA_PROJECT_ID="sbom+59539/mixed_ground_truth_dataset_20260106T105731Z_198_64.sbom"
# Bei Einstellungen --> Integrations --> API --> keine Push API
# FOSSA_API_KEY kommt aus .env, siehe require_env weiter oben


#-----------------------------------------------------------------------------------
# Parameter for SNYK API; man benötigt snyk CLI lokal und kann dann über snyk Kommandos eine SBOM zur Prüfung
# hochladen. Es ist kein Projekt in der Web UI einzurichten, wenn man nur eine SBOM testen möchte
# Vorher muss man sich authentifizieren:
# > snyk auth
# > snyk sbom test --experimental --file=/Users/petermandl/Documents/evaltech-report/evaltech-report_v3/evaltech-report/build/ground_truth/mixed_ground_truth_dataset_20260106T105731Z_198_64.sbom.json --json
# Es wird alles in JSON-Format zurückgegeben, das man dann weiterverarbeiten kann
#-----------------------------------------------------------------------------------
export SNYK_BIN=/usr/local/bin/snyk
export BASH_PATH=/bin/bash
export SNYK_BASH_SCRIPT="${CODEBASE}/src/evaluation/evaluate_snyk.sh"


# Kleiner Datensatz zum Test
export SBOM_PATH="${GROUND_TRUTH_BUILD_PATH}/mixed_ground_truth_dataset_20260127T100343Z_97_165.sbom.json"

# Großer Datensatz
export SBOM_PATH="${GROUND_TRUTH_BUILD_PATH}/mixed_ground_truth_dataset_20260126T232109Z_496_1224.sbom.json"


# Kleiner Datensatz
export SBOM_PATH="${GROUND_TRUTH_BUILD_PATH}/mixed_ground_truth_dataset_20260127T135449Z_103_174.sbom.json"


export SNYK_SBOM_FILE=${SBOM_PATH}



#-----------------------------------------------------------------------------------
# OSS Index (Sonatype)
# Kennung unter https://www.sonatype.com
# Testkennung: prc.mandl@icloud.com
# User Token erzeugen unter https://ossindex.sonatype.org/user/settings
#-----------------------------------------------------------------------------------
export OSSINDEX_USERNAME="prc.mandl@icloud.com"
# OSSINDEX_TOKEN kommt aus .env, siehe require_env weiter oben

# ------------------------------------------------------------
# Ground_truth
# ------------------------------------------------------------

export GROUND_TRUTH=${GROUND_TRUTH_BUILD_PATH}/mixed_ground_truth_dataset_20260320T091626Z_11_12.csv

TOOL="$1"

if [ -z "$TOOL" ]; then
  echo "Usage: $0 <tool>"
  exit 1
fi

echo "=== Running evaluation ==="
echo "Ground truth: ${GROUND_TRUTH}"
echo "Tool:         ${TOOL}"
echo

poetry run python -m evaluation.evaluate \
  --ground-truth "${GROUND_TRUTH}" \
  --tool "${TOOL}"

EVAL_RC=$?


if [ $EVAL_RC -ne 0 ]; then
  echo
  echo "=== Evaluation failed (exit code ${EVAL_RC}) ==="
  echo "Skipping findings analysis."
  exit $EVAL_RC
fi

echo
echo "=== Evaluation successful ==="