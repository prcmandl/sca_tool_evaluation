import requests
import time
import logging
from typing import Dict, List, Optional, Tuple, Set
import csv
import os
from pathlib import Path

from packaging.version import Version, InvalidVersion

from .api_call_tracker import ApiCallTracker


# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-5s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("build-ground-truth")


# ------------------------------------------------------------
# Place to put output
# ------------------------------------------------------------
GROUND_TRUTH_BUILD_PATH = os.environ["GROUND_TRUTH_BUILD_PATH"]

# ------------------------------------------------------------
# OSV Endpoints
# ------------------------------------------------------------

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"

# ------------------------------------------------------------
# PyPI URLs (REQUIRED by pypi collector)
# ------------------------------------------------------------

PYPI_TOP_URL = (
    "https://hugovk.github.io/top-pypi-packages/"
    "top-pypi-packages-30-days.json"
)

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"


# ------------------------------------------------------------
# Track all API Calls
# ------------------------------------------------------------
API_CALL_TRACKER = ApiCallTracker()

# ------------------------------------------------------------
# HTTP Helpers
# ------------------------------------------------------------

def request_json(
    url: str,
    payload: Optional[dict] = None,
    params: Optional[dict] = None,
    retries: int = 3,
    timeout: int = 30,
) -> dict:
    """
    Semantics identical to monolith:
    - POST if payload is given
    - GET otherwise
    """
    for attempt in range(retries):
        try:
            if payload is not None:
                r = requests.post(url, json=payload, timeout=timeout)
            else:
                r = requests.get(url, params=params, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if attempt == retries - 1:
                raise
            log.warning("request failed (%s), retrying...", e)
            time.sleep(1)

def request_json_with_retry(
    url,
    payload=None,
    headers=None,
    retries=None,
    timeout=30,
):
    """
    Perform an HTTP request (GET or POST) with retry logic.

    Semantics (backward compatible with existing code):
    - payload is None  -> HTTP GET
    - payload not None -> HTTP POST with JSON payload
    - retries defaults to 3 if not provided
    """

    import time
    import requests

    # --------------------------------------------------------
    # Defaults
    # --------------------------------------------------------
    if retries is None:
        retries = 3

    if headers is None:
        headers = {
            "Accept": "application/json",
        }

    last_exception = None

    # --------------------------------------------------------
    # Retry loop
    # --------------------------------------------------------
    for attempt in range(1, retries + 1):
        try:
            if payload is None:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                )
            else:
                response = requests.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=timeout,
                )

            # ------------------------------------------------
            # HTTP-level handling
            # ------------------------------------------------
            if response.status_code == 200:
                try:
                    return response.json()
                except ValueError:
                    # Invalid JSON response
                    return None

            # Retry on server-side errors
            if response.status_code >= 500:
                raise RuntimeError(
                    f"HTTP {response.status_code} from {url}"
                )

            # Client-side errors (4xx): do NOT retry
            return None

        except Exception as e:
            last_exception = e

            # Last attempt -> give up
            if attempt >= retries:
                break

            # Backoff before retry
            time.sleep(1.0 * attempt)

    # --------------------------------------------------------
    # Final failure
    # --------------------------------------------------------
    return None



# ------------------------------------------------------------
# Version Semantics (MONOLITH-COMPATIBLE)
# ------------------------------------------------------------

def is_stable(version: str) -> bool:
    """
    EXACT monolith semantics:
    uses packaging.version, not string heuristics
    """
    try:
        v = Version(version)
    except InvalidVersion:
        return False
    return not v.is_prerelease and not v.is_devrelease


def version_is_affected(vuln: dict, version: str) -> bool:
    """
    EXACT copy of monolith logic
    """
    try:
        v = Version(version)
    except InvalidVersion:
        return False

    def safe_version(s):
        try:
            return Version(s)
        except InvalidVersion:
            return None

    for a in vuln.get("affected", []):
        # explicit versions
        if version in a.get("versions", []):
            return True

        for r in a.get("ranges", []):
            if r.get("type") != "SEMVER":
                continue

            introduced = None
            for ev in r.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]

                elif "fixed" in ev:
                    fixed = ev["fixed"]

                    vi = safe_version(introduced) if introduced and introduced != "0" else None
                    vf = safe_version(fixed)

                    if vf is None:
                        introduced = None
                        continue

                    if (introduced == "0" or (vi and vi <= v)) and vf > v:
                        return True

                    introduced = None

            if introduced:
                vi = safe_version(introduced)
                if introduced == "0" or (vi and vi <= v):
                    return True

    return False

# ------------------------------------------------------------
# Advisory Expansion (MONOLITH)
# ------------------------------------------------------------

def expand_advisories(vuln: dict) -> List[Tuple[str, Optional[str]]]:
    vuln_id = vuln.get("id")
    aliases = vuln.get("aliases", []) or []
    cves = [a for a in aliases if a.startswith("CVE-")]

    if cves:
        return [(vuln_id, cve) for cve in cves]
    return [(vuln_id, None)]

# ------------------------------------------------------------
# Normalization / Identifiers
# ------------------------------------------------------------

def normalize_pypi_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def purl(ecosystem: str, name: str, version: str) -> str:
    eco = ecosystem.lower()
    if eco == "pypi":
        return f"pkg:pypi/{normalize_pypi_name(name)}@{version}"
    return f"pkg:{eco}/{name}@{version}"

# ------------------------------------------------------------
# Verification (MONOLITH)
# ------------------------------------------------------------

def verify_dataset_against_osv(rows: List[Dict]) -> None:
    log.info("=== verifying dataset against OSV ===")

    cache: Dict[str, dict] = {}
    mismatches = 0

    for r in rows:
        vid = r["vulnerability_id"]
        if vid not in cache:
            cache[vid] = request_json(OSV_VULN_URL.format(vuln_id=vid))
        vuln = cache[vid]

        if r["cve"] and r["cve"] not in (vuln.get("aliases") or []):
            log.error("CVE mismatch | %s", r)
            mismatches += 1
            continue

        if not version_is_affected(vuln, r["component_version"]):
            log.error("VERSION NOT AFFECTED | %s", r)
            mismatches += 1

    log.info("verification finished | mismatches=%d", mismatches)



# ------------------------------------------------------------
# Write List of candidates
# ------------------------------------------------------------

def write_candidate_coverage(
    ecosystem: str,
    candidate_coverage: dict,
    ts: str,
    component_count: int,
    cve_count: int,
):
    path = Path(GROUND_TRUTH_BUILD_PATH) / (
        f"{ecosystem}_ground_truth_dataset_{ts}_{component_count}_{cve_count}.candidates.csv"
    )

    tested = len(candidate_coverage)
    with_vulns = 0
    without_vulns = 0

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ecosystem",
            "component_name",
            "has_vulnerabilities",
            "vulnerability_count",
        ])

        for name, info in sorted(candidate_coverage.items()):
            has_v = bool(info["has_vulns"])
            if has_v:
                with_vulns += 1
            else:
                without_vulns += 1

            writer.writerow([
                ecosystem,
                name,
                has_v,
                info["vuln_count"],
            ])

    log.info(
        "%s candidates | tested=%d | with_vulns=%d | without_vulns=%d",
        ecosystem,
        tested,
        with_vulns,
        without_vulns,
    )

    log.info("| Candidate coverage written: %s", path)


from datetime import datetime
from typing import Optional

def within_date_window(
    published: Optional[datetime],
    start: Optional[datetime],
    end: Optional[datetime],
) -> bool:
    """
    Check whether a timestamp lies within the closed interval [start, end].

    All datetimes must be timezone-aware (UTC).
    If start or end is None, the interval is open on that side.
    """
    if published is None:
        return False

    if start and published < start:
        return False

    if end and published > end:
        return False

    return True

from datetime import datetime, timezone
from typing import Optional


def parse_iso_date(date_str: Optional[str]) -> Optional[datetime]:
    if date_str is None:
        return None
    return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)


import os
import logging

log = logging.getLogger(__name__)


def env_int(name: str, default: int) -> int:
    """
    Read an integer value from the environment.

    Semantics:
      - if the variable is unset: return default
      - if the variable is empty: return default
      - if the variable is not parseable as int: return default

    This function is intentionally silent to preserve reproducibility.
    """
    val = os.getenv(name)
    if val is None:
        return default

    val = val.strip()
    if val == "":
        return default

    try:
        return int(val)
    except ValueError:
        return default
