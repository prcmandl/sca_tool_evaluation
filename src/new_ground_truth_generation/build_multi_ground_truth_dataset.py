#!/usr/bin/env python3
import json
import logging
import os
import re
from datetime import datetime, timezone

from new_ground_truth_generation.statistics import write_statistics

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-5s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("build_multi_ground_truth")

from new_ground_truth_generation.osv_common import request_json, env_int

# ------------------------------------------------------------
# Imports from ecosystem collectors
# ------------------------------------------------------------

from new_ground_truth_generation.ecosystems.pypi import collect_pypi
from new_ground_truth_generation.ecosystems.npm import collect_npm
from new_ground_truth_generation.ecosystems.maven import collect_maven
from new_ground_truth_generation.ecosystems.nuget import collect_nuget

# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------

SUPPORTED_ECOSYSTEMS = {"pypi", "npm", "maven", "nuget"}

# ------------------------------------------------------------
# PyPI ground truth time window (explicit, reproducible)
# ------------------------------------------------------------
#
# These dates define the release window for PyPI versions
# included in the OSV ground truth.
#
# Set to None to disable filtering.
#

START_DATE = "2018-01-01"
END_DATE = "2025-12-31"


# ------------------------------------------------------------
# OSV vulnerability detail lookup
# ------------------------------------------------------------

OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# ------------------------------------------------------------
# Place where to put output
# ------------------------------------------------------------

GROUND_TRUTH_BUILD_PATH = os.environ["GROUND_TRUTH_BUILD_PATH"]

_vuln_detail_cache = {}


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def compute_global_counts(all_rows):
    # unique components := (ecosystem, component_name, component_version)
    unique_components = {
        (r["ecosystem"], r["component_name"], r["component_version"])
        for r in all_rows
    }
    component_count = len(unique_components)

    # after canonicalization: each row is one OSV vulnerability entry
    osv_vuln_entries = len(all_rows)

    return component_count, osv_vuln_entries

def normalize_description(text: str) -> str:
    """
    Normalize vulnerability description:
    - remove newlines, tabs, control characters
    - collapse whitespace
    - limit length
    """
    if not text:
        return ""

    # Remove control characters
    text = re.sub(r"[\r\n\t\f\v]+", " ", text)

    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()

    # Hard length limit (CSV-friendly, DT-friendly)
    return text[:300]


def get_vulnerability_description(vuln_id: str) -> str:
    """
    Prefer short CVE-style description:
    1) OSV summary
    2) first sentence of details
    """
    if vuln_id not in _vuln_detail_cache:
        _vuln_detail_cache[vuln_id] = request_json(
            OSV_VULN_URL.format(vuln_id=vuln_id)
        )

    v = _vuln_detail_cache[vuln_id]

    text = v.get("summary")
    if not text:
        details = v.get("details", "")
        # Take first sentence as fallback
        text = details.split(".")[0]

    return normalize_description(text)


def compute_pre_balance_stats(rows):
    stats = defaultdict(lambda: {
        "rows": 0,
        "components": set(),
    })

    for r in rows:
        eco = (r.get("ecosystem") or "").strip().lower()
        stats[eco]["rows"] += 1

        stats[eco]["components"].add(
            (
                (r.get("component_name") or "").strip(),
                str(r.get("component_version") or "").strip(),
            )
        )

    for eco, s in stats.items():
        s["unique_components"] = len(s["components"])
        del s["components"]

    return stats



def utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def count_samples(rows):
    return len({
        (r["ecosystem"], r["component_name"], r["component_version"])
        for r in rows
    })


def sanitize_description(text: str, max_len: int = 240) -> str:
    """
    Make vulnerability description short, single-line and CSV-safe.
    Preference: CVE/OSV summaries.
    """
    if not text:
        return ""

    cleaned = (
        str(text)
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("\t", " ")
    )
    cleaned = " ".join(cleaned.split())

    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 1].rstrip() + "…"

    return cleaned

def _stable_row_key(r):
    return (
        (r.get("ecosystem") or "").strip().lower(),
        (r.get("component_name") or "").strip().lower(),
        str(r.get("component_version") or "").strip(),
        (r.get("vulnerability_id") or "").strip().lower(),
        (r.get("cve") or "").strip().lower(),
    )

def _component_key(r):
    return (
        (r.get("component_name") or "").strip().lower(),
        str(r.get("component_version") or "").strip(),
    )


from collections import defaultdict


def _stable_row_key(r):
    return (
        (r.get("ecosystem") or "").strip().lower(),
        (r.get("component_name") or "").strip().lower(),
        str(r.get("component_version") or "").strip(),
        (r.get("vulnerability_id") or "").strip().lower(),
        (r.get("cve") or "").strip().lower(),
    )

def _component_key(r):
    return (
        (r.get("component_name") or "").strip().lower(),
        str(r.get("component_version") or "").strip(),
    )

# --------------------------------------------------------
# Validate & enrich against OSV (HARD)
# --------------------------------------------------------

def verify_dataset_against_osv(rows, osv_cache):
        log.info("=== verifying dataset against OSV (OFFLINE, CACHED) ===")

        validated = []
        errors = 0

        for idx, r in enumerate(rows, 1):
            eco = r["ecosystem"]
            comp = r["component_name"]
            ver = r["component_version"]
            vuln_id = r["vulnerability_id"]

            cache_key = (eco, comp, ver)
            res = osv_cache.get(cache_key)

            if res is None:
                raise RuntimeError(
                    f"Missing OSV cache entry for {cache_key}"
                )

            osv_ids = {v["id"] for v in res.get("vulns", [])}

            if vuln_id not in osv_ids:
                errors += 1
                log.error(
                    "[%d] INVALID ENTRY | ecosystem=%s | component=%s | version=%s | vuln_id=%s",
                    idx, eco, comp, ver, vuln_id,
                )
                continue

            validated.append(r)

        if errors > 0:
            raise RuntimeError(
                f"Ground truth validation failed: {errors} invalid entries detected"
            )

        log.info(
            "validation successful | rows=%d",
            len(validated),
        )

        return validated

# ------------------------------------------------------------
# SBOM generation and validation
# ------------------------------------------------------------

def validate_cyclonedx_sbom(bom: dict) -> None:
    """
    Validate a CycloneDX SBOM (JSON) using the official strict validator.

    Correct usage for cyclonedx-python-lib >= 5.x:
    - SchemaVersion enum
    - JSON string via validate_str()
    """
    import json
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    try:
        bom_json = json.dumps(bom)

        # IMPORTANT: schema version must be the enum, not a string
        validator = JsonStrictValidator(SchemaVersion.V1_5)

        validator.validate_str(bom_json)

        log.info("SBOM is CycloneDX 1.5 conformant")

    except ImportError as e:
        log.error(
            "CycloneDX validation requested but cyclonedx-python-lib is not installed",
            exc_info=e,
        )
        raise

    except Exception as e:
        log.error(
            "Generated SBOM is NOT CycloneDX-conformant",
            exc_info=e,
        )
        raise






def build_sbom(
    rows,
    dataset_type: str,
    timestamp: str,
    component_count: int,
    vulnerability_count: int,
    *,
    out_path: str,
    validate: bool = True,
):
    """
    Build a CycloneDX SBOM that works for both Snyk and Dependency-Track.

    - component-centric (not vulnerability-centric)
    - stable bom-ref = purl
    - Maven hashes included (SHA-1 / SHA-256 if available)
    - no vulnerabilities embedded
    - optional CycloneDX 1.5 schema validation
    """

    import json
    from collections import OrderedDict
    from datetime import datetime, timezone

    log.info("Building SBOM (component-centric)")

    # ------------------------------------------------------------
    # Step 1: Deduplicate components (rows are dicts)
    # ------------------------------------------------------------
    components = OrderedDict()

    for r in rows:
        ecosystem = r.get("ecosystem")
        name = r.get("component_name")
        version = r.get("component_version")
        purl = r.get("purl")

        if not ecosystem or not name or not version or not purl:
            continue

        key = (ecosystem, name, version, purl)
        if key not in components:
            components[key] = r

    log.info(
        "SBOM component set prepared | unique_components=%d",
        len(components),
    )

    # ------------------------------------------------------------
    # Step 2: Build CycloneDX components
    # ------------------------------------------------------------
    bom_components = []
    dependencies = []

    for (ecosystem, name, version, purl), r in components.items():
        comp = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
        }

        # Maven-specific enrichment (critical for Dependency-Track)
        if ecosystem == "maven":
            hashes = []
            if r.get("hash_sha1"):
                hashes.append({
                    "alg": "SHA-1",
                    "content": r["hash_sha1"],
                })
            if r.get("hash_sha256"):
                hashes.append({
                    "alg": "SHA-256",
                    "content": r["hash_sha256"],
                })
            if hashes:
                comp["hashes"] = hashes

        # NuGet: keep canonical casing
        if ecosystem == "nuget":
            comp["name"] = name
            comp["purl"] = purl

        bom_components.append(comp)

        # Minimal but valid dependency graph
        dependencies.append({
            "ref": purl,
            "dependsOn": [],
        })

    # ------------------------------------------------------------
    # Step 3: Assemble SBOM
    # ------------------------------------------------------------
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": f"{dataset_type}-ground-truth",
                "properties": [
                    {"name": "dataset.type", "value": dataset_type},
                    {"name": "dataset.timestamp", "value": timestamp},
                    {"name": "dataset.components", "value": str(component_count)},
                    {"name": "dataset.vulnerabilities", "value": str(vulnerability_count)},
                ],
            },
        },
        "components": bom_components,
        "dependencies": dependencies,
    }

    # ------------------------------------------------------------
    # Step 4: CycloneDX validation (strict, logged)
    # ------------------------------------------------------------
    if validate:
        log.info("Validating SBOM against CycloneDX 1.5 schema")
        validate_cyclonedx_sbom(bom)

    # ------------------------------------------------------------
    # Step 5: Write SBOM to disk
    # ------------------------------------------------------------
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(bom, f, indent=2)

    log.info("SBOM written | path=%s", out_path)

    return out_path





def compute_ecosystem_stats(rows):
    stats = defaultdict(lambda: {
        "components": set(),
        "vulnerabilities": 0,
    })

    for r in rows:
        eco = (r.get("ecosystem") or "").strip().lower()

        stats[eco]["components"].add(
            (
                (r.get("component_name") or "").strip(),
                str(r.get("component_version") or "").strip(),
            )
        )
        stats[eco]["vulnerabilities"] += 1

    return stats


def write_ground_truth_meta(
        *,
        output_csv_path,
        ecosystem_stats,
        total_vulnerabilities: int,
) -> None:
    start_date = os.environ.get("START_DATE")
    end_date = os.environ.get("END_DATE")

    meta = {
        "schema_version": "1.1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": "osv",
        "osv_query_mode": "component+version",
        "time_window": {
            "start_date": start_date,
            "end_date": end_date,
        },

        "osv_snapshot_note": (
            "Ground truth is time-fixed and constrained to the given time window. "
            "OSV vulnerabilities published outside this window or added after "
            "dataset creation are not part of the ground truth."
        ),

        "components_total": sum(
            len(v["components"]) for v in ecosystem_stats.values()
        ),
        "vulnerabilities_total": total_vulnerabilities,

        "ecosystem_breakdown": {
            eco: {
                "components": len(data["components"]),
                "vulnerabilities": data["vulnerabilities"],
            }
            for eco, data in ecosystem_stats.items()
        },
    }

    meta_path = output_csv_path.with_suffix(".meta.json")

    with meta_path.open("w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, sort_keys=True)

def balance_rows_by_vulnerability_deterministic(
    rows,
    ecosystems,
    strategy="min",
):
    from collections import defaultdict, deque, Counter
    from statistics import median

    by_eco = defaultdict(list)
    for r in rows:
        eco = (r.get("ecosystem") or "").strip().lower()
        if eco in ecosystems:
            by_eco[eco].append(r)

    counts = {eco: len(v) for eco, v in by_eco.items() if v}
    if not counts:
        raise RuntimeError("No data to balance")

    if strategy == "min":
        target = min(counts.values())
    elif strategy == "median":
        target = int(median(counts.values()))
    else:
        raise ValueError(f"Unknown strategy: {strategy}")

    balanced = []
    stats = {}

    for eco in ecosystems:
        eco_rows = by_eco.get(eco, [])

        if not eco_rows:
            stats[eco] = {
                "original_rows": 0,
                "kept_rows": 0,
                "target": target,
                "unique_components": 0,
                "unique_component_versions": 0,
            }
            continue

        groups = defaultdict(list)
        comp_counter = Counter()

        for r in eco_rows:
            comp = r.get("component_name")
            ver = r.get("component_version")
            key = (comp, ver)

            groups[key].append(r)
            comp_counter[comp] += 1

        ordered_groups = []

        for (comp, ver), items in groups.items():
            items_sorted = sorted(
                items,
                key=lambda r: (
                    str(r.get("vulnerability_id") or ""),
                    str(r.get("cve") or ""),
                ),
            )

            ordered_groups.append((
                len(items_sorted),
                comp_counter[comp],
                (comp or "").lower(),
                str(ver),
                deque(items_sorted),
            ))

        ordered_groups.sort(key=lambda x: (x[0], x[1], x[2], x[3]))

        active = [g[4] for g in ordered_groups]
        selected = []

        while len(selected) < target and active:
            next_active = []

            for q in active:
                if len(selected) >= target:
                    break

                if q:
                    selected.append(q.popleft())

                if q:
                    next_active.append(q)

            active = next_active

        balanced.extend(selected)

        stats[eco] = {
            "original_rows": len(eco_rows),
            "kept_rows": len(selected),
            "target": target,
            "unique_components": len({r["component_name"] for r in selected}),
            "unique_component_versions": len({
                (r["component_name"], r["component_version"]) for r in selected
            }),
        }

    return balanced, stats

def cap_per_component(rows, max_per_component=10):
    from collections import defaultdict

    out = []
    counter = defaultdict(int)

    for r in rows:
        key = (r.get("ecosystem"), r.get("component_name"))

        if counter[key] < max_per_component:
            out.append(r)
            counter[key] += 1

    return out

def compute_balance_validation(rows):
    from collections import Counter, defaultdict
    from statistics import median

    by_eco = defaultdict(list)

    for r in rows:
        by_eco[(r.get("ecosystem") or "").lower()].append(r)

    result = {}

    for eco, eco_rows in by_eco.items():
        comp_counter = Counter(r["component_name"] for r in eco_rows)
        comp_ver_counter = Counter(
            (r["component_name"], r["component_version"]) for r in eco_rows
        )

        total = len(eco_rows)
        comp_counts = sorted(comp_counter.values(), reverse=True)

        result[eco] = {
            "rows": total,
            "unique_components": len(comp_counter),
            "unique_versions": len(comp_ver_counter),
            "median_per_component": median(comp_counter.values()) if comp_counter else 0,
            "max_per_component": max(comp_counter.values()) if comp_counter else 0,
            "top1_share": comp_counts[0] / total if total else 0,
            "top5_share": sum(comp_counts[:5]) / total if total else 0,
        }

    return result

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------


def main():
    import csv
    import os
    from pathlib import Path
    from collections import defaultdict

    # ====================================================
    # Read configuration from environment (single source)
    # ====================================================

    if "SAMPLES" not in os.environ:
        raise RuntimeError("Missing required environment variable: SAMPLES")

    if "ECOSYSTEMS" not in os.environ:
        raise RuntimeError("Missing required environment variable: ECOSYSTEMS")

    samples = int(os.environ["SAMPLES"])
    ecosystems = os.environ["ECOSYSTEMS"].split()

    balance = os.environ.get("BALANCE", "false").lower() in {"1", "true", "yes", "on"}
    balance_strategy = os.environ.get("BALANCE_STRATEGY", "min")
    min_unique_component_ratio = float(
        os.environ.get("MIN_UNIQUE_COMPONENT_RATIO", "0.5")
    )

    start_date = os.environ.get("START_DATE", START_DATE)
    end_date = os.environ.get("END_DATE", END_DATE)

    if balance_strategy not in {"min", "median"}:
        raise ValueError(
            f"Invalid BALANCE_STRATEGY={balance_strategy} "
            "(expected 'min' or 'median')"
        )

    for eco in ecosystems:
        if eco not in SUPPORTED_ECOSYSTEMS:
            raise ValueError(f"Unsupported ecosystem: {eco}")

    ts = utc_ts()
    all_rows = []

    # --------------------------------------------------------
    # OSV cache
    # --------------------------------------------------------
    osv_cache = {}

    # --------------------------------------------------------
    # Collect per ecosystem
    # --------------------------------------------------------
    for eco in ecosystems:
        log.info("=== collecting %s ===", eco)

        if eco == "pypi":
            rows = collect_pypi(
                samples=samples,
                start_date=start_date,
                end_date=end_date,
                osv_cache=osv_cache,
            )
        elif eco == "npm":
            rows = collect_npm(
                samples=samples,
                start_date=start_date,
                end_date=end_date,
                osv_cache=osv_cache,
            )
        elif eco == "maven":
            rows = collect_maven(
                samples=samples,
                start_date=start_date,
                end_date=end_date,
                osv_cache=osv_cache,
            )
        elif eco == "nuget":
            rows = collect_nuget(
                samples=samples,
                start_date=start_date,
                end_date=end_date,
                osv_cache=osv_cache,
            )
        else:
            raise ValueError(eco)

        all_rows.extend(rows)

    if not all_rows:
        log.warning("No samples collected — writing empty dataset")

        # trotzdem leere CSV schreiben
        build_dir = Path(GROUND_TRUTH_BUILD_PATH)
        build_dir.mkdir(parents=True, exist_ok=True)

        base_name = f"empty_dataset_{utc_ts()}"

        csv_path = build_dir / f"{base_name}.csv"

        import csv
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "ecosystem",
                    "component_name",
                    "component_version",
                    "purl",
                    "vulnerability_id",
                    "cve",
                    "vulnerability_description",
                    "is_vulnerable",
                ],
            )
            writer.writeheader()

        log.warning(f"Empty dataset written to {csv_path}")
        return

    # --------------------------------------------------------
    # Enrich rows with vulnerability descriptions
    # --------------------------------------------------------
    for r in all_rows:
        r["vulnerability_description"] = get_vulnerability_description(
            r["vulnerability_id"]
        )

    # --------------------------------------------------------
    # Canonicalize OSV vulnerabilities
    # --------------------------------------------------------
    canonical = {}
    for r in all_rows:
        key = (
            r["ecosystem"],
            r["component_name"],
            r["component_version"],
            r["vulnerability_id"],
        )
        if key not in canonical:
            canonical[key] = r

    all_rows = list(canonical.values())

    # --------------------------------------------------------
    # Preserve RAW rows for pre-balancing statistics
    # --------------------------------------------------------
    raw_rows = list(all_rows)

    # --------------------------------------------------------
    # HARD CAP (SAFE)
    # --------------------------------------------------------
    MAX_COMPONENT_VERSIONS_PER_COMPONENT = env_int(
        "MAX_COMPONENT_VERSIONS_PER_COMPONENT",
        None,
    )

    if MAX_COMPONENT_VERSIONS_PER_COMPONENT is not None:
        log.info(
            "Applying SAFE cap | MAX_COMPONENT_VERSIONS_PER_COMPONENT=%d",
            MAX_COMPONENT_VERSIONS_PER_COMPONENT,
        )

        rows_by_comp = defaultdict(list)
        for r in all_rows:
            rows_by_comp[(r["ecosystem"], r["component_name"])].append(r)

        capped_rows = []

        for (eco, name), rs in rows_by_comp.items():
            versions = sorted(
                {r["component_version"] for r in rs}, reverse=True
            )
            keep_versions = set(
                versions[:MAX_COMPONENT_VERSIONS_PER_COMPONENT]
            )

            for r in rs:
                if r["component_version"] in keep_versions:
                    capped_rows.append(r)

        dropped = len(all_rows) - len(capped_rows)
        all_rows = capped_rows

        log.info(
            "SAFE cap applied | kept=%d | dropped=%d",
            len(all_rows),
            dropped,
        )

    # --------------------------------------------------------
    # OFFLINE VALIDATION AGAINST OSV CACHE
    # --------------------------------------------------------
    all_rows = verify_dataset_against_osv(all_rows, osv_cache)

    # --------------------------------------------------------
    # POST-HOC BALANCING
    # --------------------------------------------------------
    balance_stats = None
    if balance:
        log.info(
            "Applying post-hoc balancing | strategy=%s | min_unique_component_ratio=%.2f",
            balance_strategy,
            min_unique_component_ratio,
        )

        # verhindert Dominanz einzelner Pakete
        all_rows = cap_per_component(all_rows, max_per_component=10)

        # deterministische Reihenfolge
        all_rows = sorted(
            all_rows,
            key=lambda r: (
                (r.get("ecosystem") or ""),
                (r.get("component_name") or ""),
                str(r.get("component_version") or ""),
                (r.get("vulnerability_id") or ""),
            ),
        )

        # korrektes Balancing (WICHTIG: tuple unpacking)
        all_rows, balance_stats = balance_rows_by_vulnerability_deterministic(
            all_rows,
            ecosystems=[e.lower() for e in ecosystems],
            strategy=balance_strategy,
        )

    # --------------------------------------------------------
    # FINAL COUNTS
    # --------------------------------------------------------
    component_count, osv_vuln_entries = compute_global_counts(all_rows)

    # --------------------------------------------------------
    # Output paths
    # --------------------------------------------------------
    build_dir = Path(GROUND_TRUTH_BUILD_PATH)
    build_dir.mkdir(parents=True, exist_ok=True)

    base_name = f"mixed_ground_truth_dataset_{ts}_{component_count}_{osv_vuln_entries}"

    csv_path = build_dir / f"{base_name}.csv"
    stat_path = build_dir / f"{base_name}.stat.txt"
    sbom_path = build_dir / f"{base_name}.sbom.json"

    # --------------------------------------------------------
    # Write CSV
    # --------------------------------------------------------
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "ecosystem",
                "component_name",
                "component_version",
                "purl",
                "vulnerability_id",
                "cve",
                "vulnerability_description",
                "is_vulnerable",
            ],
        )
        writer.writeheader()
        writer.writerows(all_rows)

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------
    pre_balance_stats = compute_pre_balance_stats(raw_rows)

    write_statistics(
        rows=all_rows,
        out_path=stat_path,
        csv_path=csv_path,
        sbom_path=sbom_path,
        pre_balance_stats=pre_balance_stats,
        balance_stats=balance_stats,
    )

    # --------------------------------------------------------
    # SBOM
    # --------------------------------------------------------
    build_sbom(
        all_rows,
        "mixed",
        ts,
        component_count,
        osv_vuln_entries,
        out_path=sbom_path,
    )

    # --------------------------------------------------------
    # META FILE
    # --------------------------------------------------------
    ecosystem_stats = compute_ecosystem_stats(all_rows)

    write_ground_truth_meta(
        output_csv_path=csv_path,
        ecosystem_stats=ecosystem_stats,
        total_vulnerabilities=osv_vuln_entries,
    )

    log.info(
        "DONE | unique_components=%d | osv_vuln_entries=%d",
        component_count,
        osv_vuln_entries,
    )


if __name__ == "__main__":
    main()
