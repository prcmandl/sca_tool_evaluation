from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import os


# ============================================================
# Helper: environment (effective value + source)
# ============================================================

def _env_int_effective(name: str, default: int) -> Tuple[int, str]:
    """
    Resolve an integer parameter from the environment.

    Returns:
        (value, source) where source ∈ {"env", "default"}.

    Semantics:
      - if env var is unset or empty -> default
      - if env var is not parseable -> default
    """
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default, "default"
    try:
        return int(raw), "env"
    except ValueError:
        return default, "default"


# ============================================================
# Helper: global counts
# ============================================================

def compute_global_counts(rows: List[dict]) -> Tuple[int, int]:
    """
    Compute global dataset counts.

    Returns:
        component_count:
            Number of unique components defined as
            (ecosystem, component_name, component_version)

        osv_vuln_entries:
            Number of unique OSV vulnerability entries defined as
            (ecosystem, component_name, component_version, vulnerability_id)
    """
    components = {
        (r["ecosystem"], r["component_name"], r["component_version"])
        for r in rows
    }

    osv_vulns = {
        (
            r["ecosystem"],
            r["component_name"],
            r["component_version"],
            r["vulnerability_id"],
        )
        for r in rows
    }

    return len(components), len(osv_vulns)


# ============================================================
# Helper: pre-balancing statistics
# ============================================================

def compute_pre_balance_stats(rows: List[dict]) -> Dict[str, dict]:
    """
    Compute pre-balancing coverage statistics from raw OSV rows.

    Returns a dict:
      eco -> {
        osv_vuln_entries,
        unique_components,
        cve_findings,
        unique_cves,
      }
    """
    stats = defaultdict(lambda: {
        "osv_vulns": set(),
        "components": set(),
        "cve_findings": set(),
        "cves": set(),
    })

    for r in rows:
        eco = r["ecosystem"]

        stats[eco]["osv_vulns"].add(
            (eco, r["component_name"], r["component_version"], r["vulnerability_id"])
        )

        stats[eco]["components"].add(
            (r["component_name"], r["component_version"])
        )

        if r.get("cve"):
            stats[eco]["cves"].add(r["cve"])
            stats[eco]["cve_findings"].add(
                (r["component_name"], r["component_version"], r["cve"])
            )

    out = {}
    for eco, s in stats.items():
        out[eco] = {
            "osv_vuln_entries": len(s["osv_vulns"]),
            "unique_components": len(s["components"]),
            "cve_findings": len(s["cve_findings"]),
            "unique_cves": len(s["cves"]),
        }

    return out


# ============================================================
# Writer: statistics file
# ============================================================

def write_statistics(
    *,
    rows: List[dict],
    out_path: Path,
    csv_path: Path,
    sbom_path: Optional[Path] = None,
    pre_balance_stats: Optional[Dict[str, dict]] = None,
    balance_stats: Optional[Dict[str, dict]] = None,
) -> None:
    """
    Write a fully self-contained statistics file for the ground truth dataset.
    """

    import os
    from collections import defaultdict, Counter
    from datetime import datetime
    from statistics import mean, median
    from ground_truth_generation.osv_common import API_CALL_TRACKER

    # --------------------------------------------------------
    # helpers
    # --------------------------------------------------------

    def _env(name: str) -> str:
        v = os.environ.get(name)
        return "-" if v is None or str(v).strip() == "" else str(v)

    def _env_int_effective(name: str, default: int):
        raw = os.environ.get(name)
        if raw is None or str(raw).strip() == "":
            return default, "default"
        try:
            return int(raw), "env"
        except ValueError:
            return default, "default"

    def _bool_env(name: str) -> str:
        v = os.environ.get(name)
        if v is None or str(v).strip() == "":
            return "-"
        return "True" if str(v).lower() in {"1", "true", "yes", "on"} else "False"

    component_count, osv_vuln_entries = compute_global_counts(rows)

    # --------------------------------------------------------
    # Per-ecosystem (POST-balancing)
    # --------------------------------------------------------

    per_eco = defaultdict(lambda: {
        "components": set(),
        "osv_vulns": set(),
        "cve_findings": set(),
        "cves": set(),
    })

    for r in rows:
        eco = r["ecosystem"]
        name = r["component_name"]
        ver = r["component_version"]
        osv = r["vulnerability_id"]

        per_eco[eco]["components"].add((name, ver))
        per_eco[eco]["osv_vulns"].add((eco, name, ver, osv))

        if r.get("cve"):
            per_eco[eco]["cves"].add(r["cve"])
            per_eco[eco]["cve_findings"].add((name, ver, r["cve"]))

    # --------------------------------------------------------
    # Adapter configuration
    # --------------------------------------------------------

    pypi_max, pypi_src = _env_int_effective("PYPI_MAX_VERSIONS_PER_PACKAGE", 5)
    npm_max, npm_src = _env_int_effective("NPM_MAX_VERSIONS_PER_PACKAGE", 9)
    maven_max, maven_src = _env_int_effective("MAVEN_MAX_VERSIONS_PER_PACKAGE", 10)
    nuget_max, nuget_src = _env_int_effective("NUGET_MAX_VERSIONS_PER_PACKAGE", 10)

    # --------------------------------------------------------
    # Write file
    # --------------------------------------------------------

    with out_path.open("w", encoding="utf-8") as f:
        w = lambda s="": f.write(s + "\n")

        # ====================================================
        # Header
        # ====================================================
        w("OSV Ground Truth Dataset – Statistics")
        w("====================================")
        w(f"Generated at: {datetime.now():%Y-%m-%d %H:%M:%S}")
        w()

        # ====================================================
        # Dataset files
        # ====================================================
        w("Dataset files")
        w("-------------")
        w(f"CSV dataset : {csv_path.name}")
        if sbom_path:
            w(f"SBOM file   : {sbom_path.name}")
        w()

        # ====================================================
        # Adapter configuration
        # ====================================================
        w("Adapter configuration (effective parameters)")
        w("--------------------------------------------")
        w("Parameter                               | Value | Source")
        w("------------------------------------------------------------")
        w(f"PYPI_MAX_VERSIONS_PER_PACKAGE           | {pypi_max:5d} | {pypi_src}")
        w(f"NPM_MAX_VERSIONS_PER_PACKAGE            | {npm_max:5d} | {npm_src}")
        w(f"MAVEN_MAX_VERSIONS_PER_PACKAGE          | {maven_max:5d} | {maven_src}")
        w(f"NUGET_MAX_VERSIONS_PER_PACKAGE          | {nuget_max:5d} | {nuget_src}")
        w()

        # ====================================================
        # Invocation parameters
        # ====================================================
        invocation_rows = [
            ("SAMPLES_PER_ECOSYSTEM", _env("SAMPLES"), "env"),
            ("ECOSYSTEMS", _env("ECOSYSTEMS"), "env"),
            ("START_DATE", _env("START_DATE"), "env"),
            ("END_DATE", _env("END_DATE"), "env"),
            ("BALANCE_ENABLED", _bool_env("BALANCE"), "env"),
            ("BALANCE_STRATEGY", _env("BALANCE_STRATEGY"), "env"),
            ("MIN_UNIQUE_COMPONENT_RATIO", _env("MIN_UNIQUE_COMPONENT_RATIO"), "env"),
            ("BALANCE_SEED", _env("BALANCE_SEED"), "env"),
        ]

        p_w = max(len("Parameter"), max(len(r[0]) for r in invocation_rows))
        v_w = max(len("Value"), max(len(r[1]) for r in invocation_rows))
        s_w = max(len("Source"), max(len(r[2]) for r in invocation_rows))
        sep = "-" * (p_w + v_w + s_w + 6)

        w("Invocation parameters (effective run configuration)")
        w(sep)
        w(f"{'Parameter':<{p_w}} | {'Value':<{v_w}} | {'Source':<{s_w}}")
        w(sep)
        for p, v, s in invocation_rows:
            w(f"{p:<{p_w}} | {v:<{v_w}} | {s:<{s_w}}")
        w()

        # ====================================================
        # Per-ecosystem statistics (post-balancing dataset)
        # ====================================================

        w("Per-ecosystem statistics (post-balancing dataset)")
        w("-------------------------------------------------")

        # --------- FIX: global totals (correct shares) ---------
        total_components = sum(len(s["components"]) for s in per_eco.values())
        total_osv = sum(len(s["osv_vulns"]) for s in per_eco.values())

        table_rows = []

        all_comp_freq = []
        all_compver_freq = []

        total_cve_findings = 0
        total_unique_cves = set()

        for eco in sorted(per_eco.keys()):
            s = per_eco[eco]

            comp = len(s["components"])
            osv = len(s["osv_vulns"])
            cve_f = len(s["cve_findings"])
            cves = len(s["cves"])

            total_cve_findings += cve_f
            total_unique_cves |= s["cves"]

            comp_counter = Counter(
                r["component_name"]
                for r in rows if r["ecosystem"] == eco
            )
            compver_counter = Counter(
                (r["component_name"], r["component_version"])
                for r in rows if r["ecosystem"] == eco
            )

            comp_freqs = list(comp_counter.values())
            compver_freqs = list(compver_counter.values())

            all_comp_freq.extend(comp_freqs)
            all_compver_freq.extend(compver_freqs)

            def stats(v):
                return (
                    max(v),
                    mean(v),
                    min(v),
                    median(v),
                ) if v else (0, 0.0, 0, 0.0)

            max_c, avg_c, min_c, med_c = stats(comp_freqs)
            max_cv, avg_cv, min_cv, med_cv = stats(compver_freqs)

            table_rows.append({
                "Ecosystem": eco,
                "Components": comp,
                "OSV-Vulns": osv,
                "CVE-Findings": cve_f,
                "CVEs": cves,
                "Comp/OSV": f"{(comp / osv if osv else 0):.2f}",
                "CVE/OSV": f"{(cve_f / osv if osv else 0):.2f}",
                "Vuln-Share": f"{(osv / total_osv if total_osv else 0):.2%}",
                "Comp-Share": f"{(comp / total_components if total_components else 0):.2%}",
                "MaxCompFreq": max_c,
                "MaxCompVerFreq": max_cv,
                "AvgCompFreq": f"{avg_c:.2f}",
                "AvgCompVerFreq": f"{avg_cv:.2f}",
                "MinCompFreq": min_c,
                "MinCompVerFreq": min_cv,
                "MedianCompFreq": f"{med_c:.2f}",
                "MedianCompVerFreq": f"{med_cv:.2f}",
            })

        def gstats(v):
            return (
                max(v),
                mean(v),
                min(v),
                median(v),
            ) if v else (0, 0.0, 0, 0.0)

        g_max_c, g_avg_c, g_min_c, g_med_c = gstats(all_comp_freq)
        g_max_cv, g_avg_cv, g_min_cv, g_med_cv = gstats(all_compver_freq)

        table_rows.append({
            "Ecosystem": "TOTAL",
            "Components": total_components,
            "OSV-Vulns": total_osv,
            "CVE-Findings": total_cve_findings,
            "CVEs": len(total_unique_cves),
            "Comp/OSV": f"{(total_components / total_osv if total_osv else 0):.2f}",
            "CVE/OSV": f"{(total_cve_findings / total_osv if total_osv else 0):.2f}",
            "Vuln-Share": "100.00%",
            "Comp-Share": "100.00%",
            "MaxCompFreq": g_max_c,
            "MaxCompVerFreq": g_max_cv,
            "AvgCompFreq": f"{g_avg_c:.2f}",
            "AvgCompVerFreq": f"{g_avg_cv:.2f}",
            "MinCompFreq": g_min_c,
            "MinCompVerFreq": g_min_cv,
            "MedianCompFreq": f"{g_med_c:.2f}",
            "MedianCompVerFreq": f"{g_med_cv:.2f}",
        })

        columns = list(table_rows[0].keys())
        col_width = {
            c: max(len(c), max(len(str(r[c])) for r in table_rows)) + 1
            for c in columns
        }

        header = " | ".join(f"{c:<{col_width[c]}}" for c in columns)
        table_width = sum(col_width[c] for c in columns) + 3 * (len(columns) - 1)

        w(header)
        w("-" * table_width)

        for r in table_rows[:-1]:
            w(" | ".join(f"{str(r[c]):<{col_width[c]}}" for c in columns))

        w("-" * table_width)
        total_row = table_rows[-1]
        w(" | ".join(f"{str(total_row[c]):<{col_width[c]}}" for c in columns))
        w()

        # ====================================================
        # Top-20 components by frequency (post-balancing)
        # ====================================================

        w("Top-20 components by frequency (post-balancing)")
        w("-----------------------------------------------")

        comp_stats = defaultdict(lambda: {
            "ecosystem": None,
            "versions": set(),
            "samples": 0,
        })

        for r in rows:
            key = (r["ecosystem"], r["component_name"])
            comp_stats[key]["ecosystem"] = r["ecosystem"]
            comp_stats[key]["versions"].add(r["component_version"])
            comp_stats[key]["samples"] += 1

        top_components = sorted(
            comp_stats.items(),
            key=lambda x: x[1]["samples"],
            reverse=True,
        )[:20]

        table_rows = []
        for (eco, name), s in top_components:
            table_rows.append({
                "Ecosystem": eco,
                "Component": name,
                "Versions": sorted(s["versions"]),
                "Samples": s["samples"],
            })

        columns = ["Ecosystem", "Component", "Versions", "Samples"]

        def cell_lines(row, col):
            return row[col] if col == "Versions" else [str(row[col])]

        col_width = {
            c: max(
                len(c),
                max(len(line) for r in table_rows for line in cell_lines(r, c))
            ) + 1
            for c in columns
        }

        table_width = sum(col_width[c] for c in columns) + 3 * (len(columns) - 1)
        header = " | ".join(f"{c:<{col_width[c]}}" for c in columns)

        w(header)
        w("-" * table_width)

        for row in table_rows:
            max_lines = max(len(cell_lines(row, c)) for c in columns)
            for i in range(max_lines):
                w(" | ".join(
                    f"{(cell_lines(row, c)[i] if i < len(cell_lines(row, c)) else ''):<{col_width[c]}}"
                    for c in columns
                ))
            w("-" * table_width)

        w()

        # ====================================================
        # API access statistics (ground-truth collection)
        # ====================================================

        api_stats = API_CALL_TRACKER.get_stats()

        w("API access statistics (ground-truth collection)")
        w("---------------------------------------------")
        w("API              | Calls | Total Time (ms) | Avg Time (ms)")
        w("----------------------------------------------------------")

        total_calls = 0
        total_time_ms = 0.0

        for api in sorted(api_stats.keys()):
            s = api_stats[api]
            calls = int(s.get("calls", 0))
            total_ms = float(s.get("total_time_sec", 0.0)) * 1000.0
            avg_ms = (total_ms / calls) if calls else 0.0

            total_calls += calls
            total_time_ms += total_ms

            w(f"{api:<16} | {calls:5d} | {total_ms:14.2f} | {avg_ms:13.2f}")

        w("----------------------------------------------------------")

        overall_avg_ms = (total_time_ms / total_calls) if total_calls else 0.0
        w(f"{'TOTAL':<16} | {total_calls:5d} | {total_time_ms:14.2f} | {overall_avg_ms:13.2f}")
        w()

        # ====================================================
        # Notes – Definitions and column semantics
        # ====================================================
        w("Definitions and column semantics for the per-ecosystem statistics table:")
        w()
        w("Ecosystem")
        w("  Identifier of the package ecosystem (e.g., pypi, npm, maven, nuget).")
        w()
        w("Components")
        w("  Number of unique components in the final dataset for this ecosystem.")
        w("  A component is defined as a unique tuple (component_name, component_version).")
        w()
        w("OSV-Vulns")
        w("  Number of OSV vulnerability entries associated with this ecosystem.")
        w("  Each entry corresponds to one OSV advisory affecting a specific component version.")
        w()
        w("CVE-Findings")
        w("  Number of CVE-backed vulnerability findings.")
        w("  A CVE-backed finding is defined as a unique tuple")
        w("  (component_name, component_version, CVE-ID).")
        w("  Multiple OSV advisories may reference the same CVE and are deduplicated here.")
        w()
        w("CVEs")
        w("  Number of unique CVE identifiers referenced by OSV advisories")
        w("  in this ecosystem, independent of affected components or versions.")
        w()
        w("Comp/OSV")
        w("  Ratio of unique components to OSV vulnerability entries for this ecosystem:")
        w("    Comp/OSV = Components / OSV-Vulns")
        w("  This metric indicates component diversity relative to the number of vulnerabilities.")
        w()
        w("CVE/OSV")
        w("  Ratio of CVE-backed findings to OSV vulnerability entries:")
        w("    CVE/OSV = CVE-Findings / OSV-Vulns")
        w("  Values below 1 indicate that multiple OSV advisories map to the same CVE.")
        w("  This ratio characterizes the degree of advisory-to-CVE consolidation.")
        w()
        w("Vuln-Share")
        w("  Proportion of OSV vulnerability entries of this ecosystem relative")
        w("  to the total number of OSV entries across all ecosystems:")
        w("    Vuln-Share = OSV-Vulns_ecosystem / OSV-Vulns_global")
        w()
        w("Comp-Share")
        w("  Proportion of unique components of this ecosystem relative")
        w("  to the total number of unique components across all ecosystems:")
        w("    Comp-Share = Components_ecosystem / Components_global")
        w()
        w("Component frequency statistics (post-balancing):")
        w()
        w(
            "The following columns characterize how often individual components and\n"
            "component-version pairs occur in the final ground-truth dataset. Frequency\n"
            "is defined as the number of OSV vulnerability entries associated with the\n"
            "respective entity.\n"
        )
        w()

        w("MaxCompFreq")
        w(
            "  Maximum number of vulnerability entries associated with any single\n"
            "  component (identified by component_name) within the ecosystem.\n"
        )

        w("MaxCompVerFreq")
        w(
            "  Maximum number of vulnerability entries associated with any single\n"
            "  component-version pair (component_name, component_version).\n"
        )

        w("AvgCompFreq")
        w(
            "  Average number of vulnerability entries per component\n"
            "  (component_name), computed over all components in the ecosystem.\n"
        )

        w("AvgCompVerFreq")
        w(
            "  Average number of vulnerability entries per component-version pair\n"
            "  (component_name, component_version).\n"
        )

        w("MinCompFreq")
        w(
            "  Minimum number of vulnerability entries associated with any component\n"
            "  in the ecosystem.\n"
        )

        w("MinCompVerFreq")
        w(
            "  Minimum number of vulnerability entries associated with any\n"
            "  component-version pair.\n"
        )

        w("MedianCompFreq")
        w(
            "  Median number of vulnerability entries per component, providing a\n"
            "  robust central tendency measure that is less sensitive to outliers.\n"
        )

        w("MedianCompVerFreq")
        w(
            "  Median number of vulnerability entries per component-version pair,\n"
            "  reflecting the typical vulnerability density at version granularity.\n"
        )
        w()
        w("TOTAL")
        w("  Aggregated sums across all ecosystems.")
        w("  Ratio columns in the TOTAL row are computed from the summed values")
        w("  and therefore reflect global averages.")

        w("Invocation parameter semantics:")
        w()
        w("SAMPLES_PER_ECOSYSTEM")
        w("  Number of components sampled per ecosystem prior to OSV querying.")
        w()
        w("ECOSYSTEMS")
        w("  Space-separated list of ecosystems included in the dataset construction.")
        w()
        w("START_DATE")
        w("  Optional lower bound on component release dates.")
        w()
        w("END_DATE")
        w("  Optional upper bound on component release dates.")
        w()
        w("BALANCE_ENABLED")
        w("  Indicates whether post-hoc balancing across ecosystems is applied.")
        w()
        w("BALANCE_STRATEGY")
        w("  Strategy used to determine the per-ecosystem balancing target (min or median).")
        w()
        w("MIN_UNIQUE_COMPONENT_RATIO")
        w("  Minimum required ratio of unique components during balancing.")
        w()
        w("BALANCE_SEED")
        w("  Random seed used for deterministic post-hoc balancing.")
        w()
        w("Parameter-specific interpretation:")
        w()
        w("PYPI_MAX_VERSIONS_PER_PACKAGE")
        w("  Maximum number of released versions considered per PyPI package.")
        w()
        w("NPM_MAX_VERSIONS_PER_PACKAGE")
        w("  Maximum number of released versions considered per npm package.")
        w()
        w("MAVEN_MAX_VERSIONS_PER_PACKAGE")
        w("  Maximum number of released versions considered per Maven artifact.")
        w()
        w("NUGET_MAX_VERSIONS_PER_PACKAGE")
        w("  Maximum number of released versions considered per NuGet package.")
        w()
        w("NUGET_MAX_VERSIONS_PER_PACKAGE")
        w("  Maximum number of released versions considered per NuGet package.")
        w()
        w(
            "A component is defined as a unique tuple "
            "(ecosystem, component_name, component_version).\n"
            "Each OSV vulnerability entry is counted uniquely by "
            "(ecosystem, component, version, vulnerability_id).\n"
            "CVEs are treated as aliases of OSV vulnerabilities and are deduplicated "
            "only for CVE-based metrics.\n"
            "Pre-balancing coverage reports the raw OSV results after canonicalization "
            "and before validation and balancing.\n"
            "Post-hoc balancing approximates equal vulnerability coverage across "
            "ecosystems while maximizing component diversity.\n"
            "If diversity constraints are infeasible, a soft fallback reduces the "
            "per-ecosystem target accordingly."
        )
        w()





