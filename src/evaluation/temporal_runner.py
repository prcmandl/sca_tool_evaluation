from __future__ import annotations

import argparse
import hashlib
import logging
import time
from pathlib import Path
from typing import Dict, List
import json

from evaluation.evaluate import run_evaluation
from evaluation.core.ground_truth import load_ground_truth
from evaluation.core.model import Finding

log = logging.getLogger("evaluation.temporal")


TOOLS = ["dtrack", "oss-index", "github", "snyk", "trivy"]
ECOSYSTEMS = ["maven", "npm", "nuget", "pypi"]

TOOL_NAMES = {
    "dtrack": "OWASP Dependency-Track",
    "oss-index": "OSS Index",
    "github": "GitHub Advisory Database",
    "snyk": "Snyk",
    "trivy": "Trivy",
}


# ------------------------------------------------------------
# Hashing (deterministic comparison)
# ------------------------------------------------------------

def hash_gt(gt: List[Finding]) -> str:
    data = sorted(
        (f.ecosystem, f.component, f.version, f.cve or f.osv_id or "")
        for f in gt
    )
    return hashlib.sha256(str(data).encode()).hexdigest()


def hash_findings(findings: List[Finding]) -> str:
    data = sorted(
        (f.ecosystem, f.component, f.version, f.cve or f.osv_id or "")
        for f in findings
    )
    return hashlib.sha256(str(data).encode()).hexdigest()


# ------------------------------------------------------------
# LaTeX generation
# ------------------------------------------------------------

def generate_latex(results, gt_summary, output_file: Path):
    def fmt(x):
        return f"{x:.2f}" if isinstance(x, float) else str(x)

    total_gt = {
        "Components": sum(v["Components"] for v in gt_summary.values()),
        "Vulnerabilities": sum(v["Vulnerabilities"] for v in gt_summary.values()),
        "CVEs": sum(v["CVEs"] for v in gt_summary.values()),
    }

    with open(output_file, "w") as f:
        f.write("\\begin{table*}[!t]\n")
        f.write("\\centering\n")
        f.write("\\small\n")
        f.write("\\setlength{\\tabcolsep}{4pt}\n")
        f.write("\\renewcommand{\\arraystretch}{1.1}\n\n")

        f.write("\\begin{tabular}{lrrrrrrrr}\n")
        f.write("\\toprule\n")
        f.write("Ecosystem & Components & Vulnerabilities & CVEs & TP & FP & FN & Recall & Overlap \\\\\n")
        f.write("\\midrule\n\n")

        for tool, data in results.items():
            f.write(f"\\multicolumn{{9}}{{c}}{{\\textbf{{{TOOL_NAMES[tool]}}}}} \\\\\n")
            f.write("\\midrule\n")

            total_tp = total_fp = total_fn = 0

            for eco in ECOSYSTEMS:
                row = data[eco]
                gt = gt_summary[eco]

                total_tp += row["TP"]
                total_fp += row["FP"]
                total_fn += row["FN"]

                f.write(
                    f"{eco} & "
                    f"{gt['Components']} & "
                    f"{gt['Vulnerabilities']} & "
                    f"{gt['CVEs']} & "
                    f"{row['TP']} & "
                    f"{row['FP']} & "
                    f"{row['FN']} & "
                    f"{fmt(row['Recall'])} & "
                    f"{fmt(row['Overlap'])} \\\\\n"
                )

            recall = total_tp / (total_tp + total_fn) if total_tp + total_fn else 0
            overlap = total_tp / (total_tp + total_fp) if total_tp + total_fp else 0

            f.write(
                f"TOTAL & "
                f"{total_gt['Components']} & "
                f"{total_gt['Vulnerabilities']} & "
                f"{total_gt['CVEs']} & "
                f"{total_tp} & {total_fp} & {total_fn} & "
                f"{fmt(recall)} & {fmt(overlap)} \\\\\n"
            )

            f.write("\\midrule\n\n")

        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table*}\n")

import json
import statistics
from pathlib import Path

def aggregate_runs(run_dirs, output_file):
    """
    Aggregate multiple runs and compute mean/std per tool & ecosystem
    """

    all_data = []

    # --------------------------------------------------------
    # Load JSON results
    # --------------------------------------------------------
    for rd in run_dirs:
        json_file = Path(rd) / "results.json"
        if not json_file.exists():
            continue

        with open(json_file) as f:
            all_data.append(json.load(f))

    if not all_data:
        print("No JSON data found for aggregation")
        return

    # --------------------------------------------------------
    # Aggregate
    # --------------------------------------------------------
    agg = {}

    tools = all_data[0].keys()

    for tool in tools:
        agg[tool] = {}

        ecosystems = all_data[0][tool].keys()

        for eco in ecosystems:
            metrics = ["TP", "FP", "FN", "Recall", "Overlap"]

            agg[tool][eco] = {}

            for m in metrics:
                values = [run[tool][eco][m] for run in all_data]

                agg[tool][eco][m] = {
                    "mean": statistics.mean(values),
                    "std": statistics.pstdev(values) if len(values) > 1 else 0.0,
                }

    # --------------------------------------------------------
    # Write LaTeX
    # --------------------------------------------------------
    with open(output_file, "w") as f:
        f.write("\\begin{table*}[!t]\n\\centering\n\\small\n")
        f.write("\\begin{tabular}{lrrrrrrrr}\n\\toprule\n")
        f.write("Ecosystem & TP & FP & FN & Recall & Overlap \\\\\n\\midrule\n")

        for tool, ecos in agg.items():
            f.write(f"\\multicolumn{{6}}{{c}}{{\\textbf{{{tool}}}}} \\\\\n\\midrule\n")

            for eco, row in ecos.items():
                def fmt(x):
                    return f"{x['mean']:.2f} $\\pm$ {x['std']:.2f}"

                f.write(
                    f"{eco} & "
                    f"{fmt(row['TP'])} & "
                    f"{fmt(row['FP'])} & "
                    f"{fmt(row['FN'])} & "
                    f"{fmt(row['Recall'])} & "
                    f"{fmt(row['Overlap'])} \\\\\n"
                )

            f.write("\\midrule\n")

        f.write("\\bottomrule\n\\end{tabular}\n\\end{table*}\n")

# ------------------------------------------------------------
# GT summary
# ------------------------------------------------------------

def build_gt_summary(gt):
    summary = {}
    for eco in ECOSYSTEMS:
        subset = [g for g in gt if g.ecosystem == eco]

        components = {(g.component, g.version) for g in subset}
        cves = {g.cve for g in subset if g.cve}

        summary[eco] = {
            "Components": len(components),
            "Vulnerabilities": len(subset),
            "CVEs": len(cves),
        }

    return summary


# ------------------------------------------------------------
# Temporal Consistency Runner
# ------------------------------------------------------------

def run_temporal(ground_truth_path: str, output_file: str):
    gt0 = load_ground_truth(ground_truth_path)
    gt_summary = build_gt_summary(gt0)

    gt0_hash = hash_gt(gt0)

    while True:
        runs = []

        # ----------------------------------------------------
        # Run tools 3 times
        # ----------------------------------------------------
        for i in range(3):
            log.info("Run %d/3", i + 1)

            run_result = {}

            for tool in TOOLS:
                res = run_evaluation(
                    ground_truth_path=ground_truth_path,
                    tool=tool,
                    return_findings=True,
                    return_metrics=True,
                )

                run_result[tool] = {
                    "hash": hash_findings(res["findings"]),
                    "metrics": res["metrics"]["per_ecosystem"],
                }

            runs.append(run_result)

        # ----------------------------------------------------
        # GT1
        # ----------------------------------------------------
        gt1 = load_ground_truth(ground_truth_path)
        gt1_hash = hash_gt(gt1)

        # ----------------------------------------------------
        # Check consistency
        # ----------------------------------------------------
        tools_ok = True

        for tool in TOOLS:
            hashes = [r[tool]["hash"] for r in runs]
            if len(set(hashes)) != 1:
                log.warning("Tool unstable: %s", tool)
                tools_ok = False

        gt_ok = gt0_hash == gt1_hash

        if tools_ok and gt_ok:
            log.info("=== CONSISTENT ===")

            final_metrics = {
                tool: runs[0][tool]["metrics"]
                for tool in TOOLS
            }

            generate_latex(
                final_metrics,
                gt_summary,
                Path(output_file),
            )


            json_path = str(output_file).replace(".tex", ".json")

            with open(json_path, "w") as f:
                json.dump(final_metrics, f, indent=2)

            log.info("LaTeX written to %s", output_file)
            return

        log.warning("Retrying due to inconsistency...")
        time.sleep(2)


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--output", default="results.tex")

    args = ap.parse_args()

    run_temporal(args.ground_truth, args.output)


if __name__ == "__main__":
    main()