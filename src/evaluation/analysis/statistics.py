from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Dict, List


# ------------------------------------------------------------
# Load run results
# ------------------------------------------------------------
def load_runs(run_dirs: List[str]) -> List[Dict]:
    data = []

    for rd in run_dirs:
        f = Path(rd) / "results.json"

        if not f.exists():
            continue

        try:
            with f.open("r", encoding="utf-8") as fp:
                d = json.load(fp)
                if d:
                    data.append(d)
        except Exception:
            continue

    return data


# ------------------------------------------------------------
# Aggregate metrics
# ------------------------------------------------------------
def aggregate(data: List[Dict]) -> Dict:
    agg = {}

    if not data:
        return agg

    tools = set()
    ecosystems = set()

    # discover structure
    for run in data:
        tools.update(run.keys())
        for tool in run:
            ecosystems.update(run[tool].keys())

    for tool in tools:
        agg[tool] = {}

        for eco in ecosystems:
            agg[tool][eco] = {}

            for metric in ["TP", "FP", "FN", "Recall", "Overlap"]:
                values = [
                    run.get(tool, {}).get(eco, {}).get(metric, 0)
                    for run in data
                ]

                if not values:
                    values = [0]

                agg[tool][eco][metric] = {
                    "mean": statistics.mean(values),
                    "std": statistics.pstdev(values) if len(values) > 1 else 0.0,
                    "values": values,
                }

    return agg


# ------------------------------------------------------------
# Confidence intervals (95%)
# ------------------------------------------------------------
def add_confidence_intervals(agg: Dict) -> Dict:
    for tool, ecos in agg.items():
        for eco, metrics in ecos.items():
            for m in ["Recall", "Overlap"]:
                values = metrics[m]["values"]

                if len(values) <= 1:
                    ci = 0.0
                else:
                    std = statistics.stdev(values)
                    ci = 1.96 * std / (len(values) ** 0.5)

                metrics[m]["ci95"] = ci

    return agg


# ------------------------------------------------------------
# GT summary
# ------------------------------------------------------------
def build_gt_summary(gt) -> Dict:
    summary = {}

    for g in gt:
        eco = g.ecosystem

        if eco not in summary:
            summary[eco] = {
                "Components": set(),
                "Vulnerabilities": 0,
                "CVEs": set(),
            }

        summary[eco]["Components"].add((g.component, g.version))
        summary[eco]["Vulnerabilities"] += 1

        if g.cve:
            summary[eco]["CVEs"].add(g.cve)

    # convert sets to counts
    for eco in summary:
        summary[eco]["Components"] = len(summary[eco]["Components"])
        summary[eco]["CVEs"] = len(summary[eco]["CVEs"])

    return summary


# ------------------------------------------------------------
# LaTeX: main results table
# ------------------------------------------------------------
def write_latex_stats(agg: Dict, gt_summary: Dict, output_file: str):

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

        for tool, ecos in agg.items():

            f.write(f"\\multicolumn{{9}}{{c}}{{\\textbf{{{tool}}}}} \\\\\n")
            f.write("\\midrule\n")

            total = {"TP": 0, "FP": 0, "FN": 0}

            for eco, row in sorted(ecos.items()):
                gt = gt_summary.get(eco, {})

                TP = int(row["TP"]["mean"])
                FP = int(row["FP"]["mean"])
                FN = int(row["FN"]["mean"])

                total["TP"] += TP
                total["FP"] += FP
                total["FN"] += FN

                recall = row["Recall"]["mean"]
                overlap = row["Overlap"]["mean"]

                f.write(
                    f"{eco} & "
                    f"{gt.get('Components', 0)} & "
                    f"{gt.get('Vulnerabilities', 0)} & "
                    f"{gt.get('CVEs', 0)} & "
                    f"{TP} & {FP} & {FN} & "
                    f"{recall:.2f} & {overlap:.2f} \\\\\n"
                )

            # totals
            recall_total = total["TP"] / (total["TP"] + total["FN"]) if (total["TP"] + total["FN"]) else 0
            overlap_total = total["TP"] / (total["TP"] + total["FP"]) if (total["TP"] + total["FP"]) else 0

            f.write(
                f"TOTAL & - & - & - & "
                f"{total['TP']} & {total['FP']} & {total['FN']} & "
                f"{recall_total:.2f} & {overlap_total:.2f} \\\\\n"
            )

            f.write("\\midrule\n\n")

        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table*}\n")


# ------------------------------------------------------------
# LaTeX: ecosystem summary
# ------------------------------------------------------------
def write_ecosystem_summary_table(agg: Dict, gt_summary: Dict, output_file: str):

    ecosystems = gt_summary.keys()

    sums = {eco: {"TP": 0, "FP": 0, "FN": 0} for eco in ecosystems}

    for tool in agg:
        for eco in ecosystems:
            row = agg.get(tool, {}).get(eco, {})

            sums[eco]["TP"] += int(row.get("TP", {}).get("mean", 0))
            sums[eco]["FP"] += int(row.get("FP", {}).get("mean", 0))
            sums[eco]["FN"] += int(row.get("FN", {}).get("mean", 0))

    with open(output_file, "w") as f:
        f.write("\\begin{table*}[!t]\n")
        f.write("\\centering\n")
        f.write("\\small\n\n")

        f.write("\\begin{tabular}{lrrrrrrr}\n")
        f.write("\\toprule\n")
        f.write("Ecosystem & Components & Vulnerabilities & $\\sum TP$ & $\\sum FP$ & $\\sum FN$ & Mean Recall & Mean Overlap \\\\\n")
        f.write("\\midrule\n")

        total = {"TP": 0, "FP": 0, "FN": 0}

        for eco in ecosystems:
            gt = gt_summary[eco]

            TP = sums[eco]["TP"]
            FP = sums[eco]["FP"]
            FN = sums[eco]["FN"]

            total["TP"] += TP
            total["FP"] += FP
            total["FN"] += FN

            recall = TP / (TP + FN) if (TP + FN) else 0
            overlap = TP / (TP + FP) if (TP + FP) else 0

            f.write(
                f"{eco} & {gt['Components']} & {gt['Vulnerabilities']} & "
                f"{TP} & {FP} & {FN} & "
                f"{recall:.2f} & {overlap:.2f} \\\\\n"
            )

        recall_total = total["TP"] / (total["TP"] + total["FN"]) if (total["TP"] + total["FN"]) else 0
        overlap_total = total["TP"] / (total["TP"] + total["FP"]) if (total["TP"] + total["FP"]) else 0

        f.write("\\midrule\n")
        f.write(
            f"TOTAL & - & - & {total['TP']} & {total['FP']} & {total['FN']} & "
            f"{recall_total:.2f} & {overlap_total:.2f} \\\\\n"
        )

        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")
        f.write("\\end{table*}\n")