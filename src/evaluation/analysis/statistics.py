from __future__ import annotations

import statistics
from typing import List


# ------------------------------------------------------------
# Aggregation of multiple runs
# ------------------------------------------------------------
def aggregate(data: List[dict]) -> dict:
    if not data:
        return {}

    agg = {}
    tools = data[0].keys()

    for tool in tools:
        agg[tool] = {}
        ecosystems = data[0][tool].keys()

        for eco in ecosystems:
            metrics = ["TP", "FP", "FN", "Recall", "Overlap"]
            agg[tool][eco] = {}

            for metric in metrics:
                values = [run[tool][eco][metric] for run in data]
                n = len(values)

                agg[tool][eco][metric] = {
                    "mean": statistics.mean(values),
                    "std": statistics.pstdev(values) if n > 1 else 0.0,
                    "n": n,
                }

    return agg


# ------------------------------------------------------------
# Confidence intervals
# ------------------------------------------------------------
def add_confidence_intervals(agg: dict) -> dict:
    for tool in agg:
        for eco in agg[tool]:
            for metric in agg[tool][eco]:
                std = agg[tool][eco][metric]["std"]
                n = agg[tool][eco][metric].get("n", 1)
                ci95 = 1.96 * std / (n ** 0.5) if n > 1 else 0.0
                agg[tool][eco][metric]["ci95"] = ci95

    return agg


# ------------------------------------------------------------
# Ground truth summary
# ------------------------------------------------------------
def build_gt_summary(gt):
    ecosystems = sorted({g.ecosystem for g in gt})
    summary = {}

    for eco in ecosystems:
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
# LaTeX (main table)
# ------------------------------------------------------------
def write_latex_stats(agg, gt_summary, output_file, markers=None):
    markers = markers or {}

    def fmt(metric):
        return f"{metric['mean']:.2f}"

    total_components = sum(v.get("Components", 0) for v in gt_summary.values())
    total_vulnerabilities = sum(v.get("Vulnerabilities", 0) for v in gt_summary.values())
    total_cves = sum(v.get("CVEs", 0) for v in gt_summary.values())

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\\begin{table*}[!t]\n\\centering\n\\small\n")
        f.write("\\begin{tabular}{lrrrrrrrr}\n\\toprule\n")
        f.write("Ecosystem & Components & Vulnerabilities & CVEs & TP & FP & FN & Recall & Overlap \\\\\n\\midrule\n")

        for tool, ecos in agg.items():
            f.write(f"\\multicolumn{{9}}{{c}}{{\\textbf{{{tool}}}}} \\\\\n\\midrule\n")

            total_tp = 0.0
            total_fp = 0.0
            total_fn = 0.0
            recall_values = []
            overlap_values = []

            for eco, row in ecos.items():
                gt = gt_summary.get(eco, {})
                marker = markers.get(tool, "")

                tp = row["TP"]["mean"]
                fp = row["FP"]["mean"]
                fn = row["FN"]["mean"]

                total_tp += tp
                total_fp += fp
                total_fn += fn

                recall_values.append(row["Recall"]["mean"])
                overlap_values.append(row["Overlap"]["mean"])

                f.write(
                    f"{eco} & "
                    f"{gt.get('Components', 0)} & "
                    f"{gt.get('Vulnerabilities', 0)} & "
                    f"{gt.get('CVEs', 0)} & "
                    f"{int(tp)} & "
                    f"{int(fp)} & "
                    f"{int(fn)} & "
                    f"{fmt(row['Recall'])}{marker} & "
                    f"{fmt(row['Overlap'])} \\\\\n"
                )

            total_recall = sum(recall_values) / len(recall_values) if recall_values else 0.0
            total_overlap = sum(overlap_values) / len(overlap_values) if overlap_values else 0.0
            marker = markers.get(tool, "")

            f.write("\\midrule\n")
            f.write(
                f"\\textbf{{TOTAL}} & "
                f"{total_components} & "
                f"{total_vulnerabilities} & "
                f"{total_cves} & "
                f"{int(total_tp)} & "
                f"{int(total_fp)} & "
                f"{int(total_fn)} & "
                f"{total_recall:.2f}{marker} & "
                f"{total_overlap:.2f} \\\\\n"
            )
            f.write("\\midrule\n")

        f.write("\\bottomrule\n\\end{tabular}\n\\end{table*}\n")


# ------------------------------------------------------------
# Ecosystem summary
# ------------------------------------------------------------
def write_ecosystem_summary_table(agg, gt_summary, output_file):
    ecosystems = sorted(gt_summary.keys())

    total_components = 0
    total_vulnerabilities = 0
    total_tp = 0.0
    total_fp = 0.0
    total_fn = 0.0
    total_rec = 0.0
    total_ov = 0.0

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\\begin{table*}[!t]\n\\centering\n\\small\n")
        f.write("\\begin{tabular}{lrrrrrrr}\n\\toprule\n")
        f.write(
            "Ecosystem & Components & Vulnerabilities & $\\sum TP$ & $\\sum FP$ & $\\sum FN$ & Mean Recall & Mean Overlap \\\\\n\\midrule\n"
        )

        for eco in ecosystems:
            tp = fp = fn = rec = ov = 0.0
            n = len(agg)

            for tool in agg:
                tp += agg[tool][eco]["TP"]["mean"]
                fp += agg[tool][eco]["FP"]["mean"]
                fn += agg[tool][eco]["FN"]["mean"]
                rec += agg[tool][eco]["Recall"]["mean"]
                ov += agg[tool][eco]["Overlap"]["mean"]

            rec /= n
            ov /= n

            gt = gt_summary[eco]

            total_components += gt["Components"]
            total_vulnerabilities += gt["Vulnerabilities"]
            total_tp += tp
            total_fp += fp
            total_fn += fn
            total_rec += rec
            total_ov += ov

            f.write(
                f"{eco} & {gt['Components']} & {gt['Vulnerabilities']} & "
                f"{int(tp)} & {int(fp)} & {int(fn)} & "
                f"{rec:.2f} & {ov:.2f} \\\\\n"
            )

        total_mean_recall = total_rec / len(ecosystems) if ecosystems else 0.0
        total_mean_overlap = total_ov / len(ecosystems) if ecosystems else 0.0

        f.write("\\midrule\n")
        f.write(
            f"\\textbf{{TOTAL}} & {total_components} & {total_vulnerabilities} & "
            f"{int(total_tp)} & {int(total_fp)} & {int(total_fn)} & "
            f"{total_mean_recall:.2f} & {total_mean_overlap:.2f} \\\\\n"
        )

        f.write("\\bottomrule\n\\end{tabular}\n\\end{table*}\n")

# ------------------------------------------------------------
# Compute significance markers for main table
# ------------------------------------------------------------
def compute_significance_markers(rows, baseline="oss-index"):
    markers = {}

    for r in rows:
        a = r["tool_a"]
        b = r["tool_b"]

        if baseline not in (a, b):
            continue

        if r["p_adj"] >= 0.05:
            continue

        if a == baseline:
            better = b if r["n01"] > r["n10"] else None
        else:
            better = a if r["n10"] > r["n01"] else None

        if better:
            markers[better] = "*"

    return markers