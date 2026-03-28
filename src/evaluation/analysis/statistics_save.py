import os
import json
import statistics
from pathlib import Path
from typing import List, Dict
from scipy.stats import ttest_rel


# ------------------------------------------------------------
# Load run data
# ------------------------------------------------------------
def load_runs(run_dirs: List[str]):
    data = []

    for rd in run_dirs:
        p = Path(rd) / "experimental_results.json"
        if p.exists():
            with open(p) as f:
                data.append(json.load(f))

    return data


# ------------------------------------------------------------
# Aggregate metrics
# ------------------------------------------------------------
def aggregate(data):
    agg = {}

    tools = data[0].keys()

    for tool in tools:
        agg[tool] = {}

        ecosystems = data[0][tool].keys()

        for eco in ecosystems:
            agg[tool][eco] = {}

            for metric in ["TP", "FP", "FN", "Recall", "Overlap"]:
                values = [run[tool][eco][metric] for run in data]

                agg[tool][eco][metric] = {
                    "values": values,
                    "mean": statistics.mean(values),
                    "std": statistics.pstdev(values) if len(values) > 1 else 0.0,
                }

    return agg


# ------------------------------------------------------------
# Confidence intervals
# ------------------------------------------------------------
def add_confidence_intervals(agg):
    import math

    for tool in agg:
        for eco in agg[tool]:
            for metric, d in agg[tool][eco].items():
                n = len(d["values"])
                if n <= 1:
                    d["ci95"] = 0.0
                    continue

                d["ci95"] = 1.96 * d["std"] / math.sqrt(n)

    return agg


# ------------------------------------------------------------
# Significance (paired t-test)
# ------------------------------------------------------------
def compute_significance(agg):
    tools = list(agg.keys())
    significance = {}

    for i, t1 in enumerate(tools):
        for t2 in tools[i+1:]:
            key = f"{t1}_vs_{t2}"
            significance[key] = {}

            for eco in agg[t1]:
                r1 = agg[t1][eco]["Recall"]["values"]
                r2 = agg[t2][eco]["Recall"]["values"]

                if len(r1) > 1:
                    _, p = ttest_rel(r1, r2)
                    significance[key][eco] = p
                else:
                    significance[key][eco] = None

    return significance


# ------------------------------------------------------------
# Ground truth summary
# ------------------------------------------------------------
def build_gt_summary(gt):
    summary = {}

    ecosystems = sorted({g.ecosystem for g in gt})

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
# Per-tool LaTeX (mean ± CI)
# ------------------------------------------------------------
def write_latex_stats(agg, gt_summary, output_file):

    def fmt(x, is_float=True):
        if is_float:
            return f"{x['mean']:.2f} $\\pm$ {x['ci95']:.2f}"
        else:
            return f"{int(round(x['mean']))}"

    ecosystems = sorted(gt_summary.keys())

    with open(output_file, "w") as f:
        f.write("\\begin{table*}[!t]\n\\centering\n\\small\n")
        f.write("\\setlength{\\tabcolsep}{4pt}\n")
        f.write("\\renewcommand{\\arraystretch}{1.1}\n\n")

        f.write("\\begin{tabular}{lrrrrrrrr}\n\\toprule\n")
        f.write(
            "Ecosystem & Components & Vulnerabilities & CVEs "
            "& TP & FP & FN & Recall & Overlap \\\\\n"
        )
        f.write("\\midrule\n\n")

        for tool, ecos in agg.items():
            f.write(f"\\multicolumn{{9}}{{c}}{{\\textbf{{{tool}}}}} \\\\\n")
            f.write("\\midrule\n")

            total_tp = total_fp = total_fn = 0

            for eco in ecosystems:
                row = ecos[eco]
                gt = gt_summary[eco]

                tp = row["TP"]
                fp = row["FP"]
                fn = row["FN"]
                r = row["Recall"]
                o = row["Overlap"]

                total_tp += tp["mean"]
                total_fp += fp["mean"]
                total_fn += fn["mean"]

                f.write(
                    f"{eco} & {gt['Components']} & {gt['Vulnerabilities']} & {gt['CVEs']} & "
                    f"{fmt(tp, False)} & {fmt(fp, False)} & {fmt(fn, False)} & "
                    f"{fmt(r)} & {fmt(o)} \\\\\n"
                )

            recall = total_tp / (total_tp + total_fn) if total_tp + total_fn else 0
            overlap = total_tp / (total_tp + total_fp) if total_tp + total_fp else 0

            total_gt = {
                "Components": sum(v["Components"] for v in gt_summary.values()),
                "Vulnerabilities": sum(v["Vulnerabilities"] for v in gt_summary.values()),
                "CVEs": sum(v["CVEs"] for v in gt_summary.values()),
            }

            f.write(
                f"TOTAL & {total_gt['Components']} & {total_gt['Vulnerabilities']} & {total_gt['CVEs']} & "
                f"{int(round(total_tp))} & {int(round(total_fp))} & {int(round(total_fn))} & "
                f"{recall:.2f} & {overlap:.2f} \\\\\n"
            )

            f.write("\\midrule\n\n")

        f.write("\\bottomrule\n\\end{tabular}\n\\end{table*}\n")


# ------------------------------------------------------------
# Ecosystem summary (weighted!)
# ------------------------------------------------------------
def write_ecosystem_summary_table(agg, gt_summary, output_file):

    allowed_tools = set(os.environ.get("EVAL_TOOLS", "").split())
    ecosystems = sorted(gt_summary.keys())

    with open(output_file, "w") as f:
        f.write("\\begin{table*}[!t]\n\\centering\n\\small\n")
        f.write("\\setlength{\\tabcolsep}{4pt}\n")
        f.write("\\renewcommand{\\arraystretch}{1.12}\n\n")

        f.write("\\begin{tabular}{lrrrrrrr}\n\\toprule\n")
        f.write(
            "Ecosystem & Components & Vulnerabilities "
            "& $\\sum TP$ & $\\sum FP$ & $\\sum FN$ "
            "& Mean Recall & Mean Overlap \\\\\n"
        )
        f.write("\\midrule\n")

        total_tp = total_fp = total_fn = 0
        total_components = total_vulns = 0

        for eco in ecosystems:
            gt = gt_summary[eco]

            tp_sum = fp_sum = fn_sum = 0

            for tool in agg:
                if allowed_tools and tool not in allowed_tools:
                    continue

                row = agg[tool][eco]

                tp_sum += row["TP"]["mean"]
                fp_sum += row["FP"]["mean"]
                fn_sum += row["FN"]["mean"]

            recall = tp_sum / (tp_sum + fn_sum) if tp_sum + fn_sum else 0
            overlap = tp_sum / (tp_sum + fp_sum) if tp_sum + fp_sum else 0

            f.write(
                f"{eco} & {gt['Components']} & {gt['Vulnerabilities']} & "
                f"{int(round(tp_sum))} & {int(round(fp_sum))} & {int(round(fn_sum))} & "
                f"{recall:.2f} & {overlap:.2f} \\\\\n"
            )

            total_tp += tp_sum
            total_fp += fp_sum
            total_fn += fn_sum
            total_components += gt["Components"]
            total_vulns += gt["Vulnerabilities"]

        total_recall = total_tp / (total_tp + total_fn) if total_tp + total_fn else 0
        total_overlap = total_tp / (total_tp + total_fp) if total_tp + total_fp else 0

        f.write("\\midrule\n")
        f.write(
            f"TOTAL & {total_components} & {total_vulns} & "
            f"{int(round(total_tp))} & {int(round(total_fp))} & {int(round(total_fn))} & "
            f"{total_recall:.2f} & {total_overlap:.2f} \\\\\n"
        )

        f.write("\\bottomrule\n\\end{tabular}\n\\end{table*}\n")