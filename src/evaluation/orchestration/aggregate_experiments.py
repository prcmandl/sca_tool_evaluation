from __future__ import annotations

import argparse
import json
from pathlib import Path

from evaluation.analysis.statistics import (
    add_confidence_intervals,
    aggregate,
    build_gt_summary,
    write_ecosystem_summary_table,
    write_latex_stats,
)
from evaluation.core.ground_truth import load_ground_truth

try:
    from evaluation.analysis.plots_save import plot_tool_comparison
except Exception:
    plot_tool_comparison = None


def summarize_tool_metrics(metrics: dict) -> dict:
    summary = {}
    for tool, ecos in metrics.items():
        recalls = [v["Recall"]["mean"] for v in ecos.values()]
        overlaps = [v["Overlap"]["mean"] for v in ecos.values()]
        tps = [v["TP"]["mean"] for v in ecos.values()]
        fps = [v["FP"]["mean"] for v in ecos.values()]
        fns = [v["FN"]["mean"] for v in ecos.values()]
        summary[tool] = {
            "avg_recall": float(sum(recalls) / len(recalls)) if recalls else 0.0,
            "avg_overlap": float(sum(overlaps) / len(overlaps)) if overlaps else 0.0,
            "sum_tp": float(sum(tps)),
            "sum_fp": float(sum(fps)),
            "sum_fn": float(sum(fns)),
        }
    return summary


def build_tool_comparison_summary(agg: dict) -> dict:
    tool_summary = summarize_tool_metrics(agg)
    ranked = sorted(
        tool_summary.items(),
        key=lambda kv: (-kv[1]["avg_recall"], -kv[1]["avg_overlap"], kv[0]),
    )

    pairwise = []
    tools = list(tool_summary.keys())
    for i, tool_a in enumerate(tools):
        for tool_b in tools[i + 1:]:
            a = tool_summary[tool_a]
            b = tool_summary[tool_b]
            pairwise.append(
                {
                    "tool_a": tool_a,
                    "tool_b": tool_b,
                    "delta_avg_recall": float(a["avg_recall"] - b["avg_recall"]),
                    "delta_avg_overlap": float(a["avg_overlap"] - b["avg_overlap"]),
                    "delta_sum_tp": float(a["sum_tp"] - b["sum_tp"]),
                    "delta_sum_fp": float(a["sum_fp"] - b["sum_fp"]),
                    "delta_sum_fn": float(a["sum_fn"] - b["sum_fn"]),
                }
            )

    return {
        "per_tool": tool_summary,
        "ranking_by_avg_recall": [{"tool": tool, **vals} for tool, vals in ranked],
        "pairwise_deltas": pairwise,
    }


def write_tool_comparison_outputs(experiment_dir: Path, summary: dict) -> None:
    (experiment_dir / "tool_comparison_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    with (experiment_dir / "tool_comparison_summary.txt").open("w", encoding="utf-8") as f:
        f.write("TOOL COMPARISON SUMMARY\n")
        f.write("========================================\n\n")
        f.write("RANKING BY AVERAGE RECALL\n")
        f.write("----------------------------------------\n")
        for idx, row in enumerate(summary["ranking_by_avg_recall"], start=1):
            f.write(
                f"{idx}. {row['tool']}: avg_recall={row['avg_recall']:.4f}, "
                f"avg_overlap={row['avg_overlap']:.4f}, "
                f"sum_tp={row['sum_tp']:.2f}, "
                f"sum_fp={row['sum_fp']:.2f}, "
                f"sum_fn={row['sum_fn']:.2f}\n"
            )

        f.write("\nPAIRWISE DELTAS\n")
        f.write("----------------------------------------\n")
        for row in summary["pairwise_deltas"]:
            f.write(
                f"{row['tool_a']} vs {row['tool_b']}: "
                f"d_recall={row['delta_avg_recall']:.4f}, "
                f"d_overlap={row['delta_avg_overlap']:.4f}, "
                f"d_tp={row['delta_sum_tp']:.2f}, "
                f"d_fp={row['delta_sum_fp']:.2f}, "
                f"d_fn={row['delta_sum_fn']:.2f}\n"
            )


def aggregate_experiment(experiment_dir: Path, ground_truth_path: Path) -> dict:
    run_dirs = sorted(p for p in experiment_dir.glob("run_*") if p.is_dir())

    data = []
    for rd in run_dirs:
        result_file = rd / "results.json"
        if result_file.exists():
            payload = json.loads(result_file.read_text(encoding="utf-8"))
            if payload:
                data.append(payload)

    if not data:
        raise RuntimeError("No run data found")

    agg = aggregate(data)
    agg = add_confidence_intervals(agg)

    gt = load_ground_truth(ground_truth_path)
    gt_summary = build_gt_summary(gt)

    (experiment_dir / "stats.json").write_text(
        json.dumps({"metrics": agg}, indent=2),
        encoding="utf-8",
    )

    write_latex_stats(
        agg,
        gt_summary,
        experiment_dir / "aggregated_results.tex",
    )
    write_ecosystem_summary_table(
        agg,
        gt_summary,
        experiment_dir / "ecosystem_summary.tex",
    )

    if plot_tool_comparison is not None:
        plot_tool_comparison(agg, str(experiment_dir))

    tool_summary = build_tool_comparison_summary(agg)
    write_tool_comparison_outputs(experiment_dir, tool_summary)

    return {
        "metrics": agg,
        "tool_comparison": tool_summary,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--experiment-dir", required=True)
    ap.add_argument("--ground-truth", required=True)
    args = ap.parse_args()

    aggregate_experiment(
        experiment_dir=Path(args.experiment_dir),
        ground_truth_path=Path(args.ground_truth),
    )
    print(json.dumps({"status": "ok"}, indent=2))


if __name__ == "__main__":
    main()