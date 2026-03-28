#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from evaluation.analysis.statistics import (
    aggregate,
    add_confidence_intervals,
    write_latex_stats,
    write_ecosystem_summary_table,
    build_gt_summary,
)
from evaluation.core.ground_truth import load_ground_truth

try:
    from evaluation.analysis.plots import plot_tool_comparison
except Exception:
    plot_tool_comparison = None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiment-dir", required=True)
    parser.add_argument("--ground-truth", required=True)
    args = parser.parse_args()

    experiment_dir = Path(args.experiment_dir)
    ground_truth_path = Path(args.ground_truth)
    run_dirs = sorted(p for p in experiment_dir.glob("run_*") if p.is_dir())

    data = []
    for run_dir in run_dirs:
        result_file = run_dir / "results.json"
        if result_file.exists():
            with result_file.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
                if payload:
                    data.append(payload)

    if not data:
        print("[STATS] No run data found -> skipping aggregation")
        raise SystemExit(0)

    agg = aggregate(data)
    agg = add_confidence_intervals(agg)

    ground_truth = load_ground_truth(ground_truth_path)
    gt_summary = build_gt_summary(ground_truth)

    with (experiment_dir / "stats.json").open("w", encoding="utf-8") as handle:
        json.dump({"metrics": agg}, handle, indent=2)

    write_latex_stats(agg, gt_summary, experiment_dir / "aggregated_results.tex")
    write_ecosystem_summary_table(agg, gt_summary, experiment_dir / "ecosystem_summary.tex")

    if plot_tool_comparison is not None:
        plot_tool_comparison(agg, experiment_dir / "tool_comparison.png")


if __name__ == "__main__":
    main()
