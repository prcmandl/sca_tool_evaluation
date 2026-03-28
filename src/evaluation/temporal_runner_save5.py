from __future__ import annotations

"""
Temporal runner for the simplified temporal evaluation protocol.

RESPONSIBILITY
----------------------------------------------------------------
This module performs exactly one temporal evaluation attempt for a
single run_<i> directory.

It does NOT build ground truth snapshots and it does NOT retry the
full workflow. Those responsibilities remain in run_experiment_save7.sh.

SIMPLIFIED PROTOCOL INSIDE THIS MODULE
----------------------------------------------------------------
Given GT0 and its SBOM:

    1) Run all tools once   -> repeat_1
    2) Run all tools again  -> repeat_2
    3) Compare tool findings between both repeats
    4) Always write the repeat comparison outputs
    5) If tool findings differ:
           exit with code 2 (TOOL_MISMATCH)
    6) If tool findings match:
           write metrics, significance outputs, plots, and
           tool comparison summaries
           exit with code 0
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable

from evaluation.analysis.plots_save import (
    plot_significance_matrix,
    plot_tool_comparison,
)
from evaluation.analysis.significance import (
    build_detection_matrix,
    cochran_q_test,
    holm,
    pairwise_mcnemar,
    write_significance_latex,
)
from evaluation.analysis.statistics import (
    add_confidence_intervals,
    aggregate,
    build_gt_summary,
    write_ecosystem_summary_table,
    write_latex_stats,
)
from evaluation.core.ground_truth import load_ground_truth
from evaluation.core.model import Finding
from evaluation.evaluate import run_evaluation

log = logging.getLogger("evaluation.temporal")


def get_tools() -> list[str]:
    """Read the configured tool list at runtime."""
    return os.environ.get(
        "EVAL_TOOLS",
        "dtrack oss-index github snyk trivy",
    ).split()


def setup_logger(run_dir: Path) -> None:
    """Configure run.log with time-only timestamps."""
    log.setLevel(logging.INFO)
    log.propagate = False

    for handler in list(log.handlers):
        log.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass

    fh = logging.FileHandler(run_dir / "run.log", mode="w")
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-5s | %(message)s",
        datefmt="%H:%M:%S",
    ))
    log.addHandler(fh)


def hash_findings(findings: Iterable[Finding]) -> str:
    """Build a deterministic hash for a tool's findings list."""
    payload = sorted(
        [f.ecosystem, f.component, f.version, f.cve or f.osv_id or ""]
        for f in findings
    )
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def compute_significance_markers(rows, baseline: str = "oss-index"):
    """Mark tools that significantly outperform the baseline."""
    markers = {}

    for row in rows:
        a = row["tool_a"]
        b = row["tool_b"]

        if baseline not in (a, b):
            continue

        if row["p_adj"] >= 0.05:
            continue

        if a == baseline:
            better = b if row["n01"] > row["n10"] else None
        else:
            better = a if row["n10"] > row["n01"] else None

        if better:
            markers[better] = "*"

    return markers


@contextmanager
def working_directory(path: Path):
    """Temporarily switch the process working directory."""
    previous = Path.cwd()
    path.mkdir(parents=True, exist_ok=True)
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


@contextmanager
def tool_output_environment(tool_dir: Path):
    """
    Temporarily redirect all known output-related environment variables
    to the current tool artifact directory.
    """
    old_values = {
        "EVAL_ARTIFACTS_DIR": os.environ.get("EVAL_ARTIFACTS_DIR"),
        "TOOL_OUTPUT_DIR": os.environ.get("TOOL_OUTPUT_DIR"),
        "OUTPUT_DIR": os.environ.get("OUTPUT_DIR"),
        "GROUND_TRUTH_BUILD_PATH": os.environ.get("GROUND_TRUTH_BUILD_PATH"),
    }

    os.environ["EVAL_ARTIFACTS_DIR"] = str(tool_dir)
    os.environ["TOOL_OUTPUT_DIR"] = str(tool_dir)
    os.environ["OUTPUT_DIR"] = str(tool_dir)
    os.environ["GROUND_TRUTH_BUILD_PATH"] = str(tool_dir)

    try:
        yield
    finally:
        for key, old_value in old_values.items():
            if old_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old_value


def tool_artifact_dir(run_dir: Path, repeat_idx: int, tool: str) -> Path:
    """Return the canonical artifact directory for one tool repeat."""
    return run_dir / "artifacts" / f"repeat_{repeat_idx + 1}" / tool


def prepare_tool_inputs(
    tool_dir: Path,
    gt_path: Path,
    sbom_path: Path | None,
) -> tuple[Path, Path | None]:
    """
    Copy GT and SBOM into the tool directory and return the local paths.

    This prevents adapters from writing artifacts next to the original
    GT/SBOM files under ground_truth_build/.
    """
    tool_dir.mkdir(parents=True, exist_ok=True)

    local_gt = tool_dir / gt_path.name
    shutil.copy2(gt_path, local_gt)

    local_sbom = None
    if sbom_path is not None and sbom_path.exists():
        local_sbom = tool_dir / sbom_path.name
        shutil.copy2(sbom_path, local_sbom)

    return local_gt, local_sbom


def write_run_status(path: Path, status: str, message: str, extra: dict | None = None) -> None:
    payload = {
        "status": status,
        "message": message,
    }
    if extra:
        payload.update(extra)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def build_repeat_comparison_summary(
    runs: list[dict],
    repeat_hashes: list[dict],
    tools: list[str],
) -> dict:
    """
    Compare repeat_1 vs repeat_2 for every tool and expose both hashes
    and per-ecosystem metric deltas.
    """
    repeat_1 = runs[0]
    repeat_2 = runs[1]

    per_tool = {}
    for tool in tools:
        metrics_1 = repeat_1[tool]["metrics"]
        metrics_2 = repeat_2[tool]["metrics"]
        ecosystems = sorted(set(metrics_1.keys()) | set(metrics_2.keys()))

        per_eco = {}
        for eco in ecosystems:
            eco_1 = metrics_1.get(eco, {})
            eco_2 = metrics_2.get(eco, {})
            metric_rows = {}
            for metric in ["TP", "FP", "FN", "Recall", "Overlap"]:
                v1 = float(eco_1.get(metric, 0.0))
                v2 = float(eco_2.get(metric, 0.0))
                metric_rows[metric] = {
                    "repeat_1": v1,
                    "repeat_2": v2,
                    "delta_repeat2_minus_repeat1": float(v2 - v1),
                }
            per_eco[eco] = metric_rows

        per_tool[tool] = {
            "repeat_1_hash": repeat_hashes[0][tool],
            "repeat_2_hash": repeat_hashes[1][tool],
            "identical": bool(repeat_hashes[0][tool] == repeat_hashes[1][tool]),
            "per_ecosystem_metrics": per_eco,
        }

    identical_tools = [tool for tool, row in per_tool.items() if row["identical"]]
    differing_tools = [tool for tool, row in per_tool.items() if not row["identical"]]

    return {
        "identical_all_tools": bool(len(differing_tools) == 0),
        "identical_tools": identical_tools,
        "differing_tools": differing_tools,
        "per_tool": per_tool,
    }


def write_repeat_comparison_outputs(run_dir: Path, summary: dict) -> None:
    """Write JSON and TXT outputs for repeat_1 vs repeat_2 comparison."""
    (run_dir / "tool_repeat_comparison.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    with (run_dir / "tool_repeat_comparison.txt").open("w", encoding="utf-8") as f:
        f.write("TOOL REPEAT COMPARISON\n")
        f.write("========================================\n\n")
        f.write(f"Identical across all tools: {summary['identical_all_tools']}\n")
        f.write(f"Identical tools: {', '.join(summary['identical_tools']) if summary['identical_tools'] else '-'}\n")
        f.write(f"Differing tools: {', '.join(summary['differing_tools']) if summary['differing_tools'] else '-'}\n\n")

        for tool, row in summary["per_tool"].items():
            f.write(f"{tool}\n")
            f.write("----------------------------------------\n")
            f.write(f"repeat_1_hash: {row['repeat_1_hash']}\n")
            f.write(f"repeat_2_hash: {row['repeat_2_hash']}\n")
            f.write(f"identical:     {row['identical']}\n")

            for eco, metrics in row["per_ecosystem_metrics"].items():
                f.write(f"  ecosystem={eco}\n")
                for metric_name, metric_vals in metrics.items():
                    f.write(
                        f"    {metric_name}: "
                        f"r1={metric_vals['repeat_1']:.6f}, "
                        f"r2={metric_vals['repeat_2']:.6f}, "
                        f"delta={metric_vals['delta_repeat2_minus_repeat1']:.6f}\n"
                    )
            f.write("\n")


def build_tool_comparison_summary(final_metrics: dict, significance_rows: list[dict]) -> dict:
    """
    Build a compact comparison summary across tools using per-ecosystem
    metrics and, where available, pairwise McNemar/Holm results.
    """
    per_tool = {}
    for tool, ecos in final_metrics.items():
        recalls = [v["Recall"] for v in ecos.values()]
        overlaps = [v["Overlap"] for v in ecos.values()]
        tps = [v["TP"] for v in ecos.values()]
        fps = [v["FP"] for v in ecos.values()]
        fns = [v["FN"] for v in ecos.values()]
        per_tool[tool] = {
            "avg_recall": float(sum(recalls) / len(recalls)) if recalls else 0.0,
            "avg_overlap": float(sum(overlaps) / len(overlaps)) if overlaps else 0.0,
            "sum_tp": float(sum(tps)),
            "sum_fp": float(sum(fps)),
            "sum_fn": float(sum(fns)),
        }

    ranked = sorted(
        per_tool.items(),
        key=lambda kv: (-kv[1]["avg_recall"], -kv[1]["avg_overlap"], kv[0]),
    )

    sig_map = {
        frozenset((row["tool_a"], row["tool_b"])): row
        for row in significance_rows
    }

    pairwise = []
    tools = list(per_tool.keys())
    for i, tool_a in enumerate(tools):
        for tool_b in tools[i + 1:]:
            a = per_tool[tool_a]
            b = per_tool[tool_b]
            sig = sig_map.get(frozenset((tool_a, tool_b)))

            p_adj = None
            if sig and sig.get("p_adj") is not None:
                p_adj = float(sig["p_adj"])

            pairwise.append(
                {
                    "tool_a": tool_a,
                    "tool_b": tool_b,
                    "delta_avg_recall": float(a["avg_recall"] - b["avg_recall"]),
                    "delta_avg_overlap": float(a["avg_overlap"] - b["avg_overlap"]),
                    "delta_sum_tp": float(a["sum_tp"] - b["sum_tp"]),
                    "delta_sum_fp": float(a["sum_fp"] - b["sum_fp"]),
                    "delta_sum_fn": float(a["sum_fn"] - b["sum_fn"]),
                    "mcnemar_p_adj": p_adj,
                    "mcnemar_significant": (bool(p_adj < 0.05) if p_adj is not None else None),
                }
            )

    return {
        "per_tool": per_tool,
        "ranking_by_avg_recall": [{"tool": tool, **vals} for tool, vals in ranked],
        "pairwise_deltas": pairwise,
    }


def write_tool_comparison_outputs(run_dir: Path, summary: dict) -> None:
    """Write JSON and TXT summaries of the tool comparison."""
    (run_dir / "tool_comparison_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    with (run_dir / "tool_comparison_summary.txt").open("w", encoding="utf-8") as f:
        f.write("TOOL COMPARISON SUMMARY\n")
        f.write("========================================\n\n")
        f.write("RANKING BY AVERAGE RECALL\n")
        f.write("----------------------------------------\n")
        for idx, row in enumerate(summary["ranking_by_avg_recall"], start=1):
            f.write(
                f"{idx}. {row['tool']}: avg_recall={row['avg_recall']:.4f}, "
                f"avg_overlap={row['avg_overlap']:.4f}, "
                f"sum_tp={row['sum_tp']:.2f}, sum_fp={row['sum_fp']:.2f}, sum_fn={row['sum_fn']:.2f}\n"
            )

        f.write("\nPAIRWISE DELTAS\n")
        f.write("----------------------------------------\n")
        for row in summary["pairwise_deltas"]:
            sig_text = (
                f", p_adj={row['mcnemar_p_adj']:.6g}, significant={row['mcnemar_significant']}"
                if row["mcnemar_p_adj"] is not None
                else ""
            )
            f.write(
                f"{row['tool_a']} vs {row['tool_b']}: "
                f"d_recall={row['delta_avg_recall']:.4f}, "
                f"d_overlap={row['delta_avg_overlap']:.4f}, "
                f"d_tp={row['delta_sum_tp']:.2f}, "
                f"d_fp={row['delta_sum_fp']:.2f}, "
                f"d_fn={row['delta_sum_fn']:.2f}"
                f"{sig_text}\n"
            )


def run_temporal(gt_path: str, sbom_path: str | None, output_dir: str) -> None:
    """
    Execute exactly two tool repeats for one run directory.

    Exit codes:
        0 -> success, tool findings stable across both repeats
        2 -> TOOL_MISMATCH
    """
    start_time = time.time()

    tools = get_tools()

    gt_path = Path(gt_path)
    sbom = Path(sbom_path) if sbom_path else None
    run_dir = Path(output_dir)
    artifacts_dir = run_dir / "artifacts"

    run_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    setup_logger(run_dir)

    gt0 = load_ground_truth(gt_path)
    runs = []
    repeat_hashes = []

    for repeat_idx in range(2):
        log.info("REPEAT %d/2", repeat_idx + 1)
        run_result = {}
        repeat_hash_row = {}

        for tool in tools:
            tool_dir = tool_artifact_dir(run_dir, repeat_idx, tool)
            local_gt, local_sbom = prepare_tool_inputs(tool_dir, gt_path, sbom)

            log.info("Running tool=%s artifact_dir=%s", tool, tool_dir)
            log.info("Tool-local GT=%s", local_gt)
            if local_sbom is not None:
                log.info("Tool-local SBOM=%s", local_sbom)

            old_ground_truth = os.environ.get("GROUND_TRUTH")
            old_sbom = os.environ.get("SBOM_PATH")
            old_snyk_sbom = os.environ.get("SNYK_SBOM_FILE")
            old_trivy_sbom = os.environ.get("TRIVY_SBOM_FILE")

            os.environ["GROUND_TRUTH"] = str(local_gt)
            if local_sbom is not None:
                os.environ["SBOM_PATH"] = str(local_sbom)
                os.environ["SNYK_SBOM_FILE"] = str(local_sbom)
                os.environ["TRIVY_SBOM_FILE"] = str(local_sbom)
            else:
                os.environ.pop("SBOM_PATH", None)
                os.environ.pop("SNYK_SBOM_FILE", None)
                os.environ.pop("TRIVY_SBOM_FILE", None)

            try:
                with tool_output_environment(tool_dir):
                    with working_directory(tool_dir):
                        res = run_evaluation(
                            ground_truth_path=str(local_gt),
                            tool=tool,
                            return_findings=True,
                            return_metrics=True,
                        )
            finally:
                if old_ground_truth is None:
                    os.environ.pop("GROUND_TRUTH", None)
                else:
                    os.environ["GROUND_TRUTH"] = old_ground_truth

                if old_sbom is None:
                    os.environ.pop("SBOM_PATH", None)
                else:
                    os.environ["SBOM_PATH"] = old_sbom

                if old_snyk_sbom is None:
                    os.environ.pop("SNYK_SBOM_FILE", None)
                else:
                    os.environ["SNYK_SBOM_FILE"] = old_snyk_sbom

                if old_trivy_sbom is None:
                    os.environ.pop("TRIVY_SBOM_FILE", None)
                else:
                    os.environ["TRIVY_SBOM_FILE"] = old_trivy_sbom

            finding_hash = hash_findings(res["findings"])
            repeat_hash_row[tool] = finding_hash
            run_result[tool] = {
                "hash": finding_hash,
                "metrics": res["metrics"]["per_ecosystem"],
                "findings": res["findings"],
            }

        runs.append(run_result)
        repeat_hashes.append(repeat_hash_row)

    repeat_comparison_summary = build_repeat_comparison_summary(runs, repeat_hashes, tools)
    write_repeat_comparison_outputs(run_dir, repeat_comparison_summary)

    tools_ok = repeat_comparison_summary["identical_all_tools"]
    log.info("TOOL_CONSISTENT=%s", tools_ok)

    if not tools_ok:
        write_run_status(
            run_dir / "run_status.json",
            "TOOL_MISMATCH",
            "Tool findings differ between repeat_1 and repeat_2.",
            extra={"repeat_hashes": repeat_hashes},
        )
        raise SystemExit(2)

    final_findings = {tool: runs[0][tool]["findings"] for tool in tools}
    final_metrics = {tool: runs[0][tool]["metrics"] for tool in tools}

    matrix = build_detection_matrix(gt0, final_findings)
    q_stat, p_q = cochran_q_test(matrix)

    rows = pairwise_mcnemar(gt0, final_findings)
    rows = holm(rows)

    write_significance_latex(
        q_stat,
        p_q,
        rows,
        run_dir / "recall_significance.tex",
    )

    with (run_dir / "recall_significance.json").open("w", encoding="utf-8") as f:
        json.dump(
            {
                "cochran_q": {
                    "Q": q_stat,
                    "p_value": p_q,
                },
                "pairwise_mcnemar": rows,
            },
            f,
            indent=2,
        )

    plot_significance_matrix(rows, tools, str(run_dir))

    agg = aggregate([final_metrics])
    agg = add_confidence_intervals(agg)

    gt_summary = build_gt_summary(gt0)
    markers = compute_significance_markers(rows)

    write_latex_stats(
        agg,
        gt_summary,
        run_dir / "aggregated_results.tex",
        markers=markers,
    )

    write_ecosystem_summary_table(
        agg,
        gt_summary,
        run_dir / "ecosystem_summary.tex",
    )

    plot_tool_comparison(agg, str(run_dir))

    comparison_summary = build_tool_comparison_summary(final_metrics, rows)
    write_tool_comparison_outputs(run_dir, comparison_summary)

    with (run_dir / "results.json").open("w", encoding="utf-8") as f:
        json.dump(final_metrics, f, indent=2)

    write_run_status(
        run_dir / "run_status.json",
        "SUCCESS",
        "Tool findings are stable across both repeats.",
        extra={"repeat_hashes": repeat_hashes},
    )

    log.info("Total runtime: %.2fs", time.time() - start_time)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--sbom", required=False, default=None)
    ap.add_argument("--output", required=True)

    args = ap.parse_args()
    run_temporal(args.ground_truth, args.sbom, args.output)


if __name__ == "__main__":
    main()
