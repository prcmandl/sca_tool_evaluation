from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from typing import Any, Iterable

import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import binomtest

from evaluation.analysis.significance import (
    cochran_q_test,
    holm,
    write_significance_latex,
)
from evaluation.analysis.statistics import (
    add_confidence_intervals,
    aggregate,
    build_gt_summary,
    compute_significance_markers,
    write_ecosystem_summary_table,
    write_latex_stats,
)
from evaluation.core.ground_truth import load_ground_truth
from evaluation.core.model import Finding
from evaluation.evaluate import run_evaluation

log = logging.getLogger("evaluation.temporal")


# =========================
# Detection-based Significance
# =========================

def build_detection_matrix_from_vectors(detection_vectors_by_tool: dict[str, list[int]]):
    tools = sorted(detection_vectors_by_tool.keys())

    lengths = {len(v) for v in detection_vectors_by_tool.values()}
    if len(lengths) != 1:
        raise ValueError("Detection vectors have inconsistent lengths")

    matrix = np.array([detection_vectors_by_tool[t] for t in tools]).T
    return matrix, tools


def pairwise_mcnemar_from_matrix(matrix: np.ndarray, tools: list[str]):
    rows = []

    for i, j in combinations(range(len(tools)), 2):
        a = matrix[:, i]
        b = matrix[:, j]

        n10 = int(((a == 1) & (b == 0)).sum())
        n01 = int(((a == 0) & (b == 1)).sum())
        n = n10 + n01

        if n == 0:
            p = 1.0
        else:
            p = float(
                binomtest(
                    k=min(n10, n01),
                    n=n,
                    p=0.5,
                    alternative="two-sided",
                ).pvalue
            )

        rows.append(
            {
                "tool_a": tools[i],
                "tool_b": tools[j],
                "n10": n10,
                "n01": n01,
                "p": p,
                "p_adj": None,
            }
        )

    return rows


# =========================
# Helpers
# =========================

def get_tools() -> list[str]:
    return os.environ.get(
        "EVAL_TOOLS",
        "dtrack oss-index github snyk trivy",
    ).split()


def setup_logger(run_dir: Path) -> None:
    log.setLevel(logging.INFO)
    log.propagate = False

    for handler in list(log.handlers):
        log.removeHandler(handler)

    fh = logging.FileHandler(run_dir / "run.log", mode="w")
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-5s | %(message)s",
        datefmt="%H:%M:%S",
    ))
    log.addHandler(fh)


def hash_findings(findings: Iterable[Finding]) -> str:
    payload = sorted(
        [f.ecosystem, f.component, f.version, f.cve or f.osv_id or ""]
        for f in findings
    )
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@contextmanager
def working_directory(path: Path):
    previous = Path.cwd()
    path.mkdir(parents=True, exist_ok=True)
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


@contextmanager
def tool_output_environment(tool_dir: Path):
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
    return run_dir / "artifacts" / f"repeat_{repeat_idx + 1}" / tool


def prepare_tool_inputs(tool_dir: Path, gt_path: Path, sbom_path: Path | None):
    tool_dir.mkdir(parents=True, exist_ok=True)

    local_gt = tool_dir / gt_path.name
    shutil.copy2(gt_path, local_gt)

    local_sbom = None
    if sbom_path and sbom_path.exists():
        local_sbom = tool_dir / sbom_path.name
        shutil.copy2(sbom_path, local_sbom)

    return local_gt, local_sbom


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def extract_repeat_metric_runs(runs: list[dict[str, Any]], tools: list[str]) -> list[dict[str, Any]]:
    return [
        {tool: runs[idx][tool]["metrics"] for tool in tools}
        for idx in range(len(runs))
    ]


def collapse_repeat_metrics(repeat_metric_runs: list[dict[str, Any]], tools: list[str]) -> dict[str, Any]:
    if not repeat_metric_runs:
        return {}

    collapsed: dict[str, Any] = {}

    for tool in tools:
        collapsed[tool] = {}
        ecosystems = repeat_metric_runs[0][tool].keys()

        for eco in ecosystems:
            collapsed[tool][eco] = {}
            metric_names = repeat_metric_runs[0][tool][eco].keys()

            for metric_name in metric_names:
                values = [repeat[tool][eco][metric_name] for repeat in repeat_metric_runs]
                mean_value = sum(values) / len(values)

                if metric_name in {"TP", "FP", "FN", "Components", "Vulnerabilities", "CVEs"}:
                    rounded = round(mean_value)
                    if abs(mean_value - rounded) < 1e-9:
                        collapsed[tool][eco][metric_name] = int(rounded)
                    else:
                        collapsed[tool][eco][metric_name] = float(mean_value)
                else:
                    collapsed[tool][eco][metric_name] = float(mean_value)

    return collapsed


def summarize_tool_metrics(agg: dict[str, Any]) -> list[dict[str, Any]]:
    summary = []

    for tool in sorted(agg.keys()):
        ecosystems = sorted(agg[tool].keys())
        if not ecosystems:
            continue

        mean_recall = sum(agg[tool][eco]["Recall"]["mean"] for eco in ecosystems) / len(ecosystems)
        mean_overlap = sum(agg[tool][eco]["Overlap"]["mean"] for eco in ecosystems) / len(ecosystems)
        total_tp = sum(agg[tool][eco]["TP"]["mean"] for eco in ecosystems)
        total_fp = sum(agg[tool][eco]["FP"]["mean"] for eco in ecosystems)
        total_fn = sum(agg[tool][eco]["FN"]["mean"] for eco in ecosystems)

        summary.append(
            {
                "tool": tool,
                "ecosystems": ecosystems,
                "mean_recall": float(mean_recall),
                "mean_overlap": float(mean_overlap),
                "total_tp": float(total_tp),
                "total_fp": float(total_fp),
                "total_fn": float(total_fn),
            }
        )

    summary.sort(key=lambda row: (-row["mean_recall"], row["tool"]))
    return summary


def summarize_repeat_consistency(
    runs: list[dict[str, Any]],
    repeat_hashes: list[dict[str, str]],
    tools: list[str],
) -> dict[str, Any]:
    comparison: dict[str, Any] = {}

    for tool in tools:
        hashes = [repeat_hashes[idx][tool] for idx in range(len(repeat_hashes))]
        per_repeat = []

        for repeat_idx in range(len(runs)):
            per_repeat.append(
                {
                    "repeat": repeat_idx + 1,
                    "hash": runs[repeat_idx][tool]["hash"],
                    "metrics": runs[repeat_idx][tool]["metrics"],
                }
            )

        comparison[tool] = {
            "stable": len(set(hashes)) == 1,
            "hashes": hashes,
            "repeats": per_repeat,
        }

    return comparison


def render_tool_summary_text(
    tool_summary: list[dict[str, Any]],
    markers: dict[str, str],
    baseline: str,
) -> str:
    lines = [
        f"Baseline for significance markers: {baseline}",
        "",
        "Tool comparison summary",
        "=======================",
    ]

    for row in tool_summary:
        marker = markers.get(row["tool"], "")
        lines.append(
            (
                f"- {row['tool']}{marker}: mean_recall={row['mean_recall']:.4f}, "
                f"mean_overlap={row['mean_overlap']:.4f}, "
                f"total_tp={row['total_tp']:.2f}, total_fp={row['total_fp']:.2f}, "
                f"total_fn={row['total_fn']:.2f}"
            )
        )

    return "\n".join(lines) + "\n"


def render_repeat_comparison_text(repeat_comparison: dict[str, Any]) -> str:
    lines = [
        "Tool repeat comparison",
        "======================",
    ]

    for tool in sorted(repeat_comparison.keys()):
        row = repeat_comparison[tool]
        hashes = ", ".join(row["hashes"])
        lines.append(f"- {tool}: stable={row['stable']} | hashes=[{hashes}]")

    return "\n".join(lines) + "\n"


def plot_significance_matrix(matrix: np.ndarray, tools: list[str], output_path: Path) -> None:
    fig, ax = plt.subplots(figsize=(10, max(4, len(tools) * 0.6)))
    image = ax.imshow(matrix.T, aspect="auto", interpolation="nearest")
    ax.set_title("Recall significance matrix")
    ax.set_xlabel("Ground-truth item index")
    ax.set_ylabel("Tool")
    ax.set_yticks(range(len(tools)))
    ax.set_yticklabels(tools)
    fig.colorbar(image, ax=ax)
    fig.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_tool_comparison(agg: dict[str, Any], output_path: Path) -> None:
    tools = sorted(agg.keys())
    if not tools:
        return

    mean_recalls = []
    for tool in tools:
        ecosystems = sorted(agg[tool].keys())
        if ecosystems:
            value = sum(agg[tool][eco]["Recall"]["mean"] for eco in ecosystems) / len(ecosystems)
        else:
            value = 0.0
        mean_recalls.append(float(value))

    fig, ax = plt.subplots(figsize=(10, 4.5))
    ax.bar(tools, mean_recalls)
    ax.set_title("Tool comparison")
    ax.set_xlabel("Tool")
    ax.set_ylabel("Mean recall")
    ax.set_ylim(0.0, 1.0)
    ax.tick_params(axis="x", rotation=30)
    fig.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def run_temporal(gt_path: str, sbom_path: str | None, output_dir: str) -> None:
    start_time = time.time()
    tools = get_tools()

    gt_path = Path(gt_path)
    sbom = Path(sbom_path) if sbom_path else None
    run_dir = Path(output_dir)

    run_dir.mkdir(parents=True, exist_ok=True)
    setup_logger(run_dir)

    gt0 = load_ground_truth(gt_path)

    runs: list[dict[str, Any]] = []
    repeat_hashes: list[dict[str, str]] = []

    for repeat_idx in range(2):
        log.info("REPEAT %d/2", repeat_idx + 1)
        run_result: dict[str, Any] = {}
        repeat_hash_row: dict[str, str] = {}

        for tool in tools:
            tool_dir = tool_artifact_dir(run_dir, repeat_idx, tool)
            local_gt, local_sbom = prepare_tool_inputs(tool_dir, gt_path, sbom)

            with tool_output_environment(tool_dir):
                with working_directory(tool_dir):
                    res = run_evaluation(
                        ground_truth_path=str(local_gt),
                        tool=tool,
                        return_findings=True,
                        return_metrics=True,
                    )

            if not res:
                raise RuntimeError(f"{tool} returned no structured evaluation payload")

            findings = res["findings"]
            gt_detection = res.get("gt_detection_vector")

            if gt_detection is None:
                raise RuntimeError(f"{tool} did not return gt_detection_vector")

            finding_hash = hash_findings(findings)
            repeat_hash_row[tool] = finding_hash

            run_result[tool] = {
                "hash": finding_hash,
                "metrics": res["metrics"]["per_ecosystem"],
                "gt_detection": gt_detection,
            }

        runs.append(run_result)
        repeat_hashes.append(repeat_hash_row)

    # -----------------------------------
    # Significance
    # -----------------------------------
    detection_vectors_by_tool = {
        tool: runs[0][tool]["gt_detection"]
        for tool in tools
    }

    matrix, tool_order = build_detection_matrix_from_vectors(detection_vectors_by_tool)

    q_stat, p_q = cochran_q_test(matrix)
    rows = pairwise_mcnemar_from_matrix(matrix, tool_order)
    rows = holm(rows)

    write_significance_latex(
        q_stat,
        p_q,
        rows,
        run_dir / "recall_significance.tex",
    )

    recall_significance_payload = {
        "tools": tool_order,
        "matrix_shape": [int(matrix.shape[0]), int(matrix.shape[1])],
        "cochran_q": {
            "statistic": float(q_stat),
            "p_value": float(p_q),
        },
        "pairwise_mcnemar": rows,
    }
    write_json(run_dir / "recall_significance.json", recall_significance_payload)

    plot_significance_matrix(matrix, tool_order, run_dir / "recall_significance_matrix.png")
    plot_significance_matrix(matrix, tool_order, run_dir / "significance_matrix.png")

    # -----------------------------------
    # Aggregation / summaries / plots
    # -----------------------------------
    repeat_metric_runs = extract_repeat_metric_runs(runs, tools)
    agg = add_confidence_intervals(aggregate(repeat_metric_runs))
    gt_summary = build_gt_summary(gt0)
    markers = compute_significance_markers(rows, baseline="oss-index")

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

    collapsed_results = collapse_repeat_metrics(repeat_metric_runs, tools)
    write_json(run_dir / "experimental_results.json", collapsed_results)

    tool_summary = summarize_tool_metrics(agg)
    tool_summary_payload = {
        "baseline": "oss-index",
        "markers": markers,
        "tools": tool_summary,
    }
    write_json(run_dir / "tool_comparison_summary.json", tool_summary_payload)
    write_text(
        run_dir / "tool_comparison_summary.txt",
        render_tool_summary_text(tool_summary, markers, baseline="oss-index"),
    )

    repeat_comparison = summarize_repeat_consistency(runs, repeat_hashes, tools)
    write_json(run_dir / "tool_repeat_comparison.json", repeat_comparison)
    write_text(
        run_dir / "tool_repeat_comparison.txt",
        render_repeat_comparison_text(repeat_comparison),
    )

    plot_tool_comparison(agg, run_dir / "tool_comparison.png")

    duration_seconds = time.time() - start_time
    run_status = {
        "status": "success",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": float(duration_seconds),
        "repeat_count": len(runs),
        "tool_count": len(tools),
        "tools": tools,
        "repeat_hash_stability": {
            tool: len({row[tool] for row in repeat_hashes}) == 1
            for tool in tools
        },
        "outputs": {
            "results_json": "experimental_results.json",
            "aggregated_results_tex": "aggregated_results.tex",
            "ecosystem_summary_tex": "ecosystem_summary.tex",
            "recall_significance_tex": "recall_significance.tex",
            "recall_significance_json": "recall_significance.json",
            "recall_significance_matrix_png": "recall_significance_matrix.png",
            "tool_comparison_png": "tool_comparison.png",
            "tool_comparison_summary_json": "tool_comparison_summary.json",
            "tool_comparison_summary_txt": "tool_comparison_summary.txt",
            "tool_repeat_comparison_json": "tool_repeat_comparison.json",
            "tool_repeat_comparison_txt": "tool_repeat_comparison.txt",
        },
    }
    write_json(run_dir / "run_status.json", run_status)

    log.info("Temporal evaluation completed in %.2fs", duration_seconds)
    log.info("Run-level artifacts written to: %s", run_dir)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--sbom", required=False, default=None)
    ap.add_argument("--output", required=True)

    args = ap.parse_args()
    run_temporal(args.ground_truth, args.sbom, args.output)


if __name__ == "__main__":
    main()
