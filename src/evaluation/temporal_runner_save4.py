from __future__ import annotations

"""
Temporal runner for the simplified temporal evaluation protocol.

RESPONSIBILITY
----------------------------------------------------------------
This module performs exactly one temporal evaluation attempt for a
single run_<i> directory.

It does NOT build ground truth snapshots and it does NOT retry the
full workflow. Those responsibilities remain in run_experiment_save3.sh.

SIMPLIFIED PROTOCOL INSIDE THIS MODULE
----------------------------------------------------------------
Given GT0 and its SBOM:

    1) Run all tools once   -> repeat_1
    2) Run all tools again  -> repeat_2
    3) Compare tool findings between both repeats
    4) If tool findings differ:
           exit with code 2 (TOOL_MISMATCH)
    5) If tool findings match:
           write metrics, significance outputs, plots, and run_status
           exit with code 0

ARTIFACT PLACEMENT
----------------------------------------------------------------
A central requirement of this runner is that every tool writes its
own evaluation artifacts directly into:

    run_<i>/artifacts/repeat_<n>/<tool>/

This is enforced by:

    - creating a dedicated tool directory before each tool call
    - copying GT and SBOM into that directory
    - setting output-related environment variables immediately before
      the tool invocation
    - temporarily changing the working directory to the tool directory

Why the GT/SBOM copies are necessary:
Some adapters derive output file paths from the input GT/SBOM path
instead of from the current working directory. By passing tool-local
copies as inputs, those adapters still write into the correct tool
artifact directory.
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
from typing import List

from evaluation.analysis.plots import (
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

TOOLS = os.environ.get(
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


def hash_findings(findings: List[Finding]) -> str:
    """Build a deterministic hash for a tool's findings list."""
    return hashlib.sha256(
        str(
            sorted(
                (f.ecosystem, f.component, f.version, f.cve or f.osv_id or "")
                for f in findings
            )
        ).encode()
    ).hexdigest()


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


def run_temporal(gt_path: str, sbom_path: str | None, output_dir: str) -> None:
    """
    Execute exactly two tool repeats for one run directory.

    Exit codes:
        0 -> success, tool findings stable across both repeats
        2 -> TOOL_MISMATCH
    """
    start_time = time.time()

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

        for tool in TOOLS:
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

    tools_ok = all(len({run[tool]["hash"] for run in runs}) == 1 for tool in TOOLS)
    log.info("TOOL_CONSISTENT=%s", tools_ok)

    if not tools_ok:
        write_run_status(
            run_dir / "run_status.json",
            "TOOL_MISMATCH",
            "Tool findings differ between repeat_1 and repeat_2.",
            extra={"repeat_hashes": repeat_hashes},
        )
        raise SystemExit(2)

    final_findings = {tool: runs[0][tool]["findings"] for tool in TOOLS}
    final_metrics = {tool: runs[0][tool]["metrics"] for tool in TOOLS}

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

    plot_significance_matrix(rows, TOOLS, str(run_dir))

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