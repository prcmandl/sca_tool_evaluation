from __future__ import annotations

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

TOOLS = os.environ.get(
    "EVAL_TOOLS",
    "dtrack oss-index github snyk trivy",
).split()


def setup_logger(run_dir: Path) -> None:
    log.setLevel(logging.INFO)
    log.propagate = False

    for handler in list(log.handlers):
        log.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass

    fh = logging.FileHandler(run_dir / "run.log", mode="w")
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    log.addHandler(fh)


def hash_findings(findings: List[Finding]) -> str:
    return hashlib.sha256(
        str(
            sorted(
                (f.ecosystem, f.component, f.version, f.cve or f.osv_id or "")
                for f in findings
            )
        ).encode()
    ).hexdigest()


def compute_significance_markers(rows, baseline: str = "oss-index"):
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


def prepare_tool_inputs(
    tool_dir: Path,
    gt_path: Path,
    sbom_path: Path | None,
) -> tuple[Path, Path | None]:
    """
    Copy GT/SBOM into the tool directory so adapters that write relative
    to the GT input path also produce outputs inside tool_dir.
    """
    tool_dir.mkdir(parents=True, exist_ok=True)

    local_gt = tool_dir / gt_path.name
    shutil.copy2(gt_path, local_gt)

    local_sbom = None
    if sbom_path is not None and sbom_path.exists():
        local_sbom = tool_dir / sbom_path.name
        shutil.copy2(sbom_path, local_sbom)

    return local_gt, local_sbom


def run_temporal(gt_path: str, sbom_path: str | None, output_dir: str) -> None:
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

    # exactly 2 repeats
    for repeat_idx in range(2):
        log.info("REPEAT %d/2", repeat_idx + 1)
        run_result = {}

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

            run_result[tool] = {
                "hash": hash_findings(res["findings"]),
                "metrics": res["metrics"]["per_ecosystem"],
                "findings": res["findings"],
            }

        runs.append(run_result)

    tools_ok = all(len({run[tool]["hash"] for run in runs}) == 1 for tool in TOOLS)
    log.info("TOOL_CONSISTENT=%s", tools_ok)

    if not tools_ok:
        with (run_dir / "run_status.json").open("w", encoding="utf-8") as f:
            json.dump(
                {
                    "status": "TOOL_MISMATCH",
                    "message": "Tool findings differ between repeat_1 and repeat_2.",
                },
                f,
                indent=2,
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

    with (run_dir / "run_status.json").open("w", encoding="utf-8") as f:
        json.dump(
            {
                "status": "SUCCESS",
                "message": "Tool findings are stable across both repeats.",
            },
            f,
            indent=2,
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