from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import time
from contextlib import contextmanager
from datetime import datetime
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


def tool_artifact_dir(run_dir: Path, repeat_idx: int, tool: str) -> Path:
    return run_dir / "artifacts" / f"repeat_{repeat_idx + 1}" / tool


def run_temporal(gt_path: str, output_dir: str) -> None:
    start_time = time.time()
    run_start_dt = datetime.now().astimezone()

    gt_path = Path(gt_path)
    run_dir = Path(output_dir)
    artifacts_dir = run_dir / "artifacts"

    run_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    setup_logger(run_dir)

    log.info("RUN_DATE=%s", run_start_dt.strftime("%Y-%m-%d"))
    log.info("RUN_START=%s", run_start_dt.strftime("%Y-%m-%d %H:%M:%S %Z"))
    log.info("RUN_DIR=%s", run_dir)

    gt0 = load_ground_truth(gt_path)
    runs = []

    for repeat_idx in range(3):
        log.info("REPEAT %d/3", repeat_idx + 1)
        run_result = {}

        for tool in TOOLS:
            tool_dir = tool_artifact_dir(run_dir, repeat_idx, tool)
            log.info("Running tool: %s (artifacts=%s)", tool, tool_dir)

            old_eval_artifacts_dir = os.environ.get("EVAL_ARTIFACTS_DIR")
            old_tool_output_dir = os.environ.get("TOOL_OUTPUT_DIR")
            old_output_dir = os.environ.get("OUTPUT_DIR")
            old_gt_build_path = os.environ.get("GROUND_TRUTH_BUILD_PATH")

            os.environ["EVAL_ARTIFACTS_DIR"] = str(tool_dir)
            os.environ["TOOL_OUTPUT_DIR"] = str(tool_dir)
            os.environ["OUTPUT_DIR"] = str(tool_dir)
            os.environ["GROUND_TRUTH_BUILD_PATH"] = str(tool_dir)

            try:
                with working_directory(tool_dir):
                    res = run_evaluation(
                        ground_truth_path=str(gt_path),
                        tool=tool,
                        return_findings=True,
                        return_metrics=True,
                    )
            finally:
                if old_eval_artifacts_dir is None:
                    os.environ.pop("EVAL_ARTIFACTS_DIR", None)
                else:
                    os.environ["EVAL_ARTIFACTS_DIR"] = old_eval_artifacts_dir

                if old_tool_output_dir is None:
                    os.environ.pop("TOOL_OUTPUT_DIR", None)
                else:
                    os.environ["TOOL_OUTPUT_DIR"] = old_tool_output_dir

                if old_output_dir is None:
                    os.environ.pop("OUTPUT_DIR", None)
                else:
                    os.environ["OUTPUT_DIR"] = old_output_dir

                if old_gt_build_path is None:
                    os.environ.pop("GROUND_TRUTH_BUILD_PATH", None)
                else:
                    os.environ["GROUND_TRUTH_BUILD_PATH"] = old_gt_build_path

            run_result[tool] = {
                "hash": hash_findings(res["findings"]),
                "metrics": res["metrics"]["per_ecosystem"],
                "findings": res["findings"],
            }

        runs.append(run_result)

    tools_ok = all(len({run[tool]["hash"] for run in runs}) == 1 for tool in TOOLS)
    log.info("TOOL_CONSISTENT=%s", tools_ok)

    if not tools_ok:
        run_end_dt = datetime.now().astimezone()
        log.warning("Three repeats are not identical -> temporal run rejected")
        log.info("RUN_END=%s", run_end_dt.strftime("%Y-%m-%d %H:%M:%S %Z"))
        log.info("RUN_DURATION_SECONDS=%.2f", time.time() - start_time)
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

    with (run_dir / "experimental_results.json").open("w", encoding="utf-8") as f:
        json.dump(final_metrics, f, indent=2)

    run_end_dt = datetime.now().astimezone()
    log.info("RUN_END=%s", run_end_dt.strftime("%Y-%m-%d %H:%M:%S %Z"))
    log.info("RUN_DURATION_SECONDS=%.2f", time.time() - start_time)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--output", required=True)

    args = ap.parse_args()
    run_temporal(args.ground_truth, args.output)


if __name__ == "__main__":
    main()