from __future__ import annotations

import argparse
import hashlib
import logging
import time
from pathlib import Path
from typing import List
import json
import os
import shutil
from datetime import datetime

from evaluation.evaluate import run_evaluation
from evaluation.core.ground_truth import load_ground_truth
from evaluation.core.model import Finding

from evaluation.analysis.significance import (
    build_detection_matrix,
    cochran_q_test,
    pairwise_mcnemar,
    holm,
    write_significance_latex,
)

log = logging.getLogger("evaluation.temporal")

# ------------------------------------------------------------
# Config
# ------------------------------------------------------------
TOOLS = os.environ.get(
    "EVAL_TOOLS",
    "dtrack oss-index github snyk trivy"
).split()

# ------------------------------------------------------------
# Logger Setup
# ------------------------------------------------------------
def setup_run_logger(run_dir: Path):
    log_file = run_dir / "run.log"

    handler = logging.FileHandler(log_file)
    handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-5s | %(message)s",
        datefmt="%H:%M:%S",
    )
    handler.setFormatter(formatter)

    log.addHandler(handler)

    log.info("=== RUN START ===")
    log.info("Run directory: %s", run_dir)

# ------------------------------------------------------------
# Hashing
# ------------------------------------------------------------
def hash_gt(gt: List[Finding]) -> str:
    data = sorted(
        (f.ecosystem, f.component, f.version, f.cve or f.osv_id or "")
        for f in gt
    )
    return hashlib.sha256(str(data).encode()).hexdigest()


def hash_findings(findings: List[Finding]) -> str:
    data = sorted(
        (f.ecosystem, f.component, f.version, f.cve or f.osv_id or "")
        for f in findings
    )
    return hashlib.sha256(str(data).encode()).hexdigest()


# ------------------------------------------------------------
# Copy outputs
# ------------------------------------------------------------
def collect_outputs(src_dir: Path, dst_dir: Path):
    for f in src_dir.glob("*"):
        if f.suffix in {".json", ".txt", ".log", ".stat", ".csv"}:
            shutil.copy(f, dst_dir / f.name)


# ------------------------------------------------------------
# Temporal Runner
# ------------------------------------------------------------
def run_temporal(ground_truth_path: str, output_file: str):

    start_time = time.time()

    ground_truth_path = Path(ground_truth_path)

    # --------------------------------------------------------
    # Run directory (with ID)
    # --------------------------------------------------------
    run_id = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    base_dir = Path(output_file).parent
    run_dir = base_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    setup_run_logger(run_dir)

    log.info("Tools: %s", TOOLS)

    attempt = 0
    retries = 0
    tool_failures = 0
    gt_changes = 0

    while True:
        attempt += 1
        iter_start = time.time()

        log.info("=== ATTEMPT %d ===", attempt)

        # ----------------------------------------------------
        # GT snapshot 0
        # ----------------------------------------------------
        gt0 = load_ground_truth(ground_truth_path)
        gt0_hash = hash_gt(gt0)

        runs = []

        # ----------------------------------------------------
        # Run tools 3 times
        # ----------------------------------------------------
        for i in range(3):
            log.info("Run %d/3", i + 1)

            run_result = {}
            sub_run_dir = run_dir / f"run_{i+1}"
            sub_run_dir.mkdir(exist_ok=True)

            for tool in TOOLS:
                log.info("Running tool: %s", tool)

                try:
                    res = run_evaluation(
                        ground_truth_path=str(ground_truth_path),
                        tool=tool,
                        return_findings=True,
                        return_metrics=True,
                    )
                except Exception as e:
                    log.error("Tool %s failed: %s", tool, e)
                    tool_failures += 1
                    res = {"findings": [], "metrics": {}}

                findings = res.get("findings", [])
                metrics = res.get("metrics", {}).get("per_ecosystem", {})

                run_result[tool] = {
                    "hash": hash_findings(findings),
                    "metrics": metrics,
                    "findings": findings,
                }

            # ------------------------------------------------
            # Copy outputs into run_x
            # ------------------------------------------------
            collect_outputs(base_dir, sub_run_dir)

            runs.append(run_result)

        # ----------------------------------------------------
        # GT snapshot 1
        # ----------------------------------------------------
        gt1 = load_ground_truth(ground_truth_path)
        gt1_hash = hash_gt(gt1)

        # ----------------------------------------------------
        # Check consistency
        # ----------------------------------------------------
        tools_ok = True

        for tool in TOOLS:
            hashes = [r[tool]["hash"] for r in runs]
            if len(set(hashes)) != 1:
                log.warning("Tool unstable: %s", tool)
                tools_ok = False

        gt_ok = gt0_hash == gt1_hash

        if not gt_ok:
            log.warning("Ground truth changed")
            gt_changes += 1

        # ----------------------------------------------------
        # Decision
        # ----------------------------------------------------
        if tools_ok and gt_ok:
            log.info("=== CONSISTENT ===")

            final_findings = {
                tool: runs[0][tool]["findings"]
                for tool in TOOLS
            }

            # -------------------------
            # Significance
            # -------------------------
            matrix = build_detection_matrix(gt0, final_findings)
            Q, p_q = cochran_q_test(matrix)

            rows = pairwise_mcnemar(gt0, final_findings)
            rows = holm(rows)

            write_significance_latex(
                Q, p_q, rows,
                run_dir / "recall_significance.tex"
            )

            with open(run_dir / "recall_significance.json", "w") as f:
                json.dump({"Q": Q, "p_q": p_q, "pairs": rows}, f, indent=2)

            # -------------------------
            # Metrics
            # -------------------------
            final_metrics = {
                tool: runs[0][tool]["metrics"]
                for tool in TOOLS
            }

            with open(run_dir / "experimental_results.json", "w") as f:
                json.dump(final_metrics, f, indent=2)

            break

        retries += 1
        log.warning("Retrying...")
        time.sleep(2)

        log.info("Iteration runtime: %.2fs", time.time() - iter_start)

    # --------------------------------------------------------
    # Final summary
    # --------------------------------------------------------
    total_time = time.time() - start_time

    log.info("=== RUN SUMMARY ===")
    log.info("Attempts: %d", attempt)
    log.info("Retries: %d", retries)
    log.info("Tool failures: %d", tool_failures)
    log.info("GT changes: %d", gt_changes)
    log.info("Total runtime: %.2fs", total_time)


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--output", default="experiments")

    args = ap.parse_args()

    run_temporal(args.ground_truth, args.output)


if __name__ == "__main__":
    main()