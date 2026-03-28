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
from typing import Iterable

import numpy as np
from itertools import combinations
from scipy.stats import binomtest

from evaluation.analysis.significance import (
    build_detection_matrix_from_vectors,
    pairwise_mcnemar_from_matrix,
    cochran_q_test,
    holm,
    write_significance_latex,
)

from evaluation.core.ground_truth import load_ground_truth
from evaluation.core.model import Finding
from evaluation.evaluate import run_evaluation

log = logging.getLogger("evaluation.temporal")


# =========================
# Detection-based Significance
# =========================

def build_detection_matrix_from_vectors(detection_vectors_by_tool):
    tools = sorted(detection_vectors_by_tool.keys())

    lengths = {len(v) for v in detection_vectors_by_tool.values()}
    if len(lengths) != 1:
        raise ValueError("Detection vectors have inconsistent lengths")

    matrix = np.array([detection_vectors_by_tool[t] for t in tools]).T
    return matrix, tools


def pairwise_mcnemar_from_matrix(matrix, tools):
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
# Rest unverändert
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


def run_temporal(gt_path: str, sbom_path: str | None, output_dir: str) -> None:
    start_time = time.time()
    tools = get_tools()

    gt_path = Path(gt_path)
    sbom = Path(sbom_path) if sbom_path else None
    run_dir = Path(output_dir)

    run_dir.mkdir(parents=True, exist_ok=True)
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

            with tool_output_environment(tool_dir):
                with working_directory(tool_dir):
                    res = run_evaluation(
                        ground_truth_path=str(local_gt),
                        tool=tool,
                        return_findings=True,
                        return_metrics=True,
                    )

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

    from evaluation.analysis.significance import (
        build_detection_matrix_from_vectors,
        pairwise_mcnemar_from_matrix,
        cochran_q_test,
        holm,
        write_significance_latex,
    )

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
        run_dir / "recall_significance.tex"
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--sbom", required=False, default=None)
    ap.add_argument("--output", required=True)

    args = ap.parse_args()
    run_temporal(args.ground_truth, args.sbom, args.output)


if __name__ == "__main__":
    main()