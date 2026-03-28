#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import os
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

# ------------------------------------------------------------
# Adapters to tool and database APIs
# ------------------------------------------------------------
from evaluation.adapters.dtrack import DependencyTrackAdapter
from evaluation.adapters.evaltech import EvaltechAdapter
from evaluation.adapters.osv import OSVAdapter
from evaluation.adapters.github_advisory import GitHubAdvisoryAdapter
from evaluation.adapters.nvd import NVDAdapter
from evaluation.adapters.fossa import FossaAdapter
from evaluation.adapters.snyk import SnykAdapter
from evaluation.adapters.oss_index import OSSIndexAdapter
from evaluation.adapters.trivy import TrivyAdapter

from evaluation.core.ground_truth import load_ground_truth
from evaluation.core.fp_classification import classify_fp_candidate
from evaluation.core.model import Finding
from evaluation.reporting.evaluation_report import write_report
from evaluation.reporting.tool_findings_txt import write_tool_findings_txt

from evaluation.core.evaluation import (
    evaluate_project_centric,
    classify_false_negatives,
)

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-5s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("evaluation")


# ------------------------------------------------------------
# Progress bar
# ------------------------------------------------------------

def iter_with_progress(items, *, desc: str, unit: str):
    import sys
    from tqdm import tqdm

    enabled = os.environ.get("EVAL_PROGRESS", "1").lower() not in {
        "0", "false", "no", "off"
    }

    if not enabled or not sys.stderr.isatty():
        for x in items:
            yield x
        return

    for x in tqdm(
        items,
        desc=desc,
        unit=unit,
        dynamic_ncols=True,
        mininterval=0.2,
    ):
        yield x


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _get_identifier(x: Finding) -> str:
    return x.cve or x.osv_id or ""


def _gt_key(x: Finding) -> Tuple[str, str, str, str]:
    """
    Key used only on the ground-truth side.

    Important:
    We do NOT use this to reconstruct matching from raw tool findings.
    We only use it to map the already-evaluated TP list back onto the original
    ground-truth order. This keeps the significance input aligned with the
    evaluation result.
    """
    return (
        x.ecosystem,
        x.component,
        x.version,
        _get_identifier(x),
    )


def _build_gt_detection_vector(
    ground_truth: List[Finding],
    tp: List[Finding],
) -> List[int]:
    """
    Build a binary detection vector in the original ground-truth order.

    This function intentionally uses the TP list returned by
    evaluate_project_centric() as the single source of truth.

    Why this is correct:
    - Recall / TP / FN are already computed by evaluate_project_centric().
    - We do not try to re-match raw tool findings against ground truth.
    - We only map the confirmed TP findings back to GT indices.

    Multiplicity is preserved:
    - If the same GT key occurs multiple times, we keep a queue of GT indices.
    - Each TP occurrence consumes exactly one GT index.
    """
    gt_indices_by_key: Dict[Tuple[str, str, str, str], Deque[int]] = defaultdict(deque)

    for idx, gt in enumerate(ground_truth):
        gt_indices_by_key[_gt_key(gt)].append(idx)

    detected = [0] * len(ground_truth)
    unmatched_tp = 0

    for hit in tp:
        key = _gt_key(hit)
        queue = gt_indices_by_key.get(key)

        if queue:
            gt_idx = queue.popleft()
            detected[gt_idx] = 1
        else:
            unmatched_tp += 1

    if unmatched_tp:
        log.warning(
            "Could not map %d TP entries back to GT indices while building gt_detection_vector",
            unmatched_tp,
        )

    if sum(detected) != len(tp):
        log.warning(
            "gt_detection_vector sum (%d) differs from TP count (%d)",
            sum(detected),
            len(tp),
        )

    return detected


def _compute_gt_summary(ground_truth: List[Finding]) -> Dict[str, Dict[str, int]]:
    ecosystems = sorted({f.ecosystem for f in ground_truth})
    result: Dict[str, Dict[str, int]] = {}

    for eco in ecosystems:
        gt_subset = [g for g in ground_truth if g.ecosystem == eco]

        components = {
            (g.component, g.version)
            for g in gt_subset
        }
        cves = {
            g.cve
            for g in gt_subset
            if g.cve
        }

        result[eco] = {
            "Components": len(components),
            "Vulnerabilities": len(gt_subset),
            "CVEs": len(cves),
        }

    return result


def compute_per_ecosystem_metrics(
    *,
    ground_truth: List[Finding],
    tp: List[Finding],
    fp: List[Finding],
    fn: List[Finding],
) -> Dict[str, Dict[str, float]]:
    """
    Build per-ecosystem metrics from the evaluated result sets.
    This uses the SINGLE SOURCE OF TRUTH from evaluate_project_centric()
    and therefore stays aligned with the written reports.
    """
    gt_summary = _compute_gt_summary(ground_truth)
    ecosystems = sorted(gt_summary.keys())

    result: Dict[str, Dict[str, float]] = {}

    for eco in ecosystems:
        tp_count = sum(1 for x in tp if x.ecosystem == eco)
        fp_count = sum(1 for x in fp if x.ecosystem == eco)
        fn_count = sum(1 for x in fn if x.ecosystem == eco)

        recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) else 0.0
        overlap = tp_count / (tp_count + fp_count) if (tp_count + fp_count) else 0.0

        result[eco] = {
            "Components": gt_summary[eco]["Components"],
            "Vulnerabilities": gt_summary[eco]["Vulnerabilities"],
            "CVEs": gt_summary[eco]["CVEs"],
            "TP": tp_count,
            "FP": fp_count,
            "FN": fn_count,
            "Recall": recall,
            "Overlap": overlap,
        }

    return result


def _init_adapter(tool: str, config: dict):
    if tool == "dtrack":
        return DependencyTrackAdapter(config)
    elif tool == "evaltech":
        return EvaltechAdapter(config)
    elif tool == "osv":
        return OSVAdapter(config)
    elif tool == "github":
        return GitHubAdvisoryAdapter(config)
    elif tool == "nvd":
        return NVDAdapter(config)
    elif tool == "snyk":
        return SnykAdapter(config)
    elif tool == "trivy":
        return TrivyAdapter(config)
    elif tool == "fossa":
        return FossaAdapter(config)
    elif tool == "oss-index":
        return OSSIndexAdapter(config)
    else:
        raise SystemExit(f"Unsupported tool: {tool}")


# ------------------------------------------------------------
# Reusable evaluation entry point
# ------------------------------------------------------------

def run_evaluation(
    *,
    ground_truth_path: str,
    tool: str,
    return_findings: bool = False,
    return_metrics: bool = False,
) -> Optional[Dict[str, Any]]:
    log.info("=== Evaluation started ===")
    log.info("Selected tool: %s", tool)

    # --------------------------------------------------------
    # Run / naming context
    # --------------------------------------------------------
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # --------------------------------------------------------
    # Load ground truth
    # --------------------------------------------------------
    gt_path = Path(ground_truth_path).resolve()
    if not gt_path.exists():
        raise SystemExit(f"Ground truth file not found: {gt_path}")

    ground_truth_name = gt_path.stem

    log.info("Loading ground truth CSV: %s", gt_path)
    ground_truth: List[Finding] = load_ground_truth(gt_path)
    log.info("Ground truth loaded: %d entries", len(ground_truth))

    # --------------------------------------------------------
    # Adapter configuration
    # --------------------------------------------------------
    config = {
        "env": os.environ,
        "ground_truth": ground_truth,
        "ground_truth_path": gt_path,
    }

    # --------------------------------------------------------
    # Initialize adapter
    # --------------------------------------------------------
    adapter = _init_adapter(tool, config)
    log.info("Initialized adapters: %s", adapter.name())

    # --------------------------------------------------------
    # Load tool findings
    # --------------------------------------------------------
    log.info("Loading findings from tool")
    tool_findings: List[Finding] = adapter.load_findings()
    log.info("Tool findings loaded (normalized): %d", len(tool_findings))

    # --------------------------------------------------------
    # Dump tool findings (TXT)
    # --------------------------------------------------------
    write_tool_findings_txt(
        out_dir=gt_path.parent,
        ground_truth_name=ground_truth_name,
        tool=tool,
        run_id=run_id,
        findings=tool_findings,
    )

    # --------------------------------------------------------
    # Check tool capability
    # --------------------------------------------------------
    if hasattr(adapter, "supports_security_findings") and not adapter.supports_security_findings():
        log.warning(
            "Tool %s does not provide security findings – skipping evaluation",
            adapter.name(),
        )
        tp_exact: List[Finding] = []
        tp_range: List[Finding] = []
        tp: List[Finding] = []
        fp: List[Finding] = []
        fn: List[Finding] = []
        fn_stats: Dict[str, int] = {}
        fp_stats: Dict[str, int] = {}
    else:
        # ----------------------------------------------------
        # Evaluation (SINGLE SOURCE OF TRUTH)
        # ----------------------------------------------------
        tp_exact, tp_range, fp, fn = evaluate_project_centric(
            ground_truth=ground_truth,
            tool_findings=tool_findings,
        )
        tp = tp_exact + tp_range

        log.info(
            "Evaluation result | TP=%d | FP=%d | FN=%d",
            len(tp),
            len(fp),
            len(fn),
        )

        # ----------------------------------------------------
        # FP classification (diagnostic)
        # ----------------------------------------------------
        fp_stats = {"FP-CERTAIN": 0, "FP-LIKELY": 0, "FP-UNCLEAR": 0}

        if fp:
            for f in iter_with_progress(
                fp,
                desc="Classifying false positives",
                unit="findings",
            ):
                cls, reason = classify_fp_candidate(vars(f))
                f.fp_reason = reason
                if not getattr(f, "fp_class", None):
                    f.fp_class = cls
                fp_stats[cls] += 1
        else:
            log.info("No false positives to classify")

        # ----------------------------------------------------
        # FN classification (diagnostic)
        # ----------------------------------------------------
        fn_stats = classify_false_negatives(
            false_negatives=fn,
            tool_findings=tool_findings,
        )

    # --------------------------------------------------------
    # Detection vector for significance analysis
    # --------------------------------------------------------
    gt_detection_vector = _build_gt_detection_vector(
        ground_truth=ground_truth,
        tp=tp,
    )

    log.info(
        "GT detection vector built | detected=%d | gt_size=%d",
        sum(gt_detection_vector),
        len(gt_detection_vector),
    )

    # --------------------------------------------------------
    # Further analysis
    # --------------------------------------------------------
    from evaluation.analysis.tool_findings import analyze_tool_findings

    analysis = analyze_tool_findings(
        ground_truth=ground_truth,
        tool_findings=tool_findings,
        tp=tp,
        fp=fp,
        fn=fn,
    )

    # --------------------------------------------------------
    # Per-ecosystem metrics for downstream consumers
    # --------------------------------------------------------
    per_ecosystem_metrics = compute_per_ecosystem_metrics(
        ground_truth=ground_truth,
        tp=tp,
        fp=fp,
        fn=fn,
    )

    # --------------------------------------------------------
    # Write report
    # --------------------------------------------------------
    log.info("Writing evaluation report")

    api_stats = adapter.get_api_statistics()

    write_report(
        tool_name=adapter.name(),
        input_csv=str(gt_path),
        tp=tp,
        fp=fp,
        fn=fn,
        fp_stats=fp_stats,
        fn_stats=fn_stats,
        ground_truth=ground_truth,
        api_stats=api_stats,
    )

    log.info("=== Evaluation finished ===")

    # --------------------------------------------------------
    # Optional structured return for callers (e.g. temporal runner)
    # --------------------------------------------------------
    result: Dict[str, Any] = {}

    if return_findings:
        result["findings"] = tool_findings

    if return_metrics:
        result["metrics"] = {
            "per_ecosystem": per_ecosystem_metrics,
            "analysis": analysis,
            "fp_stats": fp_stats,
            "fn_stats": fn_stats,
            "api_stats": api_stats,
        }

    # Always expose the GT detection vector to structured callers.
    if return_findings or return_metrics:
        result["gt_detection_vector"] = gt_detection_vector

    if result:
        return result

    return None


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--ground-truth",
        required=True,
        help="Path to ground truth CSV file",
    )
    ap.add_argument(
        "--tool",
        choices=[
            "dtrack",
            "evaltech",
            "osv",
            "github",
            "nvd",
            "snyk",
            "fossa",
            "oss-index",
            "mend",
            "trivy",
        ],
        required=True,
        help="Vulnerability scanning tool to evaluate",
    )

    args = ap.parse_args()

    run_evaluation(
        ground_truth_path=args.ground_truth,
        tool=args.tool,
        return_findings=False,
        return_metrics=False,
    )


if __name__ == "__main__":
    main()
