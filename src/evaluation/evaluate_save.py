#!/usr/bin/en#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List

# ------------------------------------------------------------
# Adapters to tool and database APIs
# ----------------------------------------------------------
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
    import os, sys
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
# Main
# ------------------------------------------------------------

def main() -> None:
    # --------------------------------------------------------
    # CLI
    # --------------------------------------------------------
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

    log.info("=== Evaluation started ===")
    log.info("Selected tool: %s", args.tool)

    # --------------------------------------------------------
    # Run / naming context  (NEU)
    # --------------------------------------------------------

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # --------------------------------------------------------
    # Load ground truth
    # --------------------------------------------------------
    gt_path = Path(args.ground_truth).resolve()
    if not gt_path.exists():
        raise SystemExit(f"Ground truth file not found: {gt_path}")

    ground_truth_name = gt_path.stem  # <<< WICHTIG für Präfix

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
    # Initialize adapters
    # --------------------------------------------------------
    if args.tool == "dtrack":
        adapter = DependencyTrackAdapter(config)
    elif args.tool == "evaltech":
        adapter = EvaltechAdapter(config)
    elif args.tool == "osv":
        adapter = OSVAdapter(config)
    elif args.tool == "github":
        adapter = GitHubAdvisoryAdapter(config)
    elif args.tool == "nvd":
        adapter = NVDAdapter(config)
    elif args.tool == "snyk":
        adapter = SnykAdapter(config)
    elif args.tool == "trivy":
        adapter = TrivyAdapter(config)
    elif args.tool == "fossa":
        adapter = FossaAdapter(config)
    elif args.tool == "oss-index":
        adapter = OSSIndexAdapter(config)
    else:
        raise SystemExit(f"Unsupported tool: {args.tool}")

    log.info("Initialized adapters: %s", adapter.name())

    # --------------------------------------------------------
    # Load tool findings
    # --------------------------------------------------------
    log.info("Loading findings from tool")
    tool_findings: List[Finding] = adapter.load_findings()
    log.info("Tool findings loaded (normalized): %d", len(tool_findings))

    # --------------------------------------------------------
    # Dump tool findings (CSV – bestehend)
    # --------------------------------------------------------
    """
    dump_tool_findings_csv(
        tool_name=adapters.name(),
        tool_findings=tool_findings,
        ground_truth_csv=str(gt_path),
    )
    """

    # --------------------------------------------------------
    # Dump tool findings (TXT)
    # --------------------------------------------------------
    write_tool_findings_txt(
        out_dir=gt_path.parent,
        ground_truth_name=ground_truth_name,
        tool=args.tool,
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
        tp, fp, fn = [], [], []
        fn_stats = {}
        fp_stats = {}
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
    # Write report
    # --------------------------------------------------------
    log.info("Writing evaluation report")

    tp_exact, tp_range, fp, fn = evaluate_project_centric(
        ground_truth=ground_truth,
        tool_findings=tool_findings,
    )

    tp_all = tp_exact + tp_range

    api_stats = adapter.get_api_statistics()

    write_report(
        tool_name=adapter.name(),
        input_csv=str(gt_path),
        tp=tp_all,
        fp=fp,
        fn=fn,
        fp_stats=fp_stats,
        fn_stats=fn_stats,
        ground_truth=ground_truth,
        api_stats=api_stats,  # ← NEU
    )

    log.info("=== Evaluation finished ===")



if __name__ == "__main__":
    main()