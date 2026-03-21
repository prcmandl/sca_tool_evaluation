import logging
from pathlib import Path
from typing import List, Dict, Tuple

from evaluation.core.model import Finding

log = logging.getLogger("evaluation.report.text_voting")


# ============================================================
# Helper: metrics
# ============================================================

def _prf(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    return precision, recall, f1


def _compute_tool_stats(
    decisions: List[Dict],
    gt_lookup: Dict[Tuple[str, str, str, str], str],
    tool_key: str,
) -> Tuple[int, int, int, int]:
    """
    Computes TP/FP/FN/TN for a single tool based on decision trace.
    tool_key ∈ {"osv", "github", "dtrack"}
    """
    tp = fp = fn = tn = 0

    for d in decisions:
        tool_decision = d.get(tool_key)
        if tool_decision is None:
            continue  # e.g. DTrack disabled

        key = (
            d["ecosystem"],
            d["component"],
            d["version"],
            d["vulnerability"],
        )

        gt = gt_lookup.get(key, "FALSE")

        if tool_decision and gt == "TRUE":
            tp += 1
        elif tool_decision and gt == "FALSE":
            fp += 1
        elif not tool_decision and gt == "TRUE":
            fn += 1
        elif not tool_decision and gt == "FALSE":
            tn += 1

    return tp, fp, fn, tn


# ============================================================
# Public API
# ============================================================

def write_voting_report(
    *,
    tool_name: str,
    ground_truth: List[Finding],
    tool_findings: List[Finding],
    counts: Dict[str, int],
    precision: float,
    recall: float,
    f1: float,
    decisions: List[Dict],
    output_dir: Path,
    input_stem: str,
    weights: Dict[str, int],
) -> None:
    """
    Writes a voting evaluation report including:
      - summary metrics
      - per-tool statistics (OSV, GitHub, DTrack)
      - full decision trace (ALL dataset samples)
    """

    output_path = output_dir / f"{input_stem}_evaluation.txt"
    log.info("Writing voting report to %s", output_path)

    # --------------------------------------------------------
    # Ground-truth lookup (for GT column)
    # --------------------------------------------------------
    gt_lookup = {
        (g.ecosystem, g.component, g.version, g.cve or g.osv_id): g.gt_label
        for g in ground_truth
    }

    # --------------------------------------------------------
    # Column widths (dynamic)
    # --------------------------------------------------------
    def _max_len(key: str, default: int) -> int:
        return max([len(str(d.get(key, ""))) for d in decisions] + [default])

    w_eco = _max_len("ecosystem", 9)
    w_comp = _max_len("component", 12)
    w_ver = _max_len("version", 7)
    w_vuln = _max_len("vulnerability", 15)

    # --------------------------------------------------------
    # Write file
    # --------------------------------------------------------
    with output_path.open("w", encoding="utf-8") as f:
        # ====================================================
        # Header
        # ====================================================
        f.write("Voting Evaluation Report\n")
        f.write("========================\n")
        f.write(f"Tool: {tool_name}\n\n")

        # ====================================================
        # Summary
        # ====================================================
        f.write("Summary\n")
        f.write("-------\n")
        f.write(
            f"TP={counts['TP']}  FP={counts['FP']}  "
            f"FN={counts['FN']}  TN={counts['TN']}\n"
        )
        f.write(
            f"Precision={precision:.4f}  "
            f"Recall={recall:.4f}  "
            f"F1={f1:.4f}\n\n"
        )

        # ====================================================
        # Voting weights
        # ====================================================
        f.write("Voting Weights\n")
        f.write("--------------\n")
        for k, v in weights.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")

        # ====================================================
        # Per-tool statistics
        # ====================================================
        f.write("Per-Tool Statistics\n")
        f.write("-------------------\n")
        f.write(
            "Tool    | TP | FP | FN | TN | Precision | Recall | F1\n"
        )
        f.write("-" * 68 + "\n")

        for tool in ["osv", "github", "dtrack"]:
            tp, fp, fn, tn = _compute_tool_stats(decisions, gt_lookup, tool)
            p_t, r_t, f1_t = _prf(tp, fp, fn)

            f.write(
                f"{tool:<7} | "
                f"{tp:<2} | {fp:<2} | {fn:<2} | {tn:<2} | "
                f"{p_t:>9.4f} | {r_t:>6.4f} | {f1_t:>6.4f}\n"
            )

        f.write("\n")

        # ====================================================
        # Decision trace
        # ====================================================
        f.write("Decision Trace (all dataset samples)\n")
        f.write("-----------------------------------\n")

        header = (
            f"{'Eco':<{w_eco}} | "
            f"{'Component':<{w_comp}} | "
            f"{'Version':<{w_ver}} | "
            f"{'Vulnerability':<{w_vuln}} | "
            f"GT | OSV | GitHub | DTrack | Score | Decision\n"
        )
        f.write(header)
        f.write("-" * len(header) + "\n")

        for d in decisions:
            eco = d["ecosystem"]
            comp = d["component"]
            ver = d["version"]
            vuln = d.get("vulnerability") or "-"

            gt_label = gt_lookup.get((eco, comp, ver, vuln), "?")

            osv = "T" if d.get("osv") else "F"
            gh = "T" if d.get("github") else "F"
            dt_val = d.get("dtrack")
            dt = "-" if dt_val is None else ("T" if dt_val else "F")

            pos = d.get("positive_votes", 0)
            score = f"{pos}/3"

            decision = "TRUE" if d.get("decision") else "FALSE"

            f.write(
                f"{eco:<{w_eco}} | "
                f"{comp:<{w_comp}} | "
                f"{ver:<{w_ver}} | "
                f"{vuln:<{w_vuln}} | "
                f"{gt_label:^2} | "
                f"{osv:^3} | "
                f"{gh:^6} | "
                f"{dt:^6} | "
                f"{score:^5} | "
                f"{decision:^8}\n"
            )

        f.write("\n")
        f.write("Legend\n")
        f.write("------\n")
        f.write("GT       : Ground truth label (TRUE / FALSE)\n")
        f.write("OSV      : Online OSV decision\n")
        f.write("GitHub   : GitHub Advisory decision\n")
        f.write("DTrack   : Dependency-Track decision ('-' if not queried)\n")
        f.write("Score    : Number of positive votes / 3\n")
        f.write("Decision : Final voting result (>= 2 positive votes)\n")

    log.info("Voting report written successfully")
