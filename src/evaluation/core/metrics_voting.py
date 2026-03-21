from typing import List, Dict, Tuple, Literal
from collections import defaultdict

from model import Finding

GTLabel = Literal["TRUE", "FALSE"]
Outcome = Literal["TP", "FP", "FN", "TN"]


def _gt_key(f: Finding) -> Tuple[str, str, str, str | None]:
    return (f.ecosystem, f.component, f.version, f.cve)


def _normalize_label(label: str | None) -> GTLabel:
    if not label:
        return "TRUE"
    label = label.upper()
    if label not in {"TRUE", "FALSE"}:
        raise ValueError(f"Invalid GT label: {label}")
    return label  # type: ignore


def classify_voting_decision(*, tool_hit: bool, gt_label: GTLabel) -> Outcome:
    if tool_hit and gt_label == "TRUE":
        return "TP"
    if tool_hit and gt_label == "FALSE":
        return "FP"
    if (not tool_hit) and gt_label == "TRUE":
        return "FN"
    return "TN"


def evaluate_voting(
    *,
    tool_findings: List[Finding],
    ground_truth: List[Finding],
) -> Dict[str, int]:
    gt_index: Dict[Tuple[str, str, str, str | None], GTLabel] = {}

    for g in ground_truth:
        label = _normalize_label(getattr(g, "gt_label", None))
        gt_index[_gt_key(g)] = label

    tool_keys = {_gt_key(f) for f in tool_findings}
    all_keys = set(gt_index) | tool_keys

    counts = defaultdict(int)
    for key in all_keys:
        tool_hit = key in tool_keys
        gt_label = gt_index.get(key, "FALSE")  # not in GT -> treated as FALSE
        outcome = classify_voting_decision(tool_hit=tool_hit, gt_label=gt_label)
        counts[outcome] += 1

    return dict(counts)


def precision(counts: Dict[str, int]) -> float:
    tp = counts.get("TP", 0)
    fp = counts.get("FP", 0)
    return tp / (tp + fp) if (tp + fp) else 0.0


def recall(counts: Dict[str, int]) -> float:
    tp = counts.get("TP", 0)
    fn = counts.get("FN", 0)
    return tp / (tp + fn) if (tp + fn) else 0.0


def f1_score(counts: Dict[str, int]) -> float:
    p = precision(counts)
    r = recall(counts)
    return (2 * p * r / (p + r)) if (p + r) else 0.0


def summarize_counts(counts: Dict[str, int]) -> Dict[str, int]:
    return {
        "TP": counts.get("TP", 0),
        "FP": counts.get("FP", 0),
        "FN": counts.get("FN", 0),
        "TN": counts.get("TN", 0),
    }
