from collections import defaultdict
from typing import Dict, List, Tuple

from evaluation.core.model import Finding


def analyze_tool_findings(
    *,
    ground_truth: List[Finding],
    tool_findings: List[Finding],
    tp: List[Finding],
    fp: List[Finding],
    fn: List[Finding],
) -> Dict[str, dict]:
    """
    Post-evaluation analysis of tool findings.

    IMPORTANT:
    - No matching
    - No TP/FP/FN recomputation
    - Pure aggregation & diagnostics
    """

    # ------------------------------------------------------------
    # Aggregations
    # ------------------------------------------------------------
    by_ecosystem = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0})
    by_component = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0})

    for r in tp:
        by_ecosystem[r.ecosystem]["TP"] += 1
        by_component[(r.ecosystem, r.component)]["TP"] += 1

    for r in fp:
        by_ecosystem[r.ecosystem]["FP"] += 1
        by_component[(r.ecosystem, r.component)]["FP"] += 1

    for r in fn:
        by_ecosystem[r.ecosystem]["FN"] += 1
        by_component[(r.ecosystem, r.component)]["FN"] += 1

    # ------------------------------------------------------------
    # Derived diagnostic views
    # ------------------------------------------------------------
    components_with_many_fp = sorted(
        by_component.items(),
        key=lambda x: x[1]["FP"],
        reverse=True,
    )

    components_with_many_fn = sorted(
        by_component.items(),
        key=lambda x: x[1]["FN"],
        reverse=True,
    )

    ecosystems_with_high_fn = sorted(
        by_ecosystem.items(),
        key=lambda x: x[1]["FN"],
        reverse=True,
    )

    return {
        "by_ecosystem": dict(by_ecosystem),
        "by_component": dict(by_component),
        "top_fp_components": components_with_many_fp[:10],
        "top_fn_components": components_with_many_fn[:10],
        "ecosystems_by_fn": ecosystems_with_high_fn,
    }
