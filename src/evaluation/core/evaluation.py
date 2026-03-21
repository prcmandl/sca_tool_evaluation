import logging
from collections import defaultdict
from typing import Dict, List, Tuple

from model import Finding

log = logging.getLogger("evaluation.core.evaluation")


def evaluate_project_centric(
    *,
    ground_truth: List[Finding],
    tool_findings: List[Finding],
):
    tp_exact, tp_range, fp, fn = [], [], [], []

    by_comp = defaultdict(list)
    for t in tool_findings:
        by_comp[(t.ecosystem, t.component)].append(t)

    used = set()

    for g in ground_truth:
        gt_ids = g.identifiers()
        best = None

        for t in by_comp.get((g.ecosystem, g.component), []):
            if not (gt_ids & t.identifiers()):
                continue

            if t.version == g.version:
                best = ("TP_EXACT", t)
                break

            if t.affected_version_range and version_in_range(g.version, t.affected_version_range):
                best = best or ("TP_RANGE", t)

        if not best:
            fn.append(g)
            continue

        mt, t = best
        used.add(id(t))
        g.match_type = mt

        (tp_exact if mt == "TP_EXACT" else tp_range).append(g)

    for t in tool_findings:
        if id(t) not in used:
            fp.append(t)

    return tp_exact, tp_range, fp, fn




def classify_false_negatives(
    *,
    false_negatives: List[Finding],
    tool_findings: List[Finding],
) -> Dict[str, List[Finding]]:
    """
    Classify FN according to updated semantics:

    FN_EXACT:
      - Tool reported SAME component + SAME version
      - But identifiers (CVE / OSV / GHSA) do not match

    FN_RANGE:
      - Tool reported ONLY ranges
      - Version MAY be affected, but not provably contained
      - (i.e. no exact version match, no safe TP_RANGE)

    FN_TRUE:
      - Tool reported nothing relevant
    """

    fn_exact: List[Finding] = []
    fn_range: List[Finding] = []
    fn_true: List[Finding] = []

    tool_by_comp = defaultdict(list)
    for t in tool_findings:
        tool_by_comp[(t.ecosystem, t.component)].append(t)

    for g in false_negatives:
        tools = tool_by_comp.get((g.ecosystem, g.component), [])

        found_same_version = False
        found_uncertain_range = False

        for t in tools:
            # --------------------------------------
            # FN_EXACT: same version, wrong IDs
            # --------------------------------------
            if t.version == g.version:
                found_same_version = True
                break

            # --------------------------------------
            # FN_RANGE: only ranges, but not decisive
            # --------------------------------------
            if t.affected_version_range:
                try:
                    if version_in_range(g.version, t.affected_version_range):
                        # IMPORTANT:
                        # If this were a *safe* range match,
                        # it would already be TP_RANGE.
                        found_uncertain_range = True
                except Exception:
                    pass

        if found_same_version:
            fn_exact.append(g)
        elif found_uncertain_range:
            fn_range.append(g)
        else:
            fn_true.append(g)

    return {
        "FN_exact": fn_exact,
        "FN_range": fn_range,
        "FN_true": fn_true,
    }


from packaging.version import Version, InvalidVersion

from packaging.version import Version, InvalidVersion

def version_in_range(version: str, range_expr: str) -> bool:
    """
    Conservative range evaluation.

    Guarantees:
    - Never raises InvalidVersion
    - Never produces TP_RANGE if comparison is unsafe
    - Does not affect TP_EXACT logic
    - Does not change adapters behavior
    """
    try:
        v = Version(version)
    except InvalidVersion:
        # Version not safely comparable → no TP_RANGE
        return False

    parts = range_expr.split(",")

    for p in parts:
        p = p.strip()
        try:
            if p.startswith("<="):
                if v > Version(p[2:].strip()):
                    return False
            elif p.startswith("<"):
                if v >= Version(p[1:].strip()):
                    return False
            elif p.startswith(">="):
                if v < Version(p[2:].strip()):
                    return False
            elif p.startswith(">"):
                if v <= Version(p[1:].strip()):
                    return False
            elif p.startswith("=="):
                if v != Version(p[2:].strip()):
                    return False
        except InvalidVersion:
            # Range boundary not safely comparable → undecidable → no TP_RANGE
            return False

    return True


from evaluation.core.model import Finding


def evaluate_finding(
    *,
    ground_truth: Finding,
    tool_finding: Finding,
) -> str:
    """
    Decide the evaluation outcome for one tool finding
    against one ground-truth entry.

    Returns:
      - "TP"
      - "TP_RANGE"
      - "FN"
      - "FP"
    """

    # --------------------------------------------------
    # Identifier match (CVE / GHSA / OSV-ID)
    # --------------------------------------------------
    gt_ids = ground_truth.identifiers()
    tool_ids = tool_finding.identifiers()

    if not gt_ids or not tool_ids:
        return "FP"

    id_match = bool(gt_ids & tool_ids)
    if not id_match:
        return "FP"

    # --------------------------------------------------
    # Exact version match
    # --------------------------------------------------
    if tool_finding.version == ground_truth.version:
        return "TP"

    # --------------------------------------------------
    # Version range match
    # --------------------------------------------------
    if version_in_range(
        ground_truth.version,
        tool_finding.affected_version_range,
    ):
        return "TP_RANGE"

    # --------------------------------------------------
    # Same vulnerability, but version not covered
    # --------------------------------------------------
    return "FN"
