from typing import List, Dict

from evaluation.core.model import Finding

# ------------------------------------------------------------
# Heuristic quality metrics
# ------------------------------------------------------------

def _is_heuristically_marked_fp(f: Finding) -> bool:
    """
    A finding is considered 'heuristically marked' if the adapters/tool
    attached fp_class (or fp_score/fp_rules). We use fp_class as the primary flag.
    """
    return bool(getattr(f, "fp_class", None))

def compute_fp_heuristic_quality(
    tp: List[Finding],
    fp: List[Finding],
) -> Dict[str, float | int]:
    """
    Builds a heuristic confusion matrix on top of the evaluation result:

    - HTP: FP correctly marked (finding is FP and heuristic marked it)
    - HFN: FP missed by heuristic (finding is FP and heuristic did not mark it)
    - HFP: TP incorrectly marked (finding is TP but heuristic marked it)
    - HTN: TP correctly unmarked (finding is TP and heuristic did not mark it)
    """
    htp = sum(1 for f in fp if _is_heuristically_marked_fp(f))
    hfn = sum(1 for f in fp if not _is_heuristically_marked_fp(f))

    hfp = sum(1 for f in tp if _is_heuristically_marked_fp(f))
    htn = sum(1 for f in tp if not _is_heuristically_marked_fp(f))

    prec = htp / (htp + hfp) if (htp + hfp) else 0.0
    rec = htp / (htp + hfn) if (htp + hfn) else 0.0

    return {
        "HTP": htp,
        "HFN": hfn,
        "HFP": hfp,
        "HTN": htn,
        "heuristic_precision": prec,
        "heuristic_recall": rec,
    }
