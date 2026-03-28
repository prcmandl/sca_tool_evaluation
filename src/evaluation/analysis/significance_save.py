from __future__ import annotations

from itertools import combinations
from typing import Dict, List, Tuple

import numpy as np
from scipy.stats import binomtest, chi2

from evaluation.core.model import Finding


TOOL_NAMES = {
    "dtrack": "Dependency-Track",
    "oss-index": "OSS Index",
    "github": "GitHub Advisory Database",
    "snyk": "Snyk",
    "trivy": "Trivy",
}


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _key(f: Finding) -> Tuple[str, str, str, str]:
    return (
        f.ecosystem,
        f.component,
        f.version,
        f.cve or f.osv_id or "",
    )


def build_detection_matrix(
    ground_truth: List[Finding],
    findings_by_tool: Dict[str, List[Finding]],
):
    gt_keys = [_key(g) for g in ground_truth]

    matrix = []

    for k in gt_keys:
        row = []
        for tool in findings_by_tool:
            tool_keys = {_key(f) for f in findings_by_tool[tool]}
            row.append(1 if k in tool_keys else 0)
        matrix.append(row)

    return np.array(matrix)


# ------------------------------------------------------------
# Cochran's Q
# ------------------------------------------------------------

def cochran_q_test(matrix: np.ndarray):
    """
    matrix: shape (n_instances, n_tools)
    """

    k = matrix.shape[1]

    row_sums = matrix.sum(axis=1)
    col_sums = matrix.sum(axis=0)
    total = matrix.sum()

    numerator = (k - 1) * (
        k * np.sum(col_sums ** 2) - total ** 2
    )

    denominator = k * np.sum(row_sums) - np.sum(row_sums ** 2)

    if denominator == 0:
        return 0.0, 1.0

    Q = numerator / denominator
    p = 1 - chi2.cdf(Q, df=k - 1)

    return Q, p


# ------------------------------------------------------------
# Pairwise McNemar (exact)
# ------------------------------------------------------------

def pairwise_mcnemar(
    ground_truth: List[Finding],
    findings_by_tool: Dict[str, List[Finding]],
):
    detected = {
        tool: {_key(f) for f in findings_by_tool[tool]}
        for tool in findings_by_tool
    }

    gt_keys = {_key(g) for g in ground_truth}

    rows = []

    for a, b in combinations(findings_by_tool.keys(), 2):
        a_set = detected[a] & gt_keys
        b_set = detected[b] & gt_keys

        n10 = len(a_set - b_set)
        n01 = len(b_set - a_set)

        n = n10 + n01

        if n == 0:
            p = 1.0
        else:
            p = binomtest(
                k=min(n10, n01),
                n=n,
                p=0.5,
                alternative="two-sided",
            ).pvalue

        rows.append({
            "tool_a": a,
            "tool_b": b,
            "n10": n10,
            "n01": n01,
            "p": p,
            "p_adj": None,
        })

    return rows


# ------------------------------------------------------------
# Holm correction
# ------------------------------------------------------------

def holm(rows):
    rows_sorted = sorted(rows, key=lambda r: r["p"])
    m = len(rows)

    for i, r in enumerate(rows_sorted):
        r["p_adj"] = min((m - i) * r["p"], 1.0)

    return rows


# ------------------------------------------------------------
# LaTeX output
# ------------------------------------------------------------

def write_significance_latex(
    Q, p_q,
    rows,
    output_file,
):
    def fmt(x):
        if x < 0.001:
            return "<0.001"
        return f"{x:.3f}"

    with open(output_file, "w") as f:

        # Textblock
        f.write("\\paragraph{Statistical significance.}\n")

        signif = "a significant" if p_q < 0.05 else "no significant"

        f.write(
            f"To determine whether the observed recall differences are "
            f"statistically significant, we first apply Cochran's $Q$ test. "
            f"The test indicates {signif} overall difference "
            f"(Q={Q:.2f}, p={fmt(p_q)}).\n\n"
        )

        # Tabelle
        f.write("\\begin{table*}[!t]\n\\centering\n\\small\n")
        f.write("\\begin{tabular}{llrrrr}\n\\toprule\n")
        f.write("Tool A & Tool B & $n_{10}$ & $n_{01}$ & $p$ & $p_{\\mathrm{adj}}$ \\\\\n")
        f.write("\\midrule\n")

        for r in rows:
            a = TOOL_NAMES[r["tool_a"]]
            b = TOOL_NAMES[r["tool_b"]]

            f.write(
                f"{a} & {b} & {r['n10']} & {r['n01']} & "
                f"{fmt(r['p'])} & {fmt(r['p_adj'])} \\\\\n"
            )

        f.write("\\bottomrule\n\\end{tabular}\n\\end{table*}\n")
