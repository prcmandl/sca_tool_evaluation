from __future__ import annotations

from itertools import combinations
from typing import Dict, List, Tuple

import numpy as np
from scipy.stats import binomtest, chi2


TOOL_NAMES = {
    "dtrack": "Dependency-Track",
    "oss-index": "OSS Index",
    "github": "GitHub Advisory Database",
    "snyk": "Snyk",
    "trivy": "Trivy",
}


# ------------------------------------------------------------
# Detection matrix from evaluation output
# ------------------------------------------------------------

def build_detection_matrix(
    detection_vectors_by_tool: Dict[str, List[int]],
) -> Tuple[np.ndarray, List[str]]:
    """
    Build a binary detection matrix directly from GT detection vectors
    produced by the evaluation logic.

    Rows  : ground-truth instances
    Cols  : tools
    Value : 1 if the tool detected the GT instance, else 0
    """
    tool_order = list(detection_vectors_by_tool.keys())

    if not tool_order:
        raise ValueError("No tools provided for detection matrix")

    lengths = {tool: len(detection_vectors_by_tool[tool]) for tool in tool_order}
    unique_lengths = set(lengths.values())
    if len(unique_lengths) != 1:
        raise ValueError(f"Inconsistent detection vector lengths: {lengths}")

    matrix = np.array(
        [detection_vectors_by_tool[tool] for tool in tool_order],
        dtype=int,
    ).T

    return matrix, tool_order


# ------------------------------------------------------------
# Cochran's Q
# ------------------------------------------------------------

def cochran_q_test(matrix: np.ndarray):
    """
    matrix: shape (n_instances, n_tools)
    """
    if matrix.ndim != 2:
        raise ValueError("matrix must be 2-dimensional")

    k = matrix.shape[1]

    row_sums = matrix.sum(axis=1)
    col_sums = matrix.sum(axis=0)
    total = matrix.sum()

    numerator = (k - 1) * (k * np.sum(col_sums ** 2) - total ** 2)
    denominator = k * np.sum(row_sums) - np.sum(row_sums ** 2)

    if denominator == 0:
        return 0.0, 1.0

    q = float(numerator / denominator)
    p = float(1 - chi2.cdf(q, df=k - 1))

    return q, p


# ------------------------------------------------------------
# Pairwise McNemar (exact) from matrix
# ------------------------------------------------------------

def pairwise_mcnemar_from_matrix(
    matrix: np.ndarray,
    tool_order: List[str],
):
    rows = []

    for i, j in combinations(range(len(tool_order)), 2):
        a = matrix[:, i]
        b = matrix[:, j]

        n10 = int(np.sum((a == 1) & (b == 0)))
        n01 = int(np.sum((a == 0) & (b == 1)))

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
                "tool_a": tool_order[i],
                "tool_b": tool_order[j],
                "n10": n10,
                "n01": n01,
                "p": p,
                "p_adj": None,
            }
        )

    return rows


# ------------------------------------------------------------
# Holm correction
# ------------------------------------------------------------

def holm(rows):
    rows_sorted = sorted(rows, key=lambda r: r["p"])
    m = len(rows_sorted)

    running_max = 0.0
    for i, r in enumerate(rows_sorted):
        raw = min((m - i) * r["p"], 1.0)
        running_max = max(running_max, raw)
        r["p_adj"] = running_max

    return rows_sorted


# ------------------------------------------------------------
# LaTeX output
# ------------------------------------------------------------

def write_significance_latex(Q, p_q, rows, output_file):
    def fmt(x):
        if x < 0.001:
            return "<0.001"
        return f"{x:.3f}"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\\paragraph{Statistical significance.}\n")

        signif = "a significant" if p_q < 0.05 else "no significant"

        f.write(
            f"To determine whether the observed recall differences are "
            f"statistically significant, we first apply Cochran's $Q$ test. "
            f"The test indicates {signif} overall difference "
            f"(Q={Q:.2f}, p={fmt(p_q)}).\n\n"
        )

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

