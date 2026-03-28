from __future__ import annotations

import numpy as np
from itertools import combinations
from typing import Dict, List, Tuple
from scipy.stats import binomtest, chi2


# =========================
# Detection Matrix
# =========================

def build_detection_matrix_from_vectors(
    detection_vectors_by_tool: Dict[str, List[int]]
) -> Tuple[np.ndarray, List[str]]:
    tools = sorted(detection_vectors_by_tool.keys())

    lengths = {len(v) for v in detection_vectors_by_tool.values()}
    if len(lengths) != 1:
        raise ValueError("Detection vectors have inconsistent lengths")

    matrix = np.array([detection_vectors_by_tool[t] for t in tools]).T
    return matrix, tools


# =========================
# Cochran's Q Test
# =========================

def cochran_q_test(matrix: np.ndarray) -> Tuple[float, float]:
    k = matrix.shape[1]
    n = matrix.shape[0]

    row_sums = matrix.sum(axis=1)
    col_sums = matrix.sum(axis=0)

    numerator = (k - 1) * (
        k * (col_sums**2).sum() - (col_sums.sum() ** 2)
    )
    denominator = k * row_sums.sum() - (row_sums**2).sum()

    if denominator == 0:
        return 0.0, 1.0

    q = numerator / denominator
    p = 1 - chi2.cdf(q, k - 1)

    return float(q), float(p)


# =========================
# Pairwise McNemar
# =========================

def pairwise_mcnemar_from_matrix(matrix: np.ndarray, tools: List[str]):
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

        rows.append({
            "tool_a": tools[i],
            "tool_b": tools[j],
            "n10": n10,
            "n01": n01,
            "p": p,
            "p_adj": None,
        })

    return rows


# =========================
# Holm correction
# =========================

def holm(rows):
    rows_sorted = sorted(rows, key=lambda x: x["p"])
    m = len(rows_sorted)

    for i, row in enumerate(rows_sorted):
        row["p_adj"] = min((m - i) * row["p"], 1.0)

    return rows_sorted


# =========================
# LaTeX output
# =========================

def write_significance_latex(q, p_q, rows, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\\paragraph{Statistical significance.}\n")
        f.write(
            f"To determine whether the observed recall differences are statistically significant, "
            f"we first apply Cochran's $Q$ test. "
            f"The test indicates {'a significant' if p_q < 0.05 else 'no significant'} overall difference "
            f"(Q={q:.2f}, p={'<0.001' if p_q < 0.001 else f'{p_q:.3f}'}).\n\n"
        )

        f.write("\\begin{table*}[!t]\n\\centering\n\\small\n")
        f.write("\\begin{tabular}{llrrrr}\n\\toprule\n")
        f.write("Tool A & Tool B & $n_{10}$ & $n_{01}$ & $p$ & $p_{\\mathrm{adj}}$ \\\\\n")
        f.write("\\midrule\n")

        for r in rows:
            p_str = "<0.001" if r["p"] < 0.001 else f"{r['p']:.3f}"
            p_adj_str = "<0.001" if r["p_adj"] < 0.001 else f"{r['p_adj']:.3f}"

            f.write(
                f"{r['tool_a']} & {r['tool_b']} & {r['n10']} & {r['n01']} & {p_str} & {p_adj_str} \\\\\n"
            )

        f.write("\\bottomrule\n\\end{tabular}\n\\end{table*}\n")