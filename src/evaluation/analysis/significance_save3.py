from __future__ import annotations

from itertools import combinations
from typing import Dict, Iterable, List, Tuple

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
) -> np.ndarray:
    """
    Build a binary detection matrix from ground truth and tool findings.

    Rows  : ground-truth instances
    Cols  : tools
    Value : 1 if the tool detected the GT instance, else 0
    """
    tool_order = sorted(findings_by_tool.keys())
    gt_keys = [_key(g) for g in ground_truth]

    detected_by_tool = {
        tool: {_key(f) for f in findings}
        for tool, findings in findings_by_tool.items()
    }

    matrix = []
    for k in gt_keys:
        row = [1 if k in detected_by_tool[tool] else 0 for tool in tool_order]
        matrix.append(row)

    return np.array(matrix, dtype=int)


def cochran_q_test(matrix: np.ndarray) -> Tuple[float, float]:
    """
    matrix: shape (n_instances, n_tools)
    """
    if matrix.ndim != 2:
        raise ValueError("matrix must be 2-dimensional")

    if matrix.shape[1] < 2:
        return 0.0, 1.0

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


def pairwise_mcnemar(
    ground_truth: List[Finding],
    findings_by_tool: Dict[str, List[Finding]],
) -> List[dict]:
    """
    Pairwise exact McNemar tests on GT detections.

    n10: tool_a detects, tool_b misses
    n01: tool_a misses, tool_b detects
    """
    gt_keys = {_key(g) for g in ground_truth}
    detected = {
        tool: ({_key(f) for f in findings} & gt_keys)
        for tool, findings in findings_by_tool.items()
    }

    rows = []

    for tool_a, tool_b in combinations(findings_by_tool.keys(), 2):
        a = detected[tool_a]
        b = detected[tool_b]

        n10 = int(len(a - b))
        n01 = int(len(b - a))
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
                "tool_a": tool_a,
                "tool_b": tool_b,
                "n10": n10,
                "n01": n01,
                "p": p,
                "p_adj": None,
            }
        )

    return rows


def holm(rows: List[dict]) -> List[dict]:
    """
    Holm-Bonferroni adjustment with monotonic corrected p-values.
    Returns rows sorted by raw p-value.
    """
    rows_sorted = sorted(rows, key=lambda r: r["p"])
    m = len(rows_sorted)

    running_max = 0.0
    for i, row in enumerate(rows_sorted):
        raw_adj = min((m - i) * row["p"], 1.0)
        running_max = max(running_max, raw_adj)
        row["p_adj"] = running_max

    return rows_sorted


def write_significance_latex(
    Q: float,
    p_q: float,
    rows: Iterable[dict],
    output_file,
) -> None:
    def fmt(x: float) -> str:
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

        for row in rows:
            a = TOOL_NAMES.get(row["tool_a"], row["tool_a"])
            b = TOOL_NAMES.get(row["tool_b"], row["tool_b"])

            f.write(
                f"{a} & {b} & {row['n10']} & {row['n01']} & "
                f"{fmt(row['p'])} & {fmt(row['p_adj'])} \\\\\n"
            )

        f.write("\\bottomrule\n\\end{tabular}\n\\end{table*}\n")
