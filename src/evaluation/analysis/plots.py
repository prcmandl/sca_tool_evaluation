from __future__ import annotations

import logging
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import BoundaryNorm, ListedColormap

log = logging.getLogger("evaluation.analysis.plots")


def _resolve_output_png_path(out, default_filename: str) -> Path:
    out = Path(out)

    if out.suffix.lower() == ".png":
        out.parent.mkdir(parents=True, exist_ok=True)
        return out

    out.mkdir(parents=True, exist_ok=True)
    return out / default_filename


def plot_significance_matrix(rows, tools, output_path):
    """
    Pairwise significance matrix from McNemar + Holm.

    Darstellung:
    - Diagonale: "-"
    - oberes Dreieck: "*" bei signifikant, sonst adjustierter p-Wert
    - unteres Dreieck: leer
    """
    output_png = _resolve_output_png_path(
        output_path,
        "recall_significance_matrix.png",
    )

    n = len(tools)
    tool_index = {tool: idx for idx, tool in enumerate(tools)}

    # 0 = diagonal, 1 = significant, 2 = not significant
    display = np.full((n, n), 2, dtype=int)
    np.fill_diagonal(display, 0)

    labels = [["" for _ in range(n)] for _ in range(n)]
    for i in range(n):
        labels[i][i] = "-"

    for row in rows:
        i = tool_index[row["tool_a"]]
        j = tool_index[row["tool_b"]]

        p_adj = float(row.get("p_adj", row.get("p", 1.0)))
        significant = p_adj < 0.05

        display[i, j] = 1 if significant else 2
        display[j, i] = 1 if significant else 2

        if i < j:
            labels[i][j] = "*" if significant else f"{p_adj:.2f}"
        elif j < i:
            labels[j][i] = "*" if significant else f"{p_adj:.2f}"

    cmap = ListedColormap(["#d9d9d9", "#eeeeee", "#f7f7f7"])
    norm = BoundaryNorm([-0.5, 0.5, 1.5, 2.5], cmap.N)

    short_labels = {
        "dependency-track": "dtrack",
        "dtrack": "dtrack",
        "oss-index": "oss-index",
        "github": "github",
        "snyk": "snyk",
        "trivy": "trivy",
    }
    tick_labels = [short_labels.get(t, t) for t in tools]

    fig, ax = plt.subplots(figsize=(11, 11))
    ax.imshow(display, cmap=cmap, norm=norm, interpolation="nearest")

    ax.set_title("Recall Significance (McNemar + Holm)", fontsize=18, pad=18)
    ax.set_xticks(range(n))
    ax.set_yticks(range(n))
    ax.set_xticklabels(tick_labels, rotation=35, ha="right", fontsize=15)
    ax.set_yticklabels(tick_labels, fontsize=15)

    ax.set_xticks(np.arange(-0.5, n, 1), minor=True)
    ax.set_yticks(np.arange(-0.5, n, 1), minor=True)
    ax.grid(which="minor", color="white", linewidth=1.5)
    ax.tick_params(which="minor", bottom=False, left=False)

    for i in range(n):
        for j in range(n):
            if labels[i][j]:
                ax.text(
                    j,
                    i,
                    labels[i][j],
                    ha="center",
                    va="center",
                    color="black",
                    fontsize=18,
                    fontweight="bold",
                )

    fig.text(
        0.5,
        0.03,
        "* = signifikant, sonst adjustierter p-Wert",
        ha="center",
        fontsize=13,
    )

    fig.tight_layout(rect=[0, 0.05, 1, 1])
    fig.savefig(output_png, dpi=300, bbox_inches="tight")
    plt.close(fig)

    writer = globals().get("_write_significance_matrix_tex")
    if callable(writer):
        writer(display, tools, str(output_png.parent))

    log.info("[PLOT] Significance matrix: %s", output_png)


def plot_tool_comparison(agg: dict, output_path) -> None:
    """
    Creates the tool comparison bar chart.

    Accepts either:
    - a directory path, then writes tool_comparison.png there
    - or a full .png file path
    """
    output_png = _resolve_output_png_path(output_path, "tool_comparison.png")

    tools = list(agg.keys())

    mean_recall = []
    mean_overlap = []

    for tool in tools:
        ecosystems = list(agg[tool].keys())
        if not ecosystems:
            mean_recall.append(0.0)
            mean_overlap.append(0.0)
            continue

        recall = sum(
            agg[tool][eco]["Recall"]["mean"] for eco in ecosystems
        ) / len(ecosystems)
        overlap = sum(
            agg[tool][eco]["Overlap"]["mean"] for eco in ecosystems
        ) / len(ecosystems)

        mean_recall.append(recall)
        mean_overlap.append(overlap)

    x = list(range(len(tools)))
    width = 0.38

    fig, ax = plt.subplots(figsize=(10, 7))

    ax.bar(
        [i - width / 2 for i in x],
        mean_recall,
        width=width,
        color="#666666",
        label="Recall",
    )
    ax.bar(
        [i + width / 2 for i in x],
        mean_overlap,
        width=width,
        color="#b0b0b0",
        label="Overlap",
    )

    ax.set_title("Tool Comparison (Recall vs Overlap)", fontsize=22, pad=12)
    ax.set_ylabel("Score", fontsize=18)
    ax.set_ylim(0, 1.035)

    ax.set_xticks(x)
    ax.set_xticklabels(tools, rotation=35, ha="right", fontsize=16)
    ax.tick_params(axis="y", labelsize=16)

    ax.legend(loc="upper left", fontsize=16, frameon=True)

    fig.tight_layout()
    fig.savefig(output_png, dpi=150, bbox_inches="tight")
    plt.close(fig)

    log.info("[PLOT] Tool comparison: %s", output_png)
