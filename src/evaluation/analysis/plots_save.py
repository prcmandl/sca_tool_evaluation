import matplotlib.pyplot as plt
import numpy as np

import logging
log = logging.getLogger("evaluation.analysis.plots")

def plot_significance_matrix(rows, tools, output_dir):
    """
    Creates a significance heatmap from McNemar experimental_results
    in grayscale.
    """
    n = len(tools)
    matrix = np.zeros((n, n))

    tool_index = {t: i for i, t in enumerate(tools)}

    for r in rows:
        i = tool_index[r["tool_a"]]
        j = tool_index[r["tool_b"]]

        val = 1 if r["p_adj"] < 0.05 else 0
        matrix[i, j] = val
        matrix[j, i] = val

    fig, ax = plt.subplots()

    # grayscale colormap, fixed range for stable rendering
    im = ax.imshow(matrix, cmap="Greys", vmin=0, vmax=1)

    ax.set_xticks(range(n))
    ax.set_yticks(range(n))
    ax.set_xticklabels(tools, rotation=45, ha="right")
    ax.set_yticklabels(tools)

    for i in range(n):
        for j in range(n):
            if i == j:
                text = "-"
            else:
                text = "*" if matrix[i, j] == 1 else "ns"

            # darker cell -> use white text, lighter cell -> black text
            text_color = "white" if matrix[i, j] == 1 and i != j else "black"
            ax.text(j, i, text, ha="center", va="center", color=text_color)

    ax.set_title("Recall Significance (McNemar + Holm)")
    plt.tight_layout()

    out = f"{output_dir}/recall_significance_matrix.png"
    plt.savefig(out, dpi=300, bbox_inches="tight")
    plt.close()

    log.info(f"[PLOT] Significance matrix: {out}")


def plot_tool_comparison(agg, output_dir):
    """
    Creates a grouped bar chart:
    - X: tools
    - bars: Recall and Overlap side by side
    - grayscale styling
    """
    tools = list(agg.keys())

    recall_vals = []
    overlap_vals = []

    for tool in tools:
        ecos = agg[tool]

        recalls = [v["Recall"]["mean"] for v in ecos.values()]
        overlaps = [v["Overlap"]["mean"] for v in ecos.values()]

        recall_vals.append(sum(recalls) / len(recalls))
        overlap_vals.append(sum(overlaps) / len(overlaps))

    x = np.arange(len(tools))
    width = 0.38

    fig, ax = plt.subplots()

    ax.bar(x - width / 2, recall_vals, width=width, color="0.35", label="Recall")
    ax.bar(x + width / 2, overlap_vals, width=width, color="0.70", label="Overlap")

    ax.set_xticks(x)
    ax.set_xticklabels(tools, rotation=30)
    ax.set_ylabel("Score")
    ax.set_title("Tool Comparison (Recall vs Overlap)")
    ax.legend()

    plt.tight_layout()
    plt.savefig(f"{output_dir}/tool_comparison.png", dpi=300, bbox_inches="tight")
    plt.close()
