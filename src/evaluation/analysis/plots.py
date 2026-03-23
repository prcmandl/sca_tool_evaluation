import matplotlib.pyplot as plt

import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path


def plot_tool_comparison(agg, output_dir: str):
    """
    Plot Recall and Overlap per tool (aggregated over ecosystems)

    agg: output of aggregate() + add_confidence_intervals()
    """

    tools = sorted(agg.keys())

    recall_vals = []
    overlap_vals = []

    for tool in tools:
        tp_sum = fp_sum = fn_sum = 0

        for eco in agg[tool]:
            row = agg[tool][eco]

            tp_sum += row["TP"]["mean"]
            fp_sum += row["FP"]["mean"]
            fn_sum += row["FN"]["mean"]

        recall = tp_sum / (tp_sum + fn_sum) if (tp_sum + fn_sum) else 0
        overlap = tp_sum / (tp_sum + fp_sum) if (tp_sum + fp_sum) else 0

        recall_vals.append(recall)
        overlap_vals.append(overlap)

    x = np.arange(len(tools))
    width = 0.35

    plt.figure()

    plt.bar(x - width/2, recall_vals, width, label="Recall")
    plt.bar(x + width/2, overlap_vals, width, label="Overlap")

    plt.xticks(x, tools)
    plt.ylabel("Score")
    plt.title("Tool Comparison (Recall vs Overlap)")
    plt.legend()

    out_path = Path(output_dir) / "tool_comparison.png"
    plt.savefig(out_path)
    plt.close()

    print(f"[PLOT] Written: {out_path}")