import matplotlib.pyplot as plt


def plot_recall(agg, output_path):
    for eco in next(iter(agg.values())).keys():
        plt.figure()

        tools = []
        means = []
        errors = []

        for tool, ecos in agg.items():
            tools.append(tool)
            means.append(ecos[eco]["Recall"]["mean"])
            errors.append(ecos[eco]["Recall"]["ci95"])

        plt.bar(tools, means, yerr=errors)
        plt.title(f"Recall ({eco})")
        plt.ylabel("Recall")

        plt.savefig(f"{output_path}/recall_{eco}.png")
        plt.close()