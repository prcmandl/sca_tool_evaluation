# validation.py

from collections import Counter, defaultdict
from statistics import median


def compute_balance_validation(rows):
    by_eco = defaultdict(list)

    for r in rows:
        by_eco[r["ecosystem"].lower()].append(r)

    result = {}

    for eco, eco_rows in by_eco.items():
        comp_counter = Counter(r["component_name"] for r in eco_rows)
        comp_ver_counter = Counter(
            (r["component_name"], r["component_version"]) for r in eco_rows
        )

        total = len(eco_rows)
        comp_counts = sorted(comp_counter.values(), reverse=True)

        result[eco] = {
            "rows": total,
            "unique_components": len(comp_counter),
            "unique_versions": len(comp_ver_counter),
            "median_per_component": median(comp_counter.values()) if comp_counter else 0,
            "max_per_component": max(comp_counter.values()) if comp_counter else 0,
            "top1_share": comp_counts[0] / total if total else 0,
            "top5_share": sum(comp_counts[:5]) / total if total else 0,
        }

    return result