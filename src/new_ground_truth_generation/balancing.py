# balancing.py

from collections import defaultdict, deque, Counter
from statistics import median


def balance_rows_by_vulnerability_deterministic(rows, ecosystems, strategy="min"):
    by_eco = defaultdict(list)

    for r in rows:
        eco = (r.get("ecosystem") or "").lower()
        if eco in ecosystems:
            by_eco[eco].append(r)

    counts = {eco: len(v) for eco, v in by_eco.items() if v}
    if not counts:
        raise RuntimeError("No data to balance")

    if strategy == "min":
        target = min(counts.values())
    elif strategy == "median":
        target = int(median(counts.values()))
    else:
        raise ValueError(strategy)

    balanced = []
    stats = {}

    for eco in ecosystems:
        eco_rows = by_eco.get(eco, [])

        groups = defaultdict(list)
        comp_counter = Counter()

        for r in eco_rows:
            key = (r["component_name"], r["component_version"])
            groups[key].append(r)
            comp_counter[r["component_name"]] += 1

        ordered = []

        for (comp, ver), items in groups.items():
            items_sorted = sorted(
                items,
                key=lambda r: (
                    str(r.get("vulnerability_id") or ""),
                    str(r.get("cve") or ""),
                ),
            )
            ordered.append((
                len(items_sorted),
                comp_counter[comp],
                comp.lower(),
                str(ver),
                deque(items_sorted),
            ))

        ordered.sort(key=lambda x: (x[0], x[1], x[2], x[3]))

        active = [o[4] for o in ordered]
        selected = []

        while len(selected) < target and active:
            next_active = []
            for q in active:
                if len(selected) >= target:
                    break
                if q:
                    selected.append(q.popleft())
                if q:
                    next_active.append(q)
            active = next_active

        balanced.extend(selected)

        stats[eco] = {
            "original_rows": len(eco_rows),
            "kept_rows": len(selected),
            "target": target,
            "unique_components": len({r["component_name"] for r in selected}),
        }

    return balanced, stats


def cap_per_component(rows, max_per_component=10):
    out = []
    counter = defaultdict(int)

    for r in rows:
        key = (r["ecosystem"], r["component_name"])

        if counter[key] < max_per_component:
            out.append(r)
            counter[key] += 1

    return out