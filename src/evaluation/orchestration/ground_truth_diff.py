from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from evaluation.core.ground_truth import load_ground_truth


def finding_to_row(f):
    vuln_id = f.cve or f.osv_id or ""
    return {
        "ecosystem": f.ecosystem,
        "component": f.component,
        "version": f.version,
        "vuln_id": vuln_id,
    }


def finding_key(f):
    row = finding_to_row(f)
    return (
        row["ecosystem"],
        row["component"],
        row["version"],
        row["vuln_id"],
    )


def expand_counter_difference(counter_a: Counter, counter_b: Counter):
    """
    Returns entries in A-B with multiplicity preserved.
    """
    diff = []
    for key, count_a in counter_a.items():
        count_b = counter_b.get(key, 0)
        if count_a > count_b:
            diff.extend([key] * (count_a - count_b))
    return diff


def summarize_by_ecosystem(keys):
    stats = defaultdict(lambda: {
        "rows": 0,
        "components": set(),
        "vuln_ids": set(),
    })

    for eco, comp, ver, vuln_id in keys:
        stats[eco]["rows"] += 1
        stats[eco]["components"].add((comp, ver))
        if vuln_id:
            stats[eco]["vuln_ids"].add(vuln_id)

    out = {}
    for eco, val in sorted(stats.items()):
        out[eco] = {
            "rows": val["rows"],
            "unique_components": len(val["components"]),
            "unique_vuln_ids": len(val["vuln_ids"]),
        }
    return out


def write_rows_csv(path: Path, keys):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ecosystem", "component", "version", "vuln_id"])
        for row in keys:
            writer.writerow(row)


def build_diff(gt0_path: Path, gt1_path: Path, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    gt0 = load_ground_truth(gt0_path)
    gt1 = load_ground_truth(gt1_path)

    gt0_keys = [finding_key(f) for f in gt0]
    gt1_keys = [finding_key(f) for f in gt1]

    c0 = Counter(gt0_keys)
    c1 = Counter(gt1_keys)

    added = expand_counter_difference(c1, c0)
    removed = expand_counter_difference(c0, c1)

    shared_unique = set(c0.keys()) & set(c1.keys())
    all_unique = set(c0.keys()) | set(c1.keys())

    summary = {
        "gt0_path": str(gt0_path),
        "gt1_path": str(gt1_path),
        "gt0_total_rows": len(gt0_keys),
        "gt1_total_rows": len(gt1_keys),
        "gt0_unique_findings": len(c0),
        "gt1_unique_findings": len(c1),
        "shared_unique_findings": len(shared_unique),
        "added_rows": len(added),
        "removed_rows": len(removed),
        "net_row_delta": len(gt1_keys) - len(gt0_keys),
        "jaccard_unique_findings": (
            len(shared_unique) / len(all_unique) if all_unique else 1.0
        ),
        "added_by_ecosystem": summarize_by_ecosystem(added),
        "removed_by_ecosystem": summarize_by_ecosystem(removed),
        "top_added_examples": [list(x) for x in added[:25]],
        "top_removed_examples": [list(x) for x in removed[:25]],
    }

    with (output_dir / "gt_diff_summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    write_rows_csv(output_dir / "gt_diff_added.csv", added)
    write_rows_csv(output_dir / "gt_diff_removed.csv", removed)

    with (output_dir / "gt_diff_report.txt").open("w", encoding="utf-8") as f:
        f.write("GROUND TRUTH DIFFERENCE REPORT\n")
        f.write("========================================\n\n")
        f.write(f"GT0: {gt0_path}\n")
        f.write(f"GT1: {gt1_path}\n\n")
        f.write(f"GT0 total rows:         {summary['gt0_total_rows']}\n")
        f.write(f"GT1 total rows:         {summary['gt1_total_rows']}\n")
        f.write(f"GT0 unique findings:    {summary['gt0_unique_findings']}\n")
        f.write(f"GT1 unique findings:    {summary['gt1_unique_findings']}\n")
        f.write(f"Shared unique findings: {summary['shared_unique_findings']}\n")
        f.write(f"Added rows:             {summary['added_rows']}\n")
        f.write(f"Removed rows:           {summary['removed_rows']}\n")
        f.write(f"Net row delta:          {summary['net_row_delta']}\n")
        f.write(f"Jaccard(unique):        {summary['jaccard_unique_findings']:.4f}\n\n")

        f.write("ADDED BY ECOSYSTEM\n")
        f.write("----------------------------------------\n")
        for eco, vals in summary["added_by_ecosystem"].items():
            f.write(
                f"{eco}: rows={vals['rows']}, "
                f"components={vals['unique_components']}, "
                f"vuln_ids={vals['unique_vuln_ids']}\n"
            )

        f.write("\nREMOVED BY ECOSYSTEM\n")
        f.write("----------------------------------------\n")
        for eco, vals in summary["removed_by_ecosystem"].items():
            f.write(
                f"{eco}: rows={vals['rows']}, "
                f"components={vals['unique_components']}, "
                f"vuln_ids={vals['unique_vuln_ids']}\n"
            )

        f.write("\nTOP ADDED EXAMPLES\n")
        f.write("----------------------------------------\n")
        for row in added[:25]:
            f.write(f"{row}\n")

        f.write("\nTOP REMOVED EXAMPLES\n")
        f.write("----------------------------------------\n")
        for row in removed[:25]:
            f.write(f"{row}\n")

    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt0", required=True)
    ap.add_argument("--gt1", required=True)
    ap.add_argument("--output-dir", required=True)
    args = ap.parse_args()

    summary = build_diff(
        gt0_path=Path(args.gt0),
        gt1_path=Path(args.gt1),
        output_dir=Path(args.output_dir),
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()