from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from evaluation.core.ground_truth import load_ground_truth


def finding_key(f) -> tuple[str, str, str, str]:
    vuln_id = f.cve or f.osv_id or ""
    return (f.ecosystem, f.component, f.version, vuln_id)


def hash_gt(path: Path) -> str:
    gt = load_ground_truth(path)
    payload = sorted(finding_key(x) for x in gt)
    return hashlib.sha256(str(payload).encode()).hexdigest()


def expand_difference(a: Counter, b: Counter) -> list[tuple[str, str, str, str]]:
    out: list[tuple[str, str, str, str]] = []
    for key, count_a in a.items():
        count_b = b.get(key, 0)
        if count_a > count_b:
            out.extend([key] * (count_a - count_b))
    return out


def summarize(keys: list[tuple[str, str, str, str]]) -> dict:
    stats = defaultdict(lambda: {"rows": 0, "components": set(), "vuln_ids": set()})

    for eco, comp, ver, vuln_id in keys:
        stats[eco]["rows"] += 1
        stats[eco]["components"].add((comp, ver))
        if vuln_id:
            stats[eco]["vuln_ids"].add(vuln_id)

    return {
        eco: {
            "rows": data["rows"],
            "unique_components": len(data["components"]),
            "unique_vuln_ids": len(data["vuln_ids"]),
        }
        for eco, data in sorted(stats.items())
    }


def write_csv(path: Path, rows: list[tuple[str, str, str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ecosystem", "component", "version", "vuln_id"])
        for row in rows:
            writer.writerow(row)


def compare_ground_truth(gt0_path: Path, gt1_path: Path, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    gt0 = load_ground_truth(gt0_path)
    gt1 = load_ground_truth(gt1_path)

    rows0 = [finding_key(x) for x in gt0]
    rows1 = [finding_key(x) for x in gt1]

    c0 = Counter(rows0)
    c1 = Counter(rows1)

    added = expand_difference(c1, c0)
    removed = expand_difference(c0, c1)

    s0 = set(c0.keys())
    s1 = set(c1.keys())
    shared = s0 & s1
    union = s0 | s1

    summary = {
        "gt0_path": str(gt0_path),
        "gt1_path": str(gt1_path),
        "gt0_hash": hash_gt(gt0_path),
        "gt1_hash": hash_gt(gt1_path),
        "equal": rows0 == rows1,
        "gt0_total_rows": len(rows0),
        "gt1_total_rows": len(rows1),
        "gt0_unique_findings": len(s0),
        "gt1_unique_findings": len(s1),
        "shared_unique_findings": len(shared),
        "added_rows": len(added),
        "removed_rows": len(removed),
        "net_row_delta": len(rows1) - len(rows0),
        "jaccard_unique_findings": (len(shared) / len(union) if union else 1.0),
        "added_by_ecosystem": summarize(added),
        "removed_by_ecosystem": summarize(removed),
        "top_added_examples": [list(x) for x in added[:25]],
        "top_removed_examples": [list(x) for x in removed[:25]],
    }

    (output_dir / "gt_diff_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    write_csv(output_dir / "gt_diff_added.csv", added)
    write_csv(output_dir / "gt_diff_removed.csv", removed)

    with (output_dir / "gt_diff_report.txt").open("w", encoding="utf-8") as f:
        f.write("GROUND TRUTH DIFFERENCE REPORT\n")
        f.write("========================================\n\n")
        f.write(f"GT0: {gt0_path}\n")
        f.write(f"GT1: {gt1_path}\n\n")
        for key in [
            "equal",
            "gt0_hash",
            "gt1_hash",
            "gt0_total_rows",
            "gt1_total_rows",
            "gt0_unique_findings",
            "gt1_unique_findings",
            "shared_unique_findings",
            "added_rows",
            "removed_rows",
            "net_row_delta",
            "jaccard_unique_findings",
        ]:
            f.write(f"{key}: {summary[key]}\n")

        f.write("\nADDED BY ECOSYSTEM\n")
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

    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt0", required=True)
    ap.add_argument("--gt1", required=True)
    ap.add_argument("--output-dir", required=True)
    args = ap.parse_args()

    summary = compare_ground_truth(
        gt0_path=Path(args.gt0),
        gt1_path=Path(args.gt1),
        output_dir=Path(args.output_dir),
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
