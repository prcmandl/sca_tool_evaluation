#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from evaluation.core.ground_truth import load_ground_truth


def compute_gt_hash(gt_path: Path) -> str:
    gt = load_ground_truth(gt_path)
    payload = sorted(
        [g.ecosystem, g.component, g.version, g.cve or g.osv_id or ""]
        for g in gt
    )
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("ground_truth", help="Path to the ground-truth CSV file")
    args = parser.parse_args()
    print(compute_gt_hash(Path(args.ground_truth)))


if __name__ == "__main__":
    main()
