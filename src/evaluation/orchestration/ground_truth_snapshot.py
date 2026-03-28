from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from pathlib import Path


def find_latest_csv(build_dir: Path) -> Path:
    candidates = sorted(
        build_dir.glob("*.csv"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise FileNotFoundError(f"No CSV found in {build_dir}")
    return candidates[0]


def derive_related_files(csv_path: Path) -> tuple[Path, Path | None]:
    base = csv_path.name.removesuffix(".csv")
    sbom = csv_path.with_name(f"{base}.sbom.json")
    stat = csv_path.with_name(f"{base}.stat.txt")

    if not sbom.exists():
        raise FileNotFoundError(f"Matching SBOM not found for {csv_path}")

    return sbom, (stat if stat.exists() else None)


def copy_snapshot(
    csv_path: Path,
    sbom_path: Path,
    stat_path: Path | None,
    output_dir: Path,
    prefix: str,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    out_csv = output_dir / f"{prefix}.csv"
    out_sbom = output_dir / f"{prefix}.sbom.json"

    shutil.copy2(csv_path, out_csv)
    shutil.copy2(sbom_path, out_sbom)

    out_stat = None
    if stat_path is not None:
        out_stat = output_dir / f"{prefix}.stat.txt"
        shutil.copy2(stat_path, out_stat)

    return {
        "csv": str(out_csv),
        "sbom": str(out_sbom),
        "stat": str(out_stat) if out_stat is not None else None,
    }


def build_snapshot(build_dir: Path, output_dir: Path, prefix: str) -> dict:
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["GROUND_TRUTH_BUILD_PATH"] = str(build_dir)

    start = time.time()
    subprocess.run(
        [
            "python",
            "-m",
            "ground_truth_generation.build_multi_ground_truth_dataset",
        ],
        check=True,
        env=env,
    )
    duration = time.time() - start

    csv_path = find_latest_csv(build_dir)
    sbom_path, stat_path = derive_related_files(csv_path)

    copied = copy_snapshot(
        csv_path=csv_path,
        sbom_path=sbom_path,
        stat_path=stat_path,
        output_dir=output_dir,
        prefix=prefix,
    )
    copied["build_duration_seconds"] = duration
    return copied


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--prefix", required=True)
    args = ap.parse_args()

    result = build_snapshot(
        build_dir=Path(args.build_dir),
        output_dir=Path(args.output_dir),
        prefix=args.prefix,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()