# evaluation/ground_truth.py
import csv
from pathlib import Path
from typing import List

from model import Finding
from normalization import (
    normalize_component,
    normalize_identifier,
    normalize_version,
)

def load_ground_truth(path: Path) -> List[Finding]:
    rows: List[Finding] = []

    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for r in reader:
            eco = (r.get("ecosystem") or "").strip().lower()
            raw_name = (r.get("component_name") or "").strip()

            # Component identity rules
            if eco in {"maven", "nuget"}:
                component = raw_name
            else:
                component = normalize_component(eco, raw_name)

            rows.append(
                Finding(
                    ecosystem=eco,
                    component=component,
                    version=normalize_version(r.get("component_version")),
                    purl=(r.get("purl") or "").strip() or None,
                    cve=normalize_identifier(r.get("cve")),
                    osv_id=normalize_identifier(r.get("vulnerability_id")),
                    description=r.get("vulnerability_description") or "",
                    source="ground-truth",
                )
            )

    return rows
