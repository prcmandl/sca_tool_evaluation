#!/usr/bin/en#!/usr/bin/env python3
from __future__ import annotations
import logging
from pathlib import Path

from evaluation.core.tools import tool_file_id

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-5s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("dump_tool_findings")


# ------------------------------------------------------------
# Dump tool findings into file
# ------------------------------------------------------------

def dump_tool_findings_csv(
    *,
    tool_name: str,
    tool_findings: list,
    ground_truth_csv: str,
) -> Path:
    """
    Dump all normalized tool findings to a CSV compatible
    with the ground truth schema.
    """

    import csv
    from pathlib import Path
    import logging

    log = logging.getLogger("evaluation.dump")

    tool_id = tool_name.lower().replace(" ", "-")
    gt_path = Path(ground_truth_csv)


    tool_id = tool_file_id(tool_name)

    out_path = gt_path.with_name(
        f"{gt_path.stem}_{tool_id}_evaluation_findings.csv"
    )

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "ecosystem",
                "component_name",
                "component_version",
                "vulnerability_id",
                "cve",
                "vulnerability_description",
                "is_vulnerable",
            ],
        )
        writer.writeheader()

        for t in tool_findings:
            writer.writerow({
                "ecosystem": t.ecosystem,
                "component_name": t.component,
                "component_version": t.version,
                "vulnerability_id": t.osv_id or "-",
                "cve": t.cve or "-",
                "vulnerability_description": (t.description or "").strip(),
                "is_vulnerable": True,
            })

    log.info("Dumped %d %s findings to %s", len(tool_findings), tool_name, out_path)
    return out_path