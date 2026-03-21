from pathlib import Path
from typing import List, Tuple

from evaluation.core.model import Finding


# ------------------------------------------------------------------
# Column specification: (Header, Finding attribute)
# ------------------------------------------------------------------

COLUMNS: List[Tuple[str, str]] = [
    ("Ecosystem", "ecosystem"),
    ("Component", "component"),
    ("Version", "version"),
    ("CVE", "cve"),
    ("GHSA", "ghsa"),
    ("OSV-ID", "osv_id"),
    ("Affected-Range", "affected_version_range"),
    ("Source", "source"),
]


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def write_tool_findings_txt(
    *,
    out_dir: Path,
    ground_truth_name: str,
    tool: str,
    run_id: str, # run_id not used in path name
    findings: List[Finding],
) -> Path:
    """
    Write normalized tool findings as a fixed-width TXT table.

    Column widths are computed dynamically:
      width = max(len(header), max(len(value))) + 1

    This file represents the documented INPUT SNAPSHOT of the evaluation.
    """

    # run_id not used in path name
    out_dir.mkdir(parents=True, exist_ok=True)

    fname = f"{ground_truth_name}_{tool}_tool_findings.txt"
    path = out_dir / fname

    # ------------------------------------------------------------
    # Compute column widths (max + 1)
    # ------------------------------------------------------------
    col_widths = _compute_column_widths(COLUMNS, findings)

    # ------------------------------------------------------------
    # Render table
    # ------------------------------------------------------------
    lines: List[str] = []

    # Header block
    lines.append("Tool Findings (normalized)")
    lines.append("=" * 27)
    lines.append(f"Ground truth : {ground_truth_name}")
    lines.append(f"Tool         : {tool}")
    lines.append(f"Run ID       : {run_id}")
    lines.append(f"Total        : {len(findings)} findings")
    lines.append("")

    # Table header
    header_line = _format_row(
        [(h, h) for h, _ in COLUMNS],
        col_widths,
    )
    lines.append(header_line)
    lines.append("-" * len(header_line))

    # Table rows
    for f in findings:
        row_values = []
        for header, attr in COLUMNS:
            val = getattr(f, attr, None)
            row_values.append(
                (header, "-" if val in (None, "") else str(val))
            )

        lines.append(_format_row(row_values, col_widths))

    # ------------------------------------------------------------
    # Write file
    # ------------------------------------------------------------
    with path.open("w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
        fp.write("\n")

    # Safety check: all table rows have equal length
    table_lines = lines[lines.index(header_line):]
    first_len = len(table_lines[0])
    assert all(len(l) == first_len for l in table_lines), \
        "Misaligned table detected in tool findings TXT output"

    return path


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _compute_column_widths(
    columns: List[Tuple[str, str]],
    findings: List[Finding],
) -> dict:
    """
    Compute column widths as:
      max(len(header), max(len(value))) + 1
    """
    widths = {}

    for header, attr in columns:
        max_len = len(header)

        for f in findings:
            val = getattr(f, attr, None)
            s = "-" if val in (None, "") else str(val)
            max_len = max(max_len, len(s))

        widths[header] = max_len + 1

    return widths


def _format_row(
    values: List[Tuple[str, str]],
    widths: dict,
) -> str:
    """
    Format a single table row using left-aligned fixed-width columns.
    """
    parts = []
    for header, value in values:
        parts.append(f"{value:<{widths[header]}}")
    return " | ".join(parts)
