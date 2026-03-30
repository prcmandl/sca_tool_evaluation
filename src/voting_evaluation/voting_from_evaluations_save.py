#!/usr/bin/env python3
"""
voting_from_evaluations.py

Realisiert eine x/5-Voting-Strategie auf Basis von fünf Evaluationstexten.
Als "Treffer" werden genau die Vulnerabilities anerkannt, die in den
Evaluationsergebnissen der Tools als True Positive (TP_EXACT oder TP_RANGE)
auftreten und von mindestens x Tools bestätigt werden.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple


TOOL_ENV_MAP = {
    "dtrack": "DTRACK_EVAL_FILE",
    "github": "GITHUB_EVAL_FILE",
    "oss-index": "OSS_INDEX_EVAL_FILE",
    "snyk": "SNYK_EVAL_FILE",
    "trivy": "TRIVY_EVAL_FILE",
}


@dataclass(frozen=True)
class VulnKey:
    ecosystem: str
    component: str
    version: str
    cve_id: str
    osv_id: str


@dataclass
class ReportData:
    tool: str
    report_timestamp: str
    path: Path
    gt_size: int
    gt_size_by_ecosystem: Dict[str, int]
    tp_total: int
    recall: float
    overlap: float
    true_positives: set[VulnKey]


def normalize_cell(value: str) -> str:
    v = value.strip()
    if v == "-":
        return ""
    return re.sub(r"\s+", " ", v)


def parse_int(text: str, label: str) -> int:
    m = re.search(rf"^{re.escape(label)}\s*:\s*([0-9]+)\s*$", text, re.MULTILINE)
    if not m:
        raise ValueError(f"Kennzahl nicht gefunden: {label}")
    return int(m.group(1))


def parse_float(text: str, label: str) -> float:
    m = re.search(rf"^{re.escape(label)}\s*:\s*([0-9]*\.?[0-9]+)\s*$", text, re.MULTILINE)
    if not m:
        raise ValueError(f"Kennzahl nicht gefunden: {label}")
    return float(m.group(1))


def parse_header(text: str) -> Tuple[str, str]:
    m = re.search(r"^([A-Za-z0-9_.-]+)\s+Evaluation Report\s+\(([^)]+)\)", text, re.MULTILINE)
    if not m:
        raise ValueError("Kopfzeile des Reports konnte nicht gelesen werden.")
    return m.group(1).strip(), m.group(2).strip()


def extract_section(text: str, heading_regex: str) -> str:
    m = re.search(heading_regex, text, re.MULTILINE | re.DOTALL)
    if not m:
        raise ValueError(f"Abschnitt nicht gefunden: {heading_regex}")
    return m.group(1)


def parse_per_ecosystem_gt_sizes(text: str) -> Dict[str, int]:
    section = extract_section(
        text,
        r"Per-Ecosystem Statistics\s*\n[-]+\n.*?\n[-]+\n(.*?)(?:\n[-]+\nTOTAL|\nTOTAL|\n\n)",
    )
    result: Dict[str, int] = {}
    for raw_line in section.splitlines():
        line = raw_line.rstrip()
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3:
            continue
        eco = parts[0]
        if not eco or eco.lower() == "ecosystem":
            continue
        try:
            vulns = int(parts[2])
        except ValueError:
            continue
        result[eco] = vulns
    if not result:
        raise ValueError("Per-Ecosystem-Statistik konnte nicht geparst werden.")
    return result


def parse_true_positives(text: str) -> set[VulnKey]:
    m = re.search(
        r"True Positives\s*\(TP\s*=\s*TP_EXACT\s*\+\s*TP_RANGE\)\s*\(\d+\)\s*\n=+\n"
        r".*?\n[-]+\n(.*?)(?:\n\n[A-Z][^\n]*\n[=-]+|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not m:
        raise ValueError("True-Positive-Abschnitt wurde nicht gefunden.")
    block = m.group(1)

    tp_entries: set[VulnKey] = set()
    for raw_line in block.splitlines():
        line = raw_line.rstrip()
        if "|" not in line or re.match(r"^-{5,}$", line.strip()):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue

        eco = normalize_cell(parts[0])
        component = normalize_cell(parts[1])
        version = normalize_cell(parts[2])
        cve_id = normalize_cell(parts[3])
        osv_id = normalize_cell(parts[4])

        if eco.lower() == "ecosystem" or not eco or not component or not version:
            continue

        tp_entries.add(
            VulnKey(
                ecosystem=eco,
                component=component,
                version=version,
                cve_id=cve_id,
                osv_id=osv_id,
            )
        )

    if not tp_entries:
        raise ValueError("Keine True-Positive-Einträge gefunden.")
    return tp_entries


def parse_report(path: Path) -> ReportData:
    text = path.read_text(encoding="utf-8", errors="replace")
    tool, ts = parse_header(text)

    return ReportData(
        tool=tool,
        report_timestamp=ts,
        path=path,
        gt_size=parse_int(text, "Vulnerabilities in Ground Truth"),
        gt_size_by_ecosystem=parse_per_ecosystem_gt_sizes(text),
        tp_total=parse_int(text, "True Positives (TP_TOTAL)"),
        recall=parse_float(text, "Recall @ GT (TP_EXACT+TP_RANGE)"),
        overlap=parse_float(text, "Overlap Rate"),
        true_positives=parse_true_positives(text),
    )


def resolve_input_files(args: argparse.Namespace) -> List[Path]:
    files: List[str] = []

    if args.files:
        files.extend(args.files)

    env_list = os.environ.get("VOTING_EVAL_FILES", "").strip()
    if env_list:
        files.extend([p for p in re.split(r"[,:;]", env_list) if p.strip()])

    if not files:
        for env_name in TOOL_ENV_MAP.values():
            value = os.environ.get(env_name, "").strip()
            if value:
                files.append(value)

    unique_paths: List[Path] = []
    seen = set()
    for f in files:
        p = Path(f).expanduser().resolve()
        if p not in seen:
            unique_paths.append(p)
            seen.add(p)

    if len(unique_paths) != 5:
        raise SystemExit(
            f"Es werden genau 5 Evaluationsdateien benötigt, gefunden: {len(unique_paths)}."
        )

    missing = [str(p) for p in unique_paths if not p.exists()]
    if missing:
        raise SystemExit("Folgende Dateien fehlen:\n" + "\n".join(missing))

    return unique_paths


def render_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    string_rows = [[str(cell) for cell in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in string_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(row: Sequence[str]) -> str:
        return " | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))

    sep = "-+-".join("-" * w for w in widths)
    out = [fmt_row(headers), sep]
    out.extend(fmt_row(row) for row in string_rows)
    return "\n".join(out)


def percent(x: float) -> str:
    return f"{x:.3f}"


def build_voting_summary(reports: List[ReportData], threshold: int) -> str:
    if threshold < 1 or threshold > len(reports):
        raise SystemExit(f"Ungültiger Threshold: {threshold}. Erlaubt: 1..{len(reports)}")

    gt_sizes = {r.gt_size for r in reports}
    if len(gt_sizes) != 1:
        raise SystemExit(f"Inkonsistente Ground-Truth-Größen: {sorted(gt_sizes)}")
    gt_size = gt_sizes.pop()

    base_eco_sizes = reports[0].gt_size_by_ecosystem
    for idx, report in enumerate(reports[1:], start=2):
        if report.gt_size_by_ecosystem != base_eco_sizes:
            raise SystemExit(
                f"Inkonsistente Per-Ecosystem-Statistiken zwischen Report 1 und Report {idx}."
            )

    support_counter: Counter[VulnKey] = Counter()
    tools_by_vuln: Dict[VulnKey, List[str]] = defaultdict(list)

    for report in reports:
        for vuln in report.true_positives:
            support_counter[vuln] += 1
            tools_by_vuln[vuln].append(report.tool)

    vote_hist = Counter(support_counter.values())
    accepted = {v for v, c in support_counter.items() if c >= threshold}

    accepted_by_eco: Dict[str, int] = Counter(v.ecosystem for v in accepted)
    rejected_by_eco = {
        eco: base_eco_sizes[eco] - accepted_by_eco.get(eco, 0)
        for eco in sorted(base_eco_sizes)
    }

    timestamp = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    lines: List[str] = []
    lines.append("Voting-Auswertung auf Basis der Evaluationsergebnisse")
    lines.append("=" * 90)
    lines.append(f"Erstellt am               : {timestamp}")
    lines.append(f"Voting-Schwelle           : {threshold}/{len(reports)}")
    lines.append(f"Ground-Truth-Größe        : {gt_size}")
    lines.append("")

    lines.append("Verarbeitete Dateien")
    lines.append("-" * 90)
    input_rows = [
        [r.tool, r.report_timestamp, str(r.path), len(r.true_positives), percent(r.recall), percent(r.overlap)]
        for r in sorted(reports, key=lambda x: x.tool)
    ]
    lines.append(
        render_table(
            ["Tool", "Report-Datum", "Datei", "TP-Einträge", "Recall", "Overlap"],
            input_rows,
        )
    )
    lines.append("")

    accepted_count = len(accepted)
    rejected_count = gt_size - accepted_count
    overall_rows = [
        ["GT-Größe", gt_size],
        [f"Anerkannte Treffer (>= {threshold} Stimmen)", accepted_count],
        ["Nicht anerkannt", rejected_count],
        ["Recall des Votings vs. GT", percent(accepted_count / gt_size if gt_size else 0.0)],
        ["Precision/Overlap des Votings", "1.000 (konstruktiv aus TP-Listen)"],
    ]
    lines.append("Gesamtkennzahlen des Votings")
    lines.append("-" * 90)
    lines.append(render_table(["Kennzahl", "Wert"], overall_rows))
    lines.append("")

    vote_rows = [[f"{k}/{len(reports)}", vote_hist.get(k, 0)] for k in range(1, len(reports) + 1)]
    lines.append("Verteilung der Stimmen je Vulnerability")
    lines.append("-" * 90)
    lines.append(render_table(["Stimmen", "Anzahl Vulnerabilities"], vote_rows))
    lines.append("")

    eco_rows = []
    for eco in sorted(base_eco_sizes):
        gt_eco = base_eco_sizes[eco]
        acc = accepted_by_eco.get(eco, 0)
        rej = rejected_by_eco.get(eco, 0)
        eco_rows.append([eco, gt_eco, acc, rej, percent(acc / gt_eco if gt_eco else 0.0)])
    lines.append("Anerkannte Treffer pro Ecosystem")
    lines.append("-" * 90)
    lines.append(render_table(["Ecosystem", "GT", "Anerkannt", "Nicht anerkannt", "Recall"], eco_rows))
    lines.append("")

    near_miss = [
        (v, support_counter[v], sorted(tools_by_vuln[v]))
        for v in support_counter
        if threshold > 1 and support_counter[v] == threshold - 1
    ]
    near_miss = sorted(near_miss, key=lambda x: (x[0].ecosystem, x[0].component, x[0].version, x[0].cve_id, x[0].osv_id))
    if near_miss:
        lines.append(f"Beispiele knapp verfehlter Treffer ({threshold-1}/{len(reports)} Stimmen)")
        lines.append("-" * 90)
        sample_rows = []
        for vuln, votes, tools in near_miss[:20]:
            sample_rows.append([
                vuln.ecosystem,
                vuln.component,
                vuln.version,
                vuln.cve_id or "-",
                vuln.osv_id or "-",
                votes,
                ",".join(tools),
            ])
        lines.append(render_table(["Eco", "Component", "Version", "CVE", "OSV", "Votes", "Tools"], sample_rows))
        lines.append("")

    lines.append("Hinweise")
    lines.append("-" * 90)
    lines.append("* Das Voting basiert ausschließlich auf True-Positive-Einträgen der Reports.")
    lines.append("* Dadurch ist die Voting-Menge per Konstruktion eine Teilmenge der Ground Truth.")
    lines.append("* False Positives der einzelnen Tools fließen nicht in die Anerkennung ein.")
    lines.append("* Die Matching-Identität einer Vulnerability wird über "
                 "(ecosystem, component, version, cve_id, osv_id) bestimmt.")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="x/5 Voting auf Basis von Tool-Evaluationsreports")
    parser.add_argument("--files", nargs="*", help="Optional: explizite Liste der fünf Report-Dateien")
    parser.add_argument("--threshold", type=int, default=int(os.environ.get("VOTING_THRESHOLD", "3")))
    parser.add_argument("--output", default=os.environ.get("VOTING_OUTPUT_TXT", "voting_report.txt"))
    args = parser.parse_args()

    files = resolve_input_files(args)
    reports = [parse_report(p) for p in files]
    reports.sort(key=lambda r: r.tool)

    report_text = build_voting_summary(reports, args.threshold)
    output_path = Path(args.output).expanduser().resolve()
    output_path.write_text(report_text, encoding="utf-8")
    print(f"Voting-Report geschrieben: {output_path}")


if __name__ == "__main__":
    main()
