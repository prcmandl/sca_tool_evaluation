#!/usr/bin/env python3
"""
Erweitertes x/5-Voting auf Basis von fünf Evaluationstexten.

Neuerungen in dieser Fassung:
- Korrigierte 0/5-Logik für TP-Voting durch Kanonisierung von Report-Einträgen
  gegen die Ground Truth (exakt, über CVE oder über OSV/GHSA-ID, falls eindeutig).
- FP-Listen werden ausschließlich aus False Positives aufgebaut.
- 0/5-Referenzeinträge werden in allen Listen und Statistiken ergänzt.
- Zusätzliche erklärende und interpretierende Abschnitte im Hauptreport.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

TOOL_ENV_MAP = {
    "dtrack": "DTRACK_EVAL_FILE",
    "github": "GITHUB_EVAL_FILE",
    "oss-index": "OSS_INDEX_EVAL_FILE",
    "snyk": "SNYK_EVAL_FILE",
    "trivy": "TRIVY_EVAL_FILE",
}
TOOL_ORDER = ["dtrack", "github", "oss-index", "snyk", "trivy"]


@dataclass(frozen=True)
class VulnKey:
    ecosystem: str
    component: str
    version: str
    cve_id: str
    osv_id: str


@dataclass(frozen=True)
class FPKey:
    ecosystem: str
    component: str
    version: str


@dataclass(frozen=True)
class ComponentKey:
    ecosystem: str
    component: str


@dataclass
class ReportData:
    tool: str
    report_timestamp: str
    path: Path
    gt_size: int
    gt_size_by_ecosystem: Dict[str, int]
    tp_total: int
    fp_total: int
    recall: float
    overlap: float
    true_positives: set[VulnKey]
    false_positives: set[VulnKey]
    false_positive_candidates: set[FPKey]
    tp_details: Dict[VulnKey, Dict[str, str]]
    fp_details: Dict[VulnKey, Dict[str, str]]
    tp_unmatched_after_gt_map: int = 0
    fp_unmatched_after_gt_map: int = 0


@dataclass
class GroundTruthData:
    path: Path
    vulnerabilities: set[VulnKey]
    component_versions: set[FPKey]
    components: set[ComponentKey]
    descriptions_by_vuln: Dict[VulnKey, str]
    ids_by_component_version: Dict[FPKey, set[str]]
    ids_by_component: Dict[ComponentKey, set[str]]
    versions_by_component: Dict[ComponentKey, set[str]]
    counts_by_ecosystem: Dict[str, int]


@dataclass
class GTIndex:
    exact: Dict[VulnKey, VulnKey]
    by_cve: Dict[Tuple[str, str, str, str], set[VulnKey]]
    by_osv: Dict[Tuple[str, str, str, str], set[VulnKey]]


@dataclass
class TPSummary:
    gt_size: int
    accepted_count: int
    rejected_count: int
    vote_hist: Counter[int]
    accepted_by_eco: Dict[str, int]
    unmatched_tp_by_tool: Dict[str, int]


@dataclass
class FPSummary:
    exact_total: int
    exact_accepted: int
    exact_vote_hist: Counter[int]
    exact_total_by_eco: Dict[str, int]
    exact_accepted_by_eco: Dict[str, int]
    component_total: int
    component_accepted: int
    component_vote_hist: Counter[int]
    component_total_by_eco: Dict[str, int]
    component_accepted_by_eco: Dict[str, int]
    aggregated_total: int
    aggregated_accepted: int
    aggregated_vote_hist: Counter[int]
    aggregated_total_by_eco: Dict[str, int]
    aggregated_accepted_by_eco: Dict[str, int]
    unmatched_fp_by_tool: Dict[str, int]


def normalize_cell(value: str) -> str:
    v = (value or "").strip()
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
        if "|" not in raw_line:
            continue
        parts = [p.strip() for p in raw_line.split("|")]
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


def parse_tabular_vuln_section_details(text: str, section_name: str) -> Dict[VulnKey, Dict[str, str]]:
    m = re.search(
        rf"{re.escape(section_name)}\s*\(\d+\)\s*\n=+\n.*?\n[-]+\n(.*?)(?:\n\n[A-Z][^\n]*\n[=-]+|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not m:
        raise ValueError(f"Abschnitt nicht gefunden: {section_name}")
    block = m.group(1)

    entries: Dict[VulnKey, Dict[str, str]] = {}
    for raw_line in block.splitlines():
        line = raw_line.rstrip()
        if "|" not in line or re.match(r"^-{5,}$", line.strip()):
            continue

        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            continue

        eco = normalize_cell(parts[0])
        component = normalize_cell(parts[1]) if len(parts) > 1 else ""
        version = normalize_cell(parts[2]) if len(parts) > 2 else ""
        cve_id = normalize_cell(parts[3]) if len(parts) > 3 else ""
        osv_id = normalize_cell(parts[4]) if len(parts) > 4 else ""
        classification = normalize_cell(parts[5]) if len(parts) > 5 else ""
        description = normalize_cell(" | ".join(parts[6:])) if len(parts) > 6 else ""

        if eco.lower() == "ecosystem" or not eco or not component or not version:
            continue

        key = VulnKey(eco, component, version, cve_id, osv_id)
        current = entries.get(key, {})
        if not current:
            entries[key] = {"classification": classification, "description": description}
        else:
            if description and not current.get("description"):
                current["description"] = description
            if classification and not current.get("classification"):
                current["classification"] = classification
            entries[key] = current

    return entries


def parse_true_positives(text: str) -> Dict[VulnKey, Dict[str, str]]:
    entries = parse_tabular_vuln_section_details(text, "True Positives (TP = TP_EXACT + TP_RANGE)")
    if not entries:
        raise ValueError("Keine True-Positive-Einträge gefunden.")
    return entries


def parse_false_positives(text: str) -> Dict[VulnKey, Dict[str, str]]:
    entries = parse_tabular_vuln_section_details(text, "False Positives")
    if not entries:
        raise ValueError("Keine False-Positive-Einträge gefunden.")
    return entries


def parse_report(path: Path) -> ReportData:
    text = path.read_text(encoding="utf-8", errors="replace")
    tool, ts = parse_header(text)

    tp_details = parse_true_positives(text)
    fp_details = parse_false_positives(text)

    tp_entries = set(tp_details.keys())
    fp_entries = set(fp_details.keys())
    fp_candidates = {FPKey(v.ecosystem, v.component, v.version) for v in fp_entries}

    return ReportData(
        tool=tool,
        report_timestamp=ts,
        path=path,
        gt_size=parse_int(text, "Vulnerabilities in Ground Truth"),
        gt_size_by_ecosystem=parse_per_ecosystem_gt_sizes(text),
        tp_total=parse_int(text, "True Positives (TP_TOTAL)"),
        fp_total=parse_int(text, "False Positives (FP)"),
        recall=parse_float(text, "Recall @ GT (TP_EXACT+TP_RANGE)"),
        overlap=parse_float(text, "Overlap Rate"),
        true_positives=tp_entries,
        false_positives=fp_entries,
        false_positive_candidates=fp_candidates,
        tp_details=tp_details,
        fp_details=fp_details,
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
        raise SystemExit(f"Es werden genau 5 Evaluationsdateien benötigt, gefunden: {len(unique_paths)}.")

    missing = [str(p) for p in unique_paths if not p.exists()]
    if missing:
        raise SystemExit("Folgende Dateien fehlen:\n" + "\n".join(missing))

    return unique_paths


def resolve_gt_csv_path(args: argparse.Namespace) -> Path:
    candidates: List[Path] = []
    if args.ground_truth_csv:
        candidates.append(Path(args.ground_truth_csv).expanduser())

    env_gt = os.environ.get("GROUND_TRUTH_CSV", "").strip()
    if env_gt:
        candidates.append(Path(env_gt).expanduser())

    exp_path = os.environ.get("EXPERIMENT_PATH", "").strip()
    if exp_path:
        candidates.append(
            Path(exp_path).expanduser() / "ground_truth_build" / "run_1" / "attempt_1" / "gt0" / "ground_truth_gt0.csv"
        )

    for p in candidates:
        rp = p.resolve()
        if rp.exists():
            return rp

    tried = "\n".join(str(p) for p in candidates) if candidates else "(keine Kandidatenpfade vorhanden)"
    raise SystemExit(
        "Ground-Truth-CSV konnte nicht gefunden werden. "
        "Bitte --ground-truth-csv setzen oder EXPERIMENT_PATH/GROUND_TRUTH_CSV korrekt definieren.\n"
        f"Geprüfte Pfade:\n{tried}"
    )


def vuln_id(v: VulnKey) -> str:
    return v.cve_id or v.osv_id or "-"


def vuln_id_type(v: VulnKey) -> str:
    if v.cve_id:
        return "CVE"
    if v.osv_id:
        return "OSV"
    return "-"


def build_gt_index(gt: GroundTruthData) -> GTIndex:
    exact: Dict[VulnKey, VulnKey] = {}
    by_cve: Dict[Tuple[str, str, str, str], set[VulnKey]] = defaultdict(set)
    by_osv: Dict[Tuple[str, str, str, str], set[VulnKey]] = defaultdict(set)
    for v in gt.vulnerabilities:
        exact[v] = v
        if v.cve_id:
            by_cve[(v.ecosystem, v.component, v.version, v.cve_id)].add(v)
        if v.osv_id:
            by_osv[(v.ecosystem, v.component, v.version, v.osv_id)].add(v)
    return GTIndex(exact=exact, by_cve=dict(by_cve), by_osv=dict(by_osv))


def load_ground_truth_csv(path: Path) -> GroundTruthData:
    vulnerabilities: set[VulnKey] = set()
    component_versions: set[FPKey] = set()
    components: set[ComponentKey] = set()
    descriptions_by_vuln: Dict[VulnKey, str] = {}
    ids_by_component_version: Dict[FPKey, set[str]] = defaultdict(set)
    ids_by_component: Dict[ComponentKey, set[str]] = defaultdict(set)
    versions_by_component: Dict[ComponentKey, set[str]] = defaultdict(set)
    counts_by_ecosystem: Dict[str, int] = Counter()

    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        required = {"ecosystem", "component_name", "component_version", "vulnerability_id", "cve", "vulnerability_description"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"Ground-Truth-CSV fehlt Pflichtspalten: {sorted(missing)}")

        for row in reader:
            eco = normalize_cell(row.get("ecosystem", ""))
            component = normalize_cell(row.get("component_name", ""))
            version = normalize_cell(row.get("component_version", ""))
            osv_id = normalize_cell(row.get("vulnerability_id", ""))
            cve_id = normalize_cell(row.get("cve", ""))
            description = normalize_cell(row.get("vulnerability_description", ""))
            is_vulnerable = normalize_cell(row.get("is_vulnerable", "True")).lower()

            if is_vulnerable not in {"", "true", "1", "yes"}:
                continue
            if not eco or not component or not version:
                continue

            v = VulnKey(eco, component, version, cve_id, osv_id)
            cv = FPKey(eco, component, version)
            comp = ComponentKey(eco, component)
            vulnerabilities.add(v)
            component_versions.add(cv)
            components.add(comp)
            counts_by_ecosystem[eco] += 1
            if description:
                descriptions_by_vuln.setdefault(v, description)
            ids_by_component_version[cv].add(vuln_id(v))
            ids_by_component[comp].add(vuln_id(v))
            versions_by_component[comp].add(version)

    if not vulnerabilities:
        raise SystemExit(f"Ground-Truth-CSV enthält keine verwertbaren Einträge: {path}")

    return GroundTruthData(
        path=path,
        vulnerabilities=vulnerabilities,
        component_versions=component_versions,
        components=components,
        descriptions_by_vuln=descriptions_by_vuln,
        ids_by_component_version=ids_by_component_version,
        ids_by_component=ids_by_component,
        versions_by_component=versions_by_component,
        counts_by_ecosystem=dict(counts_by_ecosystem),
    )


def map_key_to_gt_if_possible(v: VulnKey, gt_index: GTIndex) -> VulnKey | None:
    if v in gt_index.exact:
        return gt_index.exact[v]

    candidates: set[VulnKey] = set()
    if v.cve_id:
        candidates.update(gt_index.by_cve.get((v.ecosystem, v.component, v.version, v.cve_id), set()))
    if v.osv_id:
        candidates.update(gt_index.by_osv.get((v.ecosystem, v.component, v.version, v.osv_id), set()))

    if len(candidates) == 1:
        return next(iter(candidates))
    return None


def merge_detail(dst: Dict[str, str], src: Dict[str, str]) -> Dict[str, str]:
    out = dict(dst)
    for key in ("classification", "description"):
        if not out.get(key) and src.get(key):
            out[key] = src[key]
    return out


def canonicalize_report_entries_against_gt(reports: List[ReportData], gt: GroundTruthData) -> None:
    gt_index = build_gt_index(gt)
    for report in reports:
        # TP: only GT entries should count in voting; map where possible, otherwise keep only for diagnostics
        new_tp_details: Dict[VulnKey, Dict[str, str]] = {}
        tp_unmatched = 0
        for k, details in report.tp_details.items():
            mapped = map_key_to_gt_if_possible(k, gt_index)
            if mapped is None:
                tp_unmatched += 1
                continue
            new_tp_details[mapped] = merge_detail(new_tp_details.get(mapped, {}), details)
        report.tp_details = new_tp_details
        report.true_positives = set(new_tp_details.keys())
        report.tp_unmatched_after_gt_map = tp_unmatched

        # FP: map to GT key when possible to avoid duplicate identity forms; otherwise keep observed key
        new_fp_details: Dict[VulnKey, Dict[str, str]] = {}
        fp_unmatched = 0
        for k, details in report.fp_details.items():
            mapped = map_key_to_gt_if_possible(k, gt_index)
            target = mapped if mapped is not None else k
            if mapped is None:
                fp_unmatched += 1
            new_fp_details[target] = merge_detail(new_fp_details.get(target, {}), details)
        report.fp_details = new_fp_details
        report.false_positives = set(new_fp_details.keys())
        report.false_positive_candidates = {FPKey(v.ecosystem, v.component, v.version) for v in report.false_positives}
        report.fp_unmatched_after_gt_map = fp_unmatched


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


def yesno(flag: bool) -> str:
    return "YES" if flag else "NO"


def pick_description(descriptions: Iterable[str]) -> str:
    cleaned = sorted(d for d in descriptions if d and d.strip())
    return cleaned[0] if cleaned else "-"


def join_limited(values: Iterable[str], limit: int = 8) -> str:
    cleaned = sorted(v for v in values if v and v.strip())
    if not cleaned:
        return "-"
    if len(cleaned) <= limit:
        return "; ".join(cleaned)
    head = "; ".join(cleaned[:limit])
    return f"{head}; ... (+{len(cleaned) - limit} weitere)"


def vote_hist_rows(hist: Counter[int], max_votes: int) -> List[List[object]]:
    return [[f"{k}/{max_votes}", hist.get(k, 0)] for k in range(0, max_votes + 1)]


def build_tp_sections(reports: List[ReportData], threshold: int, gt: GroundTruthData) -> Tuple[List[str], str, TPSummary]:
    gt_sizes = {r.gt_size for r in reports}
    if len(gt_sizes) != 1:
        raise SystemExit(f"Inkonstistente Ground-Truth-Größen: {sorted(gt_sizes)}")
    gt_size = gt_sizes.pop()
    if gt_size != len(gt.vulnerabilities):
        raise SystemExit(f"Ground-Truth-Größe aus Reports ({gt_size}) passt nicht zur CSV ({len(gt.vulnerabilities)}).")

    support_counter: Counter[VulnKey] = Counter({v: 0 for v in gt.vulnerabilities})
    tools_by_vuln: Dict[VulnKey, set[str]] = defaultdict(set)
    descriptions_by_vuln: Dict[VulnKey, set[str]] = defaultdict(set)
    unmatched_tp_by_tool: Dict[str, int] = {}

    for v, desc in gt.descriptions_by_vuln.items():
        if desc:
            descriptions_by_vuln[v].add(desc)

    for report in reports:
        unmatched_tp_by_tool[report.tool] = report.tp_unmatched_after_gt_map
        for vuln in report.true_positives:
            # After canonicalization every TP should be inside GT. Guard anyway.
            if vuln not in support_counter:
                continue
            support_counter[vuln] += 1
            tools_by_vuln[vuln].add(report.tool)
            desc = report.tp_details.get(vuln, {}).get("description", "")
            if desc:
                descriptions_by_vuln[vuln].add(desc)

    vote_hist = Counter(support_counter.values())
    accepted = {v for v, c in support_counter.items() if c >= threshold}
    accepted_by_eco: Dict[str, int] = Counter(v.ecosystem for v in accepted)

    lines: List[str] = []
    lines.append("TP-Voting")
    lines.append("-" * 90)

    accepted_count = len(accepted)
    rejected_count = gt_size - accepted_count
    overall_rows = [
        ["GT-Größe", gt_size],
        [f"Anerkannte Treffer (>= {threshold} Stimmen)", accepted_count],
        ["Nicht anerkannt", rejected_count],
        ["Recall des Votings vs. GT", percent(accepted_count / gt_size if gt_size else 0.0)],
        ["Precision/Overlap des Votings", "1.000 (konstruktiv aus TP-Listen)"],
    ]
    lines.append(render_table(["Kennzahl", "Wert"], overall_rows))
    lines.append("")

    lines.append("Verteilung der Stimmen je TP-Vulnerability (inkl. 0/5)")
    lines.append("-" * 90)
    lines.append(render_table(["Stimmen", "Anzahl Vulnerabilities"], vote_hist_rows(vote_hist, len(reports))))
    lines.append("")

    eco_rows = []
    for eco in sorted(gt.counts_by_ecosystem):
        gt_eco = gt.counts_by_ecosystem[eco]
        acc = accepted_by_eco.get(eco, 0)
        rej = gt_eco - acc
        eco_rows.append([eco, gt_eco, acc, rej, percent(acc / gt_eco if gt_eco else 0.0)])
    lines.append("Anerkannte TP-Treffer pro Ecosystem")
    lines.append("-" * 90)
    lines.append(render_table(["Ecosystem", "GT", "Anerkannt", "Nicht anerkannt", "Recall"], eco_rows))
    lines.append("")

    if any(unmatched_tp_by_tool.values()):
        lines.append("Nicht auf Ground-Truth-Einträge abbildbare TP-Kandidaten (informativ, nicht gezählt)")
        lines.append("-" * 90)
        rows = [[tool, unmatched_tp_by_tool.get(tool, 0)] for tool in TOOL_ORDER]
        lines.append(render_table(["Tool", "Unmatched TP entries"], rows))
        lines.append("")

    tp_rows = []
    for idx, (v, votes) in enumerate(
        sorted(support_counter.items(), key=lambda item: (-item[1], item[0].ecosystem, item[0].component, item[0].version, vuln_id(item[0]))),
        start=1,
    ):
        tool_flags = {tool: (tool in tools_by_vuln[v]) for tool in TOOL_ORDER}
        tp_rows.append([
            idx, v.ecosystem, v.component, v.version,
            pick_description(descriptions_by_vuln.get(v, set())), vuln_id(v), vuln_id_type(v),
            yesno(tool_flags["dtrack"]), yesno(tool_flags["github"]), yesno(tool_flags["oss-index"]),
            yesno(tool_flags["snyk"]), yesno(tool_flags["trivy"]), votes,
            "Anerkannt" if votes >= threshold else "Nicht anerkannt",
        ])

    tp_headers = ["Nr", "Eco", "Component", "Version", "Vulnerability", "Vuln-ID", "ID-Type", "dtrack", "github", "oss-index", "snyk", "trivy", "Votes", "Gesamtbewertung"]
    tp_list_text = []
    tp_list_text.append("Liste aller TP-Vulnerabilities (eine Zeile pro Component + Vulnerability + Vuln-ID; inkl. 0/5 aus GT)")
    tp_list_text.append("=" * 220)
    tp_list_text.append(f"Erstellt am        : {dt.datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}")
    tp_list_text.append(f"Voting-Schwelle    : {threshold}/{len(reports)}")
    tp_list_text.append(f"Ground-Truth-CSV   : {gt.path}")
    tp_list_text.append("")
    tp_list_text.append(render_table(tp_headers, tp_rows))
    tp_list_text.append("")

    summary = TPSummary(
        gt_size=gt_size,
        accepted_count=accepted_count,
        rejected_count=rejected_count,
        vote_hist=vote_hist,
        accepted_by_eco=dict(accepted_by_eco),
        unmatched_tp_by_tool=unmatched_tp_by_tool,
    )
    return lines, "\n".join(tp_list_text), summary


def build_fp_sections(reports: List[ReportData], threshold: int, gt: GroundTruthData) -> Tuple[List[str], str, str, str, FPSummary]:
    # For FP voting, the universe consists only of *observed* false positives.
    # Ground-truth entries are used only for InGT marking, not as 0/5 reference entries.
    exact_support: Counter[VulnKey] = Counter()
    component_support: Counter[FPKey] = Counter()
    aggregated_component_support: Counter[ComponentKey] = Counter()

    tools_by_vuln: Dict[VulnKey, set[str]] = defaultdict(set)
    tools_by_component: Dict[FPKey, set[str]] = defaultdict(set)
    tools_by_aggregated_component: Dict[ComponentKey, set[str]] = defaultdict(set)
    descriptions_by_vuln: Dict[VulnKey, set[str]] = defaultdict(set)
    ids_by_component: Dict[FPKey, set[str]] = defaultdict(set)
    descriptions_by_component: Dict[FPKey, set[str]] = defaultdict(set)
    exact_accepted_count_by_component: Dict[FPKey, int] = defaultdict(int)
    versions_by_aggregated_component: Dict[ComponentKey, set[str]] = defaultdict(set)
    ids_by_aggregated_component: Dict[ComponentKey, set[str]] = defaultdict(set)
    descriptions_by_aggregated_component: Dict[ComponentKey, set[str]] = defaultdict(set)
    accepted_exact_count_by_aggregated_component: Dict[ComponentKey, int] = defaultdict(int)
    accepted_cv_count_by_aggregated_component: Dict[ComponentKey, int] = defaultdict(int)
    unmatched_fp_by_tool: Dict[str, int] = {}

    for v, desc in gt.descriptions_by_vuln.items():
        if desc:
            descriptions_by_vuln[v].add(desc)
        cv = FPKey(v.ecosystem, v.component, v.version)
        comp = ComponentKey(v.ecosystem, v.component)
        ids_by_component[cv].add(vuln_id(v))
        ids_by_aggregated_component[comp].add(vuln_id(v))
        versions_by_aggregated_component[comp].add(v.version)

    for report in reports:
        unmatched_fp_by_tool[report.tool] = report.fp_unmatched_after_gt_map
        aggregated_seen_in_report: set[ComponentKey] = set()
        component_seen_in_report: set[FPKey] = set()
        for fp in report.false_positives:
            exact_support[fp] += 1
            tools_by_vuln[fp].add(report.tool)
            fp_key = FPKey(fp.ecosystem, fp.component, fp.version)
            agg_key = ComponentKey(fp.ecosystem, fp.component)
            component_seen_in_report.add(fp_key)
            aggregated_seen_in_report.add(agg_key)
            desc = report.fp_details.get(fp, {}).get("description", "")
            if desc:
                descriptions_by_vuln[fp].add(desc)
                descriptions_by_component[fp_key].add(desc)
                descriptions_by_aggregated_component[agg_key].add(desc)
            ids_by_component[fp_key].add(vuln_id(fp))
            ids_by_aggregated_component[agg_key].add(vuln_id(fp))
            versions_by_aggregated_component[agg_key].add(fp.version)

        for fp_key in component_seen_in_report:
            component_support[fp_key] += 1
            tools_by_component[fp_key].add(report.tool)
        for agg_key in aggregated_seen_in_report:
            aggregated_component_support[agg_key] += 1
            tools_by_aggregated_component[agg_key].add(report.tool)

    exact_vote_hist = Counter(exact_support.values())
    exact_accepted = {v for v, c in exact_support.items() if c >= threshold}
    exact_total_by_eco: Dict[str, int] = Counter(v.ecosystem for v in exact_support)
    exact_accepted_by_eco: Dict[str, int] = Counter(v.ecosystem for v in exact_accepted)

    for v in exact_accepted:
        exact_accepted_count_by_component[FPKey(v.ecosystem, v.component, v.version)] += 1
        accepted_exact_count_by_aggregated_component[ComponentKey(v.ecosystem, v.component)] += 1

    component_vote_hist = Counter(component_support.values())
    component_accepted = {fp for fp, c in component_support.items() if c >= threshold}
    component_total_by_eco: Dict[str, int] = Counter(fp.ecosystem for fp in component_support)
    component_accepted_by_eco: Dict[str, int] = Counter(fp.ecosystem for fp in component_accepted)

    for fp_key in component_accepted:
        accepted_cv_count_by_aggregated_component[ComponentKey(fp_key.ecosystem, fp_key.component)] += 1

    aggregated_vote_hist = Counter(aggregated_component_support.values())
    aggregated_accepted = {k for k, c in aggregated_component_support.items() if c >= threshold}
    aggregated_total_by_eco: Dict[str, int] = Counter(k.ecosystem for k in aggregated_component_support)
    aggregated_accepted_by_eco: Dict[str, int] = Counter(k.ecosystem for k in aggregated_accepted)

    lines: List[str] = []
    lines.append("FP-Voting auf Vulnerability-Ebene")
    lines.append("-" * 90)
    rows = [
        ["Beobachtete FP-Vulnerabilities", len(exact_support)],
        [f"Anerkannte FP-Vulnerabilities (>= {threshold} Stimmen)", len(exact_accepted)],
        ["Nicht anerkannt", len(exact_support) - len(exact_accepted)],
        ["Anteil anerkannter FP-Vulnerabilities", percent(len(exact_accepted) / len(exact_support) if exact_support else 0.0)],
        ["Voting-Ebene", "exact vulnerability"],
    ]
    lines.append(render_table(["Kennzahl", "Wert"], rows))
    lines.append("")
    lines.append("Verteilung der Stimmen je FP-Vulnerability")
    lines.append("-" * 90)
    lines.append(render_table(["Stimmen", "Anzahl FP-Vulnerabilities"], vote_hist_rows(exact_vote_hist, len(reports))))
    lines.append("")
    eco_rows = []
    for eco in sorted(exact_total_by_eco):
        total = exact_total_by_eco[eco]
        acc = exact_accepted_by_eco.get(eco, 0)
        eco_rows.append([eco, total, acc, total - acc, percent(acc / total if total else 0.0)])
    lines.append("Anerkannte FP-Vulnerabilities pro Ecosystem")
    lines.append("-" * 90)
    lines.append(render_table(["Ecosystem", "FP-Vulns", "Anerkannt", "Nicht anerkannt", "Quote"], eco_rows))
    lines.append("")

    lines.append("FP-Voting auf Component-Version-Ebene")
    lines.append("-" * 90)
    rows = [
        ["Beobachtete FP-Component-Versionen", len(component_support)],
        [f"Anerkannte FP-Component-Versionen (>= {threshold} Stimmen)", len(component_accepted)],
        ["Nicht anerkannt", len(component_support) - len(component_accepted)],
        ["Anteil anerkannter FP-Component-Versionen", percent(len(component_accepted) / len(component_support) if component_support else 0.0)],
        ["Voting-Ebene", "component-version"],
    ]
    lines.append(render_table(["Kennzahl", "Wert"], rows))
    lines.append("")
    lines.append("Verteilung der Stimmen je FP-Component-Version")
    lines.append("-" * 90)
    lines.append(render_table(["Stimmen", "Anzahl FP-Component-Versionen"], vote_hist_rows(component_vote_hist, len(reports))))
    lines.append("")
    eco_rows = []
    for eco in sorted(component_total_by_eco):
        total = component_total_by_eco[eco]
        acc = component_accepted_by_eco.get(eco, 0)
        eco_rows.append([eco, total, acc, total - acc, percent(acc / total if total else 0.0)])
    lines.append("Anerkannte FP-Component-Versionen pro Ecosystem")
    lines.append("-" * 90)
    lines.append(render_table(["Ecosystem", "FP-Component-Versionen", "Anerkannt", "Nicht anerkannt", "Quote"], eco_rows))
    lines.append("")

    lines.append("FP-Voting auf Komponenten-Ebene (alle Versionen zusammengefasst)")
    lines.append("-" * 90)
    rows = [
        ["Beobachtete FP-Komponenten", len(aggregated_component_support)],
        [f"Anerkannte FP-Komponenten (>= {threshold} Stimmen)", len(aggregated_accepted)],
        ["Nicht anerkannt", len(aggregated_component_support) - len(aggregated_accepted)],
        ["Anteil anerkannter FP-Komponenten", percent(len(aggregated_accepted) / len(aggregated_component_support) if aggregated_component_support else 0.0)],
        ["Voting-Ebene", "component across all versions"],
    ]
    lines.append(render_table(["Kennzahl", "Wert"], rows))
    lines.append("")
    lines.append("Verteilung der Stimmen je FP-Komponente")
    lines.append("-" * 90)
    lines.append(render_table(["Stimmen", "Anzahl FP-Komponenten"], vote_hist_rows(aggregated_vote_hist, len(reports))))
    lines.append("")
    eco_rows = []
    for eco in sorted(aggregated_total_by_eco):
        total = aggregated_total_by_eco[eco]
        acc = aggregated_accepted_by_eco.get(eco, 0)
        eco_rows.append([eco, total, acc, total - acc, percent(acc / total if total else 0.0)])
    lines.append("Anerkannte FP-Komponenten pro Ecosystem")
    lines.append("-" * 90)
    lines.append(render_table(["Ecosystem", "FP-Komponenten", "Anerkannt", "Nicht anerkannt", "Quote"], eco_rows))
    lines.append("")

    if any(unmatched_fp_by_tool.values()):
        lines.append("Nicht auf Ground-Truth-Einträge abbildbare FP-Kandidaten (informativ, weiterhin als beobachtete FPs gezählt)")
        lines.append("-" * 90)
        rows = [[tool, unmatched_fp_by_tool.get(tool, 0)] for tool in TOOL_ORDER]
        lines.append(render_table(["Tool", "Unmatched FP entries"], rows))
        lines.append("")

    # detail lists
    fp_vuln_rows = []
    for idx, (v, exact_votes) in enumerate(sorted(exact_support.items(), key=lambda item: (-item[1], item[0].ecosystem, item[0].component, item[0].version, vuln_id(item[0]))), start=1):
        fp_key = FPKey(v.ecosystem, v.component, v.version)
        component_votes = component_support[fp_key]
        tool_flags = {tool: (tool in tools_by_vuln[v]) for tool in TOOL_ORDER}
        fp_vuln_rows.append([
            idx, yesno(v in gt.vulnerabilities), v.ecosystem, v.component, v.version,
            pick_description(descriptions_by_vuln.get(v, set())), vuln_id(v), vuln_id_type(v),
            yesno(tool_flags["dtrack"]), yesno(tool_flags["github"]), yesno(tool_flags["oss-index"]),
            yesno(tool_flags["snyk"]), yesno(tool_flags["trivy"]), exact_votes, component_votes,
            "Anerkannt" if exact_votes >= threshold else "Nicht anerkannt",
        ])

    fp_vuln_headers = ["Nr", "InGT", "Eco", "Component", "Version", "Vulnerability", "Vuln-ID", "ID-Type", "dtrack", "github", "oss-index", "snyk", "trivy", "Votes", "CVVotes", "Gesamtbewertung"]
    fp_vuln_list_text = []
    fp_vuln_list_text.append("Liste aller FP-Vulnerabilities (FP-Votes stammen ausschließlich aus False Positives)")
    fp_vuln_list_text.append("=" * 250)
    fp_vuln_list_text.append(f"Erstellt am        : {dt.datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}")
    fp_vuln_list_text.append(f"Voting-Schwelle    : {threshold}/{len(reports)}")
    fp_vuln_list_text.append(f"Ground-Truth-CSV   : {gt.path}")
    fp_vuln_list_text.append("Hinweis            : Gesamtbewertung basiert auf exakten FP-Votes; CVVotes zeigt zusätzlich die Stimmen auf Component-Version-Ebene. InGT=YES bedeutet: exakte Vulnerability ist in der Ground Truth vorhanden.")
    fp_vuln_list_text.append("")
    fp_vuln_list_text.append(render_table(fp_vuln_headers, fp_vuln_rows))
    fp_vuln_list_text.append("")

    fp_component_rows = []
    for idx, (fp_key, component_votes) in enumerate(sorted(component_support.items(), key=lambda item: (-item[1], item[0].ecosystem, item[0].component, item[0].version)), start=1):
        tool_flags = {tool: (tool in tools_by_component[fp_key]) for tool in TOOL_ORDER}
        in_gt = fp_key in gt.component_versions
        fp_component_rows.append([
            idx, yesno(in_gt), fp_key.ecosystem, fp_key.component, fp_key.version,
            join_limited(ids_by_component.get(fp_key, set()), limit=10), len(ids_by_component.get(fp_key, set())),
            exact_accepted_count_by_component.get(fp_key, 0), yesno(tool_flags["dtrack"]), yesno(tool_flags["github"]),
            yesno(tool_flags["oss-index"]), yesno(tool_flags["snyk"]), yesno(tool_flags["trivy"]),
            component_votes, "Anerkannt" if component_votes >= threshold else "Nicht anerkannt",
            join_limited(descriptions_by_component.get(fp_key, set()), limit=3),
        ])

    fp_component_headers = ["Nr", "InGT", "Eco", "Component", "Version", "Vuln-IDs", "VulnCount", "AcceptedVulns", "dtrack", "github", "oss-index", "snyk", "trivy", "Votes", "Gesamtbewertung", "Beispiele"]
    fp_component_list_text = []
    fp_component_list_text.append("Liste aller FP-Component-Version-Kandidaten")
    fp_component_list_text.append("=" * 250)
    fp_component_list_text.append(f"Erstellt am        : {dt.datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}")
    fp_component_list_text.append(f"Voting-Schwelle    : {threshold}/{len(reports)}")
    fp_component_list_text.append(f"Ground-Truth-CSV   : {gt.path}")
    fp_component_list_text.append("Hinweis            : Eine Zeile pro Component-Version. InGT=YES bedeutet: diese Component-Version kommt in der Ground Truth vor. Votes stammen ausschließlich aus False Positives.")
    fp_component_list_text.append("")
    fp_component_list_text.append(render_table(fp_component_headers, fp_component_rows))
    fp_component_list_text.append("")

    fp_agg_rows = []
    for idx, (agg_key, votes) in enumerate(sorted(aggregated_component_support.items(), key=lambda item: (-item[1], item[0].ecosystem, item[0].component)), start=1):
        tool_flags = {tool: (tool in tools_by_aggregated_component[agg_key]) for tool in TOOL_ORDER}
        in_gt = agg_key in gt.components
        fp_agg_rows.append([
            idx, yesno(in_gt), agg_key.ecosystem, agg_key.component,
            join_limited(versions_by_aggregated_component.get(agg_key, set()), limit=12), len(versions_by_aggregated_component.get(agg_key, set())),
            join_limited(ids_by_aggregated_component.get(agg_key, set()), limit=12), len(ids_by_aggregated_component.get(agg_key, set())),
            accepted_exact_count_by_aggregated_component.get(agg_key, 0), accepted_cv_count_by_aggregated_component.get(agg_key, 0),
            yesno(tool_flags["dtrack"]), yesno(tool_flags["github"]), yesno(tool_flags["oss-index"]), yesno(tool_flags["snyk"]), yesno(tool_flags["trivy"]),
            votes, "Anerkannt" if votes >= threshold else "Nicht anerkannt", join_limited(descriptions_by_aggregated_component.get(agg_key, set()), limit=3),
        ])

    fp_agg_headers = ["Nr", "InGT", "Eco", "Component", "Versionen", "VersionCount", "Vuln-IDs", "VulnCount", "AcceptedVulns", "AcceptedCVs", "dtrack", "github", "oss-index", "snyk", "trivy", "Votes", "Gesamtbewertung", "Beispiele"]
    fp_aggregated_component_list_text = []
    fp_aggregated_component_list_text.append("Liste aller FP-Komponenten (alle Versionen und alle Vulnerabilities einer Komponente in einem Eintrag)")
    fp_aggregated_component_list_text.append("=" * 280)
    fp_aggregated_component_list_text.append(f"Erstellt am        : {dt.datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}")
    fp_aggregated_component_list_text.append(f"Voting-Schwelle    : {threshold}/{len(reports)}")
    fp_aggregated_component_list_text.append(f"Ground-Truth-CSV   : {gt.path}")
    fp_aggregated_component_list_text.append("Hinweis            : Eine Zeile pro Komponente (Eco+Component). InGT=YES bedeutet: die Komponente kommt in der Ground Truth vor. Votes stammen ausschließlich aus False Positives.")
    fp_aggregated_component_list_text.append("")
    fp_aggregated_component_list_text.append(render_table(fp_agg_headers, fp_agg_rows))
    fp_aggregated_component_list_text.append("")

    summary = FPSummary(
        exact_total=len(exact_support), exact_accepted=len(exact_accepted), exact_vote_hist=exact_vote_hist,
        exact_total_by_eco=dict(exact_total_by_eco), exact_accepted_by_eco=dict(exact_accepted_by_eco),
        component_total=len(component_support), component_accepted=len(component_accepted), component_vote_hist=component_vote_hist,
        component_total_by_eco=dict(component_total_by_eco), component_accepted_by_eco=dict(component_accepted_by_eco),
        aggregated_total=len(aggregated_component_support), aggregated_accepted=len(aggregated_accepted), aggregated_vote_hist=aggregated_vote_hist,
        aggregated_total_by_eco=dict(aggregated_total_by_eco), aggregated_accepted_by_eco=dict(aggregated_accepted_by_eco),
        unmatched_fp_by_tool=unmatched_fp_by_tool,
    )
    return lines, "\n".join(fp_vuln_list_text), "\n".join(fp_component_list_text), "\n".join(fp_aggregated_component_list_text), summary


def build_explanation_and_interpretation(tp: TPSummary, fp: FPSummary, threshold: int, reports: List[ReportData]) -> List[str]:
    lines: List[str] = []
    lines.append("Erläuterung der Tabellen")
    lines.append("-" * 90)
    lines.append("* 'Verarbeitete Dateien' zeigt pro Tool den eingelesenen Report sowie die darin enthaltenen TP- und FP-Mengen.")
    lines.append("* 'TP-Voting' betrachtet nur Ground-Truth-Vulnerabilities. Ein Eintrag gilt als anerkannt, wenn ihn mindestens vier der fünf Tools als TP melden.")
    lines.append("* 'FP-Voting auf Vulnerability-Ebene' betrachtet exakte Tupel aus Ecosystem, Component, Version und Vulnerability-ID.")
    lines.append("* 'FP-Voting auf Component-Version-Ebene' ignoriert die einzelne Vulnerability-ID und fragt nur, ob eine bestimmte Component-Version als FP auffällig ist.")
    lines.append("* 'FP-Voting auf Komponenten-Ebene' fasst alle Versionen und alle Vulnerabilities einer Komponente zu einem Eintrag zusammen.")
    lines.append("* '0/5' tritt nur im TP-Voting auf und bedeutet: Der Ground-Truth-Eintrag ist vorhanden, wurde aber von keinem Tool als TP gemeldet.")
    lines.append("* 'InGT' markiert in den Detail-Listen, ob die exakte Vulnerability, die Component-Version oder die Komponente in der Ground Truth vorkommt.")
    lines.append("")

    lines.append("Automatische Interpretation")
    lines.append("-" * 90)
    lines.append(
        f"* TP-Seite: Das {threshold}/5-Voting deckt {tp.accepted_count} von {tp.gt_size} Ground-Truth-Einträgen ab "
        f"({percent(tp.accepted_count / tp.gt_size if tp.gt_size else 0.0)} Recall)."
    )
    if tp.vote_hist.get(len(reports), 0) or tp.vote_hist.get(len(reports) - 1, 0):
        lines.append(
            f"* Stabiler TP-Kern: {tp.vote_hist.get(len(reports), 0)} Einträge erhalten 5/5 Stimmen und "
            f"{tp.vote_hist.get(len(reports)-1, 0)} weitere 4/5 Stimmen."
        )
    best_tp_eco = max(tp.accepted_by_eco.items(), key=lambda kv: kv[1])[0] if tp.accepted_by_eco else "-"
    lines.append(f"* Ökosysteme: Der größte absolute Block an anerkannten TP-Treffern liegt in {best_tp_eco}.")

    lines.append(
        f"* Exakte FP-Vulnerabilities: Nur {fp.exact_accepted} von {fp.exact_total} Kandidaten erreichen die Schwelle. "
        "Das spricht gegen eine starke toolübergreifende Übereinstimmung auf exakter Vulnerability-Ebene."
    )
    lines.append(
        f"* FP-Component-Versionen: {fp.component_accepted} von {fp.component_total} Component-Versionen erreichen die Schwelle. "
        "Damit zeigt sich wesentlich mehr Struktur auf Component-Version-Ebene als auf exakter Vulnerability-Ebene."
    )
    lines.append(
        f"* FP-Komponenten: {fp.aggregated_accepted} von {fp.aggregated_total} Komponenten erreichen die Schwelle. "
        "Wenn hier hohe Zustimmung entsteht, deutet das eher auf systematische Auffälligkeiten ganzer Komponentenfamilien hin."
    )
    if any(tp.unmatched_tp_by_tool.values()):
        worst_tool, worst_count = max(tp.unmatched_tp_by_tool.items(), key=lambda kv: kv[1])
        lines.append(
            f"* Datenqualität TP: Nach der GT-Kanonisierung blieben bei {worst_tool} die meisten nicht zuordenbaren TP-Einträge übrig ({worst_count}). "
            "Diese informativen Kandidaten werden nicht in das TP-Voting einbezogen."
        )
    if any(fp.unmatched_fp_by_tool.values()):
        worst_tool, worst_count = max(fp.unmatched_fp_by_tool.items(), key=lambda kv: kv[1])
        lines.append(
            f"* Datenqualität FP: Die meisten nicht direkt auf GT-Einträge abbildbaren FP-Kandidaten stammen von {worst_tool} ({worst_count}). "
            "Sie bleiben als beobachtete FPs im FP-Voting erhalten."
        )
    lines.append("")
    return lines


def build_voting_summary(reports: List[ReportData], threshold: int, gt: GroundTruthData) -> Tuple[str, str, str, str, str]:
    if threshold < 1 or threshold > len(reports):
        raise SystemExit(f"Ungültiger Threshold: {threshold}. Erlaubt: 1..{len(reports)}")

    timestamp = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    lines: List[str] = []
    lines.append("Voting-Auswertung auf Basis der Evaluationsergebnisse")
    lines.append("=" * 90)
    lines.append(f"Erstellt am               : {timestamp}")
    lines.append(f"Voting-Schwelle           : {threshold}/{len(reports)}")
    lines.append(f"Ground-Truth-CSV          : {gt.path}")
    lines.append("")

    lines.append("Verarbeitete Dateien")
    lines.append("-" * 90)
    input_rows = []
    for r in sorted(reports, key=lambda x: x.tool):
        input_rows.append([
            r.tool, r.report_timestamp, str(r.path), len(r.true_positives), len(r.false_positives),
            len(r.false_positive_candidates), r.fp_total, percent(r.recall), percent(r.overlap)
        ])
    lines.append(render_table(["Tool", "Report-Datum", "Datei", "TP-Einträge", "FP-Vulns", "FP-Component-Versionen", "FP-Roh", "Recall", "Overlap"], input_rows))
    lines.append("")

    tp_lines, tp_list_text, tp_summary = build_tp_sections(reports, threshold, gt)
    lines.extend(tp_lines)

    fp_lines, fp_vuln_list_text, fp_component_list_text, fp_aggregated_component_list_text, fp_summary = build_fp_sections(reports, threshold, gt)
    lines.extend(fp_lines)

    lines.extend(build_explanation_and_interpretation(tp_summary, fp_summary, threshold, reports))

    lines.append("Hinweise")
    lines.append("-" * 90)
    lines.append("* TP-Voting basiert auf den True-Positive-Einträgen der Reports plus 0/5-Referenzeinträgen aus der Ground Truth CSV.")
    lines.append("* Vor dem TP-Voting werden Report-Einträge gegen die Ground Truth kanonisiert (exakt, über CVE oder über OSV/GHSA-ID, falls eindeutig).")
    lines.append("* FP-Voting basiert ausschließlich auf den False-Positive-Einträgen der Reports; es werden keine künstlichen 0/5-FP-Referenzeinträge ergänzt.")
    lines.append("* FP-Voting wird getrennt auf exakter Vulnerability-Ebene, auf Component-Version-Ebene und auf Komponenten-Ebene ausgewertet.")
    lines.append("* InGT markiert, ob die exakte Vulnerability, Component-Version oder Komponente in der Ground Truth vorkommt.")
    lines.append("* Für FP-Vulnerabilities zeigt 'Votes', wie viele Tools exakt dieselbe Vulnerability als FP melden.")
    lines.append("* 'CVVotes' zeigt zusätzlich die Stimmen auf Component-Version-Ebene.")
    lines.append("* Die vollständigen Detail-Listen werden zusätzlich als eigene TXT-Dateien geschrieben.")

    return "\n".join(lines) + "\n", tp_list_text, fp_vuln_list_text, fp_component_list_text, fp_aggregated_component_list_text


def main() -> None:
    parser = argparse.ArgumentParser(description="x/5 Voting auf Basis von Tool-Evaluationsreports")
    parser.add_argument("--files", nargs="*", help="Optional: explizite Liste der fünf Report-Dateien")
    parser.add_argument("--threshold", type=int, default=int(os.environ.get("VOTING_THRESHOLD", "3")))
    parser.add_argument("--output", default=os.environ.get("VOTING_OUTPUT_TXT", "voting_report.txt"))
    parser.add_argument("--ground-truth-csv", default=os.environ.get("GROUND_TRUTH_CSV", ""), help="Pfad zur Ground-Truth-CSV; alternativ wird aus EXPERIMENT_PATH der Standardpfad zusammengesetzt")
    args = parser.parse_args()

    files = resolve_input_files(args)
    gt_csv_path = resolve_gt_csv_path(args)
    gt = load_ground_truth_csv(gt_csv_path)
    reports = [parse_report(p) for p in files]
    reports.sort(key=lambda r: r.tool)
    canonicalize_report_entries_against_gt(reports, gt)

    report_text, tp_list_text, fp_vuln_list_text, fp_component_list_text, fp_aggregated_component_list_text = build_voting_summary(reports, args.threshold, gt)

    output_path = Path(args.output).expanduser().resolve()
    output_path.write_text(report_text, encoding="utf-8")

    tp_list_path = output_path.with_name(output_path.stem + "_tp_list.txt")
    tp_list_path.write_text(tp_list_text, encoding="utf-8")

    fp_vuln_list_path = output_path.with_name(output_path.stem + "_fp_list.txt")
    fp_vuln_list_path.write_text(fp_vuln_list_text, encoding="utf-8")

    fp_component_list_path = output_path.with_name(output_path.stem + "_fp_component_list.txt")
    fp_component_list_path.write_text(fp_component_list_text, encoding="utf-8")

    fp_agg_list_path = output_path.with_name(output_path.stem + "_fp_component_aggregate_list.txt")
    fp_agg_list_path.write_text(fp_aggregated_component_list_text, encoding="utf-8")

    print(f"Voting-Report geschrieben      : {output_path}")
    print(f"TP-Liste geschrieben          : {tp_list_path}")
    print(f"FP-Vulnerability-Liste        : {fp_vuln_list_path}")
    print(f"FP-Component-Liste            : {fp_component_list_path}")
    print(f"FP-Komponenten-Liste          : {fp_agg_list_path}")


if __name__ == "__main__":
    main()
