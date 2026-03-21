import logging
from pathlib import Path
from typing import List

from evaluation.core.model import Finding

log = logging.getLogger("evaluation.report.text")

LINE = "-" * 119


# ============================================================
# PUBLIC API — MUST STAY STABLE
# ============================================================

def write_report(
    *,
    tool_name: str,
    input_csv: str,
    tp,
    fp,
    fn,
    fp_stats,
    fn_stats,
    ground_truth,
    api_stats=None,
):

    from datetime import datetime
    from pathlib import Path

    out_path = Path(input_csv).with_name(
        f"{Path(input_csv).stem}_{tool_name}_evaluation.txt"
    )

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    title = f"{tool_name} Evaluation Report ({created_at})"

    tp = tp or []
    fp = fp or []
    fn = fn or []
    fp_stats = fp_stats or {}
    fn_stats = fn_stats or {}
    ground_truth = ground_truth or []

    tp_exact = [t for t in tp if getattr(t, "match_type", None) == "TP_EXACT"]
    tp_range = [t for t in tp if getattr(t, "match_type", None) == "TP_RANGE"]

    if not tp_exact and not tp_range and tp:
        tp_exact = list(tp)
        tp_range = []

    with out_path.open("w", encoding="utf-8") as f:
        f.write(title + "\n")
        f.write("=" * len(title) + "\n\n")

        f.write("Input Parameters\n")
        f.write("----------------\n")
        f.write(f"GROUND_TRUTH_CSV = {input_csv}\n")
        f.write(f"TOOL            = {tool_name}\n\n")

        _write_global_summary(
            f,
            ground_truth=ground_truth,
            tp_exact=tp_exact,
            tp_range=tp_range,
            fp=fp,
        )

        if tool_name.lower() == "osv":
            _write_osv_ground_truth_note(f)

        _write_per_ecosystem_statistics(
            f,
            ground_truth=ground_truth,
            tp_exact=tp_exact,
            tp_range=tp_range,
            fp=fp,
            fn_stats=fn_stats,
        )

        # ========================================================
        # API Access
        # ========================================================
        _write_api_access_statistics(f, api_stats)


        # ========================================================
        # GROUND TRUTH SUMMARY (OSV-centric)
        # ========================================================
        _write_ground_truth_summary(
            f,
            ground_truth=ground_truth,
        )

        # ========================================================
        # FP CLASSIFICATION
        # ========================================================
        f.write("\n\nFP Classification (candidate-based)\n")
        f.write(LINE + "\n")
        f.write(f"FP-CERTAIN : {fp_stats.get('FP-CERTAIN', 0):>7d}\n")
        f.write(f"FP-LIKELY  : {fp_stats.get('FP-LIKELY', 0):>7d}\n")
        f.write(f"FP-UNCLEAR : {fp_stats.get('FP-UNCLEAR', 0):>7d}\n\n")

        f.write("FP class semantics\n")
        f.write("------------------\n")
        f.write(
            "FP-CERTAIN : High-confidence false positive (clear mismatch).\n"
            "FP-LIKELY  : Probable false positive (weak/partial evidence).\n"
            "FP-UNCLEAR : Ambiguous case requiring manual inspection.\n\n"
        )

        # ========================================================
        # FN CLASSIFICATION
        # ========================================================
        f.write("\n\nFN Classification (ground-truth based)\n")
        f.write(LINE + "\n")
        f.write(f"FN-EXACT : {len(fn_stats.get('FN_exact', [])):>7d}\n")
        f.write(f"FN-RANGE : {len(fn_stats.get('FN_range', [])):>7d}\n")
        f.write(f"FN-TRUE  : {len(fn_stats.get('FN_true', [])):>7d}\n\n")

        f.write("FN class semantics\n")
        f.write("------------------\n")
        f.write(
            "FN-EXACT : Tool reports same component/version but wrong identifiers.\n"
            "FN-RANGE : Tool reports a covering range but no explicit finding.\n"
            "FN-TRUE  : Tool reports no finding at all.\n\n"
        )

        # ========================================================
        # TOOL FINDINGS ANALYSIS (diagnostic)
        # ========================================================
        _write_tool_findings_analysis(
            f,
            tp=tp_exact + tp_range,
            fp=fp,
            fn=fn,
        )

        # ========================================================
        # DETAIL TABLES
        # ========================================================

        # --- False Positives (immer anzeigen, auch wenn leer) ---
        f.write("\n\n")
        _write_false_positives_table(f, fp)

        # --- False Negatives (immer anzeigen, auch wenn leer) ---
        f.write("\n\n")
        _write_false_negatives_table(f, fn, fn_stats)

        # --- True Positives (immer anzeigen, auch wenn leer) ---
        f.write("\n\n")
        _write_list(
            f,
            "True Positives (TP = TP_EXACT + TP_RANGE)",
            tp_exact + tp_range,
            include_tp_type=True,
        )

        f.write("\n=== End of report ===\n")




# ============================================================
# GLOBAL SUMMARIES
# ============================================================

def _write_global_summary(
    f,
    *,
    ground_truth,
    tp_exact,
    tp_range,
    fp,
):
    tp_total = len(tp_exact) + len(tp_range)
    gt_total = len(ground_truth)

    recall_gt = tp_total / gt_total if gt_total else 0.0
    recall_exact = len(tp_exact) / gt_total if gt_total else 0.0
    overlap = tp_total / (tp_total + len(fp)) if (tp_total + len(fp)) else 0.0

    f.write("Summary\n")
    f.write(LINE + "\n")
    f.write(f"True Positives (TP_EXACT)              : {len(tp_exact):>7d}\n")
    f.write(f"True Positives (TP_RANGE)              : {len(tp_range):>7d}\n")
    f.write(f"True Positives (TP_TOTAL)              : {tp_total:>7d}\n")
    f.write(f"False Positives (FP)                   : {len(fp):>7d}\n")
    f.write(f"False Negatives (FN)                   : {gt_total - tp_total:>7d}\n")
    f.write(f"Vulnerabilities in Ground Truth        : {gt_total:>7d}\n")
    f.write(f"Recall @ GT (TP_EXACT+TP_RANGE)        : {recall_gt:7.3f}\n")
    f.write(f"Recall_EXACT (TP_EXACT only)           : {recall_exact:7.3f}\n")
    f.write(f"Overlap Rate                           : {overlap:7.3f}\n\n")




def _write_ground_truth_summary(f, *, ground_truth):
    LABEL = 42
    INT = 7
    FLT = 7

    def li(label, v):
        f.write(f"{label:<{LABEL}} : {v:>{INT}d}\n")

    def lf(label, v):
        f.write(f"{label:<{LABEL}} : {v:>{FLT}.3f}\n")

    components = {
        (g.ecosystem, g.component, g.version)
        for g in ground_truth
    }
    osv_entries = {
        (g.ecosystem, g.component, g.version, g.osv_id)
        for g in ground_truth if g.osv_id
    }
    cves = {g.cve for g in ground_truth if g.cve}

    ratio = len(cves) / len(osv_entries) if osv_entries else 0.0

    f.write("\n\n")
    f.write("Ground Truth Summary (OSV-centric)\n")
    f.write("---------------------------------\n")
    li("Unique Components", len(components))
    li("OSV vulnerability entries", len(osv_entries))
    li("Unique CVE identifiers", len(cves))
    lf("CVEs / OSV-vulnerabilities", ratio)
    f.write("\n")


# ============================================================
# PER-ECOSYSTEM STATISTICS
# ============================================================

def _write_per_ecosystem_statistics(
    f,
    *,
    ground_truth,
    tp_exact,
    tp_range,
    fp,
    fn_stats,
):
    from collections import defaultdict

    f.write("\nPer-Ecosystem Statistics\n")

    W = {
        "eco": 10,
        "components": 10,
        "vulns": 15,
        "cves": 5,
        "tp": 3,
        "tp_exact": 8,
        "tp_range": 8,
        "fp": 3,
        "fn": 3,
        "fn_exact": 8,
        "fn_range": 8,
        "fn_true": 7,
        "fp_certain": 10,
        "fp_likely": 9,
        "fp_unclear": 10,
        "recall": 6,
        "recall_exact": 12,
        "overlap": 7,
    }

    header = (
        f"{'Ecosystem':<{W['eco']}} | "
        f"{'Components':>{W['components']}} | "
        f"{'Vulnerabilities':>{W['vulns']}} | "
        f"{'CVEs':>{W['cves']}} | "
        f"{'TP':>{W['tp']}} | "
        f"{'TP_EXACT':>{W['tp_exact']}} | "
        f"{'TP_RANGE':>{W['tp_range']}} | "
        f"{'FP':>{W['fp']}} | "
        f"{'FN':>{W['fn']}} | "
        f"{'FN_EXACT':>{W['fn_exact']}} | "
        f"{'FN_RANGE':>{W['fn_range']}} | "
        f"{'FN_TRUE':>{W['fn_true']}} | "
        f"{'FP-CERTAIN':>{W['fp_certain']}} | "
        f"{'FP-LIKELY':>{W['fp_likely']}} | "
        f"{'FP-UNCLEAR':>{W['fp_unclear']}} | "
        f"{'Recall':>{W['recall']}} | "
        f"{'Recall_EXACT':>{W['recall_exact']}} | "
        f"{'Overlap':>{W['overlap']}}"
    )

    line = "-" * len(header)
    f.write(line + "\n")
    f.write(header + "\n")
    f.write(line + "\n")

    # --------------------------------------------------
    # Ground truth aggregation
    # --------------------------------------------------
    comps = defaultdict(set)
    vulns = defaultdict(int)
    cves = defaultdict(set)

    for g in ground_truth:
        eco = g.ecosystem
        comps[eco].add((g.component, g.version))
        vulns[eco] += 1
        if g.cve:
            cves[eco].add(g.cve)

    # --------------------------------------------------
    # TP aggregation
    # --------------------------------------------------
    tp_e = defaultdict(int)
    tp_r = defaultdict(int)

    for g in tp_exact:
        tp_e[g.ecosystem] += 1
    for g in tp_range:
        tp_r[g.ecosystem] += 1

    # --------------------------------------------------
    # FP aggregation
    # --------------------------------------------------
    fp_by_eco = defaultdict(lambda: {"FP-CERTAIN": 0, "FP-LIKELY": 0, "FP-UNCLEAR": 0})
    for fnd in fp:
        cls = getattr(fnd, "fp_class", "FP-CERTAIN")
        fp_by_eco[fnd.ecosystem][cls] += 1

    # --------------------------------------------------
    # FN aggregation
    # --------------------------------------------------
    fn_stats = fn_stats or {}
    fn_by_eco = defaultdict(lambda: {"FN_exact": 0, "FN_range": 0, "FN_true": 0})
    for k, lst in fn_stats.items():
        if not lst:
            continue
        for g in lst:
            # erwartet: k ist "FN_exact" / "FN_range" / "FN_true"
            if k in fn_by_eco[g.ecosystem]:
                fn_by_eco[g.ecosystem][k] += 1

    # --------------------------------------------------
    # TOTAL aggregators (EXPLICIT)
    # --------------------------------------------------
    total_tp_sum = 0
    total_fp_sum = 0
    total_vulns = 0

    total_tp_exact = 0
    total_tp_range = 0

    total_fn = 0
    total_fn_exact = 0
    total_fn_range = 0
    total_fn_true = 0

    total_fp_certain = 0
    total_fp_likely = 0
    total_fp_unclear = 0

    total_cves = set()

    # --------------------------------------------------
    # Per-ecosystem rows
    # --------------------------------------------------
    for eco in sorted(comps):
        te = tp_e[eco]
        tr = tp_r[eco]
        tp = te + tr

        fp_n = sum(fp_by_eco[eco].values())
        fn_exact_n = fn_by_eco[eco]["FN_exact"]
        fn_range_n = fn_by_eco[eco]["FN_range"]
        fn_true_n = fn_by_eco[eco]["FN_true"]
        fn_n = fn_exact_n + fn_range_n + fn_true_n

        v = vulns[eco]

        recall = tp / v if v > 0 else 0.0
        recall_exact = te / v if v > 0 else 0.0
        overlap = tp / (tp + fp_n) if (tp + fp_n) > 0 else 0.0

        f.write(
            f"{eco:<{W['eco']}} | "
            f"{len(comps[eco]):>{W['components']}d} | "
            f"{v:>{W['vulns']}d} | "
            f"{len(cves[eco]):>{W['cves']}d} | "
            f"{tp:>{W['tp']}d} | "
            f"{te:>{W['tp_exact']}d} | "
            f"{tr:>{W['tp_range']}d} | "
            f"{fp_n:>{W['fp']}d} | "
            f"{fn_n:>{W['fn']}d} | "
            f"{fn_exact_n:>{W['fn_exact']}d} | "
            f"{fn_range_n:>{W['fn_range']}d} | "
            f"{fn_true_n:>{W['fn_true']}d} | "
            f"{fp_by_eco[eco]['FP-CERTAIN']:>{W['fp_certain']}d} | "
            f"{fp_by_eco[eco]['FP-LIKELY']:>{W['fp_likely']}d} | "
            f"{fp_by_eco[eco]['FP-UNCLEAR']:>{W['fp_unclear']}d} | "
            f"{recall:>{W['recall']}.2f} | "
            f"{recall_exact:>{W['recall_exact']}.2f} | "
            f"{overlap:>{W['overlap']}.2f}\n"
        )

        # accumulate totals
        total_tp_sum += tp
        total_fp_sum += fp_n
        total_vulns += v

        total_tp_exact += te
        total_tp_range += tr

        total_fn += fn_n
        total_fn_exact += fn_exact_n
        total_fn_range += fn_range_n
        total_fn_true += fn_true_n

        total_fp_certain += fp_by_eco[eco]["FP-CERTAIN"]
        total_fp_likely += fp_by_eco[eco]["FP-LIKELY"]
        total_fp_unclear += fp_by_eco[eco]["FP-UNCLEAR"]

        total_cves |= cves[eco]

    # Safety: falls FN-Listen fehlen/leer sind, FN konsistent aus GT ableiten
    # (wenn fn_stats gar nicht geführt wurde)
    if total_fn == 0 and total_vulns > 0:
        total_fn = total_vulns - total_tp_sum

    # --------------------------------------------------
    # TOTAL row
    # --------------------------------------------------
    total_recall = total_tp_sum / total_vulns if total_vulns > 0 else 0.0
    total_recall_exact = total_tp_exact / total_vulns if total_vulns > 0 else 0.0
    total_overlap = (
        total_tp_sum / (total_tp_sum + total_fp_sum)
        if (total_tp_sum + total_fp_sum) > 0
        else 0.0
    )

    f.write(line + "\n")
    f.write(
        f"{'TOTAL':<{W['eco']}} | "
        f"{sum(len(v) for v in comps.values()):>{W['components']}d} | "
        f"{total_vulns:>{W['vulns']}d} | "
        f"{len(total_cves):>{W['cves']}d} | "
        f"{total_tp_sum:>{W['tp']}d} | "
        f"{total_tp_exact:>{W['tp_exact']}d} | "
        f"{total_tp_range:>{W['tp_range']}d} | "
        f"{total_fp_sum:>{W['fp']}d} | "
        f"{total_fn:>{W['fn']}d} | "
        f"{total_fn_exact:>{W['fn_exact']}d} | "
        f"{total_fn_range:>{W['fn_range']}d} | "
        f"{total_fn_true:>{W['fn_true']}d} | "
        f"{total_fp_certain:>{W['fp_certain']}d} | "
        f"{total_fp_likely:>{W['fp_likely']}d} | "
        f"{total_fp_unclear:>{W['fp_unclear']}d} | "
        f"{total_recall:>{W['recall']}.2f} | "
        f"{total_recall_exact:>{W['recall_exact']}.2f} | "
        f"{total_overlap:>{W['overlap']}.2f}\n"
    )




# ============================================================
# LIST OUTPUT
# ============================================================

def _write_list(
    f,
    title: str,
    rows: list,
    *,
    include_tp_type: bool = False,
) -> None:
    f.write(f"\n{title} ({len(rows)})\n")
    f.write("=" * (len(title) + len(str(len(rows))) + 3) + "\n")

    comp_w = _component_col_width(rows)

    if include_tp_type:
        f.write(
            f"Ecosystem  | {'Component':<{comp_w}} | Version        | "
            "CVE-ID          | OSV-ID               | TP-Type  | Description\n"
        )
        f.write("-" * (comp_w + 145) + "\n")
    else:
        f.write(
            f"Ecosystem  | {'Component':<{comp_w}} | Version        | "
            "CVE-ID          | OSV-ID               | Description\n"
        )
        f.write("-" * (comp_w + 125) + "\n")

    for r in rows:
        desc = (r.description or "").replace("\n", " ").replace("|", " ")
        tp_type = getattr(r, "match_type", "-")

        if include_tp_type:
            f.write(
                f"{r.ecosystem:<10} | "
                f"{r.component:<{comp_w}} | "
                f"{r.version[:14]:<14} | "
                f"{(r.cve or '-'): <15} | "
                f"{(r.osv_id or '-'): <20} | "
                f"{tp_type:<8} | "
                f"{desc[:70]}\n"
            )
        else:
            f.write(
                f"{r.ecosystem:<10} | "
                f"{r.component:<{comp_w}} | "
                f"{r.version[:14]:<14} | "
                f"{(r.cve or '-'): <15} | "
                f"{(r.osv_id or '-'): <20} | "
                f"{desc[:70]}\n"
            )



def _write_false_positives_table(f, fp):
    f.write("\n\n")
    count = len(fp)

    title = f"False Positives ({count})"
    f.write(title + "\n")
    f.write("=" * (len(title) + 1) + "\n")

    comp_w = _component_col_width(fp)

    f.write(
        f"Ecosystem  | {'Component':<{comp_w}} | Version        | "
        "CVE-ID          | OSV-ID               | FP-Class  | Description\n"
    )
    f.write("-" * (comp_w + 111) + "\n")

    for r in fp:
        fp_class = getattr(r, "fp_class", "FP")

        f.write(
            f"{r.ecosystem:<10} | "
            f"{r.component:<{comp_w}} | "
            f"{r.version[:14]:<14} | "
            f"{(r.cve or '-'): <15} | "
            f"{(r.osv_id or '-'): <20} | "
            f"{fp_class:<9} | "
            f"{(r.description or '')[:60]}\n"
        )




def _fn_class_lookup(fn_stats):
    return {
        id(g): cls.upper()
        for cls, lst in fn_stats.items()
        for g in lst
    }


def _write_false_negatives_table(f, fn, fn_stats):
    f.write("\n\n")
    count = len(fn)

    title = f"False Negatives ({count})"
    f.write(title + "\n")
    f.write("=" * (len(title) + 1) + "\n")

    fn_class = _fn_class_lookup(fn_stats)
    comp_w = _component_col_width(fn)

    f.write(
        f"Ecosystem  | {'Component':<{comp_w}} | Version        | "
        "CVE-ID          | OSV-ID               | FN-Class  | Description\n"
    )
    f.write("-" * (comp_w + 111) + "\n")

    for g in fn:
        component = str(g.component or "")
        f.write(
            f"{g.ecosystem:<10} | "
            f"{component:<{comp_w}} | "
            f"{g.version[:14]:<14} | "
            f"{(g.cve or '-'): <15} | "
            f"{(g.osv_id or '-'): <20} | "
            f"{fn_class.get(id(g), 'FN_TRUE'):<9} | "
            f"{(g.description or '')[:60]}\n"
        )



def _write_tool_findings_analysis(
    f,
    *,
    tp,
    fp,
    fn,
    top_n: int = 5,
):
    from collections import defaultdict

    by_component = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0})
    by_ecosystem = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0})

    for r in tp:
        by_component[(r.ecosystem, r.component)]["TP"] += 1
        by_ecosystem[r.ecosystem]["TP"] += 1
    for r in fp:
        by_component[(r.ecosystem, r.component)]["FP"] += 1
        by_ecosystem[r.ecosystem]["FP"] += 1
    for r in fn:
        by_component[(r.ecosystem, r.component)]["FN"] += 1
        by_ecosystem[r.ecosystem]["FN"] += 1

    top_fp = sorted(by_component.items(), key=lambda x: x[1]["FP"], reverse=True)[:top_n]
    top_fn = sorted(by_component.items(), key=lambda x: x[1]["FN"], reverse=True)[:top_n]
    eco_fn = sorted(by_ecosystem.items(), key=lambda x: x[1]["FN"], reverse=True)

    f.write("Tool Findings Analysis (diagnostic)\n")
    f.write("---------------------------------\n")

    f.write("Top-5 components with most False Positives\n")
    for (eco, comp), s in top_fp:
        f.write(
            f"- {eco:<8} | {comp:<35} | "
            f"FP={s['FP']:>3} | TP={s['TP']:>3} | FN={s['FN']:>3}\n"
        )
    f.write("\n")

    f.write("Top-5 components with most False Negatives\n")
    for (eco, comp), s in top_fn:
        f.write(
            f"- {eco:<8} | {comp:<35} | "
            f"FN={s['FN']:>3} | TP={s['TP']:>3} | FP={s['FP']:>3}\n"
        )
    f.write("\n")

    f.write("Ecosystems ranked by False Negatives\n")
    for eco, s in eco_fn:
        f.write(
            f"- {eco:<8} | "
            f"FN={s['FN']:>3} | TP={s['TP']:>3} | FP={s['FP']:>3}\n"
        )
    f.write("\n")


def _write_osv_ground_truth_note(f) -> None:
    f.write(
        "Notes on OSV and Ground Truth Stability\n"
        "--------------------------------------\n"
        "Ground truth is vulnerability-centric. Multiple OSV advisories (e.g. GHSA,\n"
        "PYSEC, OSV IDs) referring to the same canonical vulnerability are collapsed\n"
        "prior to evaluation. OSV is therefore used as a reference validator and not\n"
        "evaluated at advisory granularity.\n\n"
    )


def _write_request_stats(f, request_stats) -> None:
    if not request_stats:
        return

    f.write("\n\nRequest / Response Statistics\n")
    f.write("----------------------------\n")

    # erwartetes Schema (Beispiel):
    # request_stats = {
    #   "requests_total": 123,
    #   "errors_total": 2,
    #   "avg_ms": 210.5,
    #   "p50_ms": 180.0,
    #   "p95_ms": 420.0,
    #   "min_ms": 50.0,
    #   "max_ms": 1200.0,
    # }
    for k in [
         "requests_total", "errors_total",
        "min_ms", "avg_ms", "p50_ms", "p95_ms", "max_ms",
    ]:
        if k in request_stats:
                f.write(f"{k:<22}: {request_stats[k]}\n")


def _write_api_access_statistics(f, api_stats) -> None:
    if not api_stats:
        return

    f.write("\n\nAPI access statistics (evaluation)\n")
    f.write("---------------------------------\n")
    f.write(
        "API              | Calls | Total Time (ms) | Avg Time (ms)\n"
    )
    f.write("-" * 58 + "\n")

    for api, s in sorted(api_stats.items()):
        f.write(
            f"{api:<16} | "
            f"{s['calls']:>5} | "
            f"{s['total_ms']:>15.2f} | "
            f"{s['avg_ms']:>13.2f}\n"
        )

def _component_col_width(rows, min_width: int = 10) -> int:
    """
    Compute the column width for the 'Component' column so that
    all values fit without truncation.

    Width = max(len(component)) + 1
    """
    if not rows:
        return min_width

    max_len = max(len(str(r.component or "")) for r in rows)
    return max(min_width, max_len + 1)
