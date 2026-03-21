import logging
from typing import Dict, List, Optional, Tuple, Set

import requests

from evaluation.core.model import Finding
from evaluation.adapters.github_advisory import GitHubAdvisoryAdapter
from evaluation.adapters.dtrack import DependencyTrackAdapter

log = logging.getLogger("evaluation.adapters.evaltech_simple_voting")


class EvalTechSimpleVotingAdapter:
    """
    Online voting adapters.

    Für jede eindeutige (ecosystem, component, version):
      - OSV online (/v1/query)
      - GitHub Advisory (keyword-basierter Komponenten-Call)
      - Dependency-Track (keyword-basierter Komponenten-Call, optional)

    Entscheidung pro Datensatz-Zeile (Vulnerability):
      - mindestens 2 von 3 müssen zustimmen
    """

    OSV_QUERY_URL = "https://api.osv.dev/v1/query"

    def __init__(self, config: Dict):
        self.ground_truth: List[Finding] = config.get("ground_truth", [])
        self.decisions: List[Dict] = []

        # Adapter
        self.github = GitHubAdvisoryAdapter(config)

        self.dtrack: Optional[DependencyTrackAdapter] = None
        if "env" in config:
            self.dtrack = DependencyTrackAdapter(config)
            log.info("Dependency-Track enabled")
        else:
            log.info("Dependency-Track disabled (no 'env' in config)")

        # Caches pro Komponente
        self._osv_cache: Dict[Tuple[str, str, str], List[Finding]] = {}
        self._gh_cache: Dict[Tuple[str, str, str], List[Finding]] = {}
        self._dt_cache: Dict[Tuple[str, str, str], List[Finding]] = {}

        # Indizes für schnelles Matching
        self._osv_index: Set[Tuple[str, str, str, str]] = set()
        self._gh_index: Set[Tuple[str, str, str, str]] = set()
        self._dt_index: Set[Tuple[str, str, str, str]] = set()

    def name(self) -> str:
        return "EvalTechSimpleVoting (2-of-3)"

    # ---------------------------------------------------------
    # Public API
    # ---------------------------------------------------------

    def load_findings(self) -> List[Finding]:
        log.info(
            "Starting voting over %d ground truth entries",
            len(self.ground_truth),
        )

        components = self._unique_components(self.ground_truth)
        log.info("Unique components to query: %d", len(components))

        self._build_indices(components)

        positives: List[Finding] = []
        for g in self.ground_truth:
            out = self._decide_for_row(g)
            if out is not None:
                positives.append(out)

        log.info("Voting produced %d positive findings", len(positives))
        return positives

    # ---------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------

    @staticmethod
    def _unique_components(gt: List[Finding]) -> List[Tuple[str, str, str]]:
        seen = set()
        out = []
        for g in gt:
            key = (g.ecosystem, g.component, g.version)
            if key not in seen:
                seen.add(key)
                out.append(key)
        return out

    def _build_indices(self, comps: List[Tuple[str, str, str]]) -> None:
        # OSV
        for eco, comp, ver in comps:
            for f in self._osv_findings_for_component(eco, comp, ver):
                vuln = f.cve or f.osv_id
                if vuln:
                    self._osv_index.add((eco, comp, ver, vuln))

        # GitHub
        for eco, comp, ver in comps:
            for f in self._github_findings_for_component(eco, comp, ver):
                vuln = f.cve or f.osv_id
                if vuln:
                    self._gh_index.add((eco, comp, ver, vuln))

        # DTrack
        if self.dtrack:
            for eco, comp, ver in comps:
                for f in self._dtrack_findings_for_component(eco, comp, ver):
                    vuln = f.cve or f.osv_id
                    if vuln:
                        self._dt_index.add((eco, comp, ver, vuln))

        log.info(
            "Built indices: OSV=%d | GitHub=%d | DTrack=%d",
            len(self._osv_index),
            len(self._gh_index),
            len(self._dt_index),
        )

    # ---------------------------------------------------------
    # Decision per row
    # ---------------------------------------------------------

    def _decide_for_row(self, g: Finding) -> Optional[Finding]:
        eco, comp, ver = g.ecosystem, g.component, g.version
        vuln_id = g.cve or g.osv_id

        if not vuln_id:
            self.decisions.append(
                {
                    "ecosystem": eco,
                    "component": comp,
                    "version": ver,
                    "vulnerability": "",
                    "osv": False,
                    "github": False,
                    "dtrack": (False if self.dtrack else None),
                    "positive_votes": 0,
                    "rule": ">=2 of 3",
                    "decision": False,
                    "reason": "missing vulnerability identifier",
                }
            )
            return None

        osv_hit = (eco, comp, ver, vuln_id) in self._osv_index
        gh_hit = (eco, comp, ver, vuln_id) in self._gh_index
        dt_hit = (eco, comp, ver, vuln_id) in self._dt_index if self.dtrack else False

        positive_votes = sum(1 for v in (osv_hit, gh_hit, dt_hit) if v)
        decision = positive_votes >= 2

        log.info(
            "[VOTING] %s %s@%s %s | OSV=%s GH=%s DT=%s | votes=%d -> decision=%s",
            eco,
            comp,
            ver,
            vuln_id,
            "T" if osv_hit else "F",
            "T" if gh_hit else "F",
            "T" if dt_hit else "F",
            positive_votes,
            decision,
        )

        self.decisions.append(
            {
                "ecosystem": eco,
                "component": comp,
                "version": ver,
                "vulnerability": vuln_id,
                "osv": osv_hit,
                "github": gh_hit,
                "dtrack": (dt_hit if self.dtrack else None),
                "positive_votes": positive_votes,
                "rule": ">=2 of 3",
                "decision": decision,
            }
        )

        if not decision:
            return None

        return Finding(
            ecosystem=eco,
            component=comp,
            version=ver,
            cve=g.cve,
            osv_id=g.osv_id,
            description=g.description,
            source=self.name(),
        )

    # ---------------------------------------------------------
    # OSV (online)
    # ---------------------------------------------------------

    @staticmethod
    def _osv_ecosystem_name(eco: str) -> str:
        return {
            "pypi": "PyPI",
            "npm": "npm",
            "maven": "Maven",
            "nuget": "NuGet",
        }.get(eco.lower(), eco)

    @staticmethod
    def _extract_cves(v: dict) -> List[str]:
        return [a for a in (v.get("aliases") or []) if a.startswith("CVE-")]

    def _osv_findings_for_component(self, eco: str, comp: str, ver: str) -> List[Finding]:
        key = (eco, comp, ver)
        if key in self._osv_cache:
            return self._osv_cache[key]

        payload = {
            "package": {
                "ecosystem": self._osv_ecosystem_name(eco),
                "name": comp,
            },
            "version": ver,
        }

        log.info("[OSV] query %s %s@%s", eco, comp, ver)
        try:
            r = requests.post(self.OSV_QUERY_URL, json=payload, timeout=60)
            r.raise_for_status()
            data = r.json() or {}
        except Exception as e:
            log.info("[OSV] ERROR %s %s@%s -> %s", eco, comp, ver, e)
            self._osv_cache[key] = []
            return []

        vulns = data.get("vulns") or []
        log.info("[OSV] result %s %s@%s -> %d vulns", eco, comp, ver, len(vulns))

        findings: List[Finding] = []
        for v in vulns:
            osv_id = v.get("id")
            desc = (v.get("summary") or v.get("details") or "").strip()
            cves = self._extract_cves(v)
            if cves:
                for cve in cves:
                    findings.append(
                        Finding(
                            ecosystem=eco,
                            component=comp,
                            version=ver,
                            cve=cve,
                            osv_id=osv_id,
                            description=desc,
                            source="OSV",
                        )
                    )
            else:
                findings.append(
                    Finding(
                        ecosystem=eco,
                        component=comp,
                        version=ver,
                        cve=None,
                        osv_id=osv_id,
                        description=desc,
                        source="OSV",
                    )
                )

        self._osv_cache[key] = findings
        return findings

    # ---------------------------------------------------------
    # GitHub / DTrack (keyword-only!)
    # ---------------------------------------------------------

    def _github_findings_for_component(self, eco: str, comp: str, ver: str) -> List[Finding]:
        key = (eco, comp, ver)
        if key in self._gh_cache:
            return self._gh_cache[key]

        log.info("[GITHUB] query %s %s@%s", eco, comp, ver)
        try:
            findings = self.github.load_findings_for_component(
                ecosystem=eco,
                component=comp,
                version=ver,
            ) or []
        except Exception as e:
            log.info("[GITHUB] ERROR %s %s@%s -> %s", eco, comp, ver, e)
            findings = []

        log.info("[GITHUB] result %s %s@%s -> %d findings", eco, comp, ver, len(findings))
        self._gh_cache[key] = findings
        return findings

    def _dtrack_findings_for_component(self, eco: str, comp: str, ver: str) -> List[Finding]:
        key = (eco, comp, ver)
        if key in self._dt_cache:
            return self._dt_cache[key]

        if not self.dtrack:
            self._dt_cache[key] = []
            return []

        log.info("[DTRACK] query %s %s@%s", eco, comp, ver)
        try:
            findings = self.dtrack.load_findings_for_component(
                ecosystem=eco,
                component=comp,
                version=ver,
            ) or []
        except Exception as e:
            log.info("[DTRACK] ERROR %s %s@%s -> %s", eco, comp, ver, e)
            findings = []

        log.info("[DTRACK] result %s %s@%s -> %d findings", eco, comp, ver, len(findings))
        self._dt_cache[key] = findings
        return findings
