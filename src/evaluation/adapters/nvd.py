import logging
import re
import time
from typing import List, Dict, Optional, Set, Tuple

import requests
from packaging.version import Version, InvalidVersion

from evaluation.adapters.base import VulnerabilityToolAdapter
from evaluation.core.model import Finding


log = logging.getLogger("evaluation.adapters.nvd")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
REQUEST_DELAY = 0.6


class NVDAdapter(VulnerabilityToolAdapter):

    def __init__(self, config: dict):
        super().__init__(config)

        self.env = config.get("env", {})
        self.ground_truth = config.get("ground_truth", [])

        self.api_key: Optional[str] = self.env.get("NVD_API_KEY")

        self.session = requests.Session()
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key

        log.info(
            "Initialized NVD adapter | api_key=%s",
            "yes" if self.api_key else "no",
        )

    # ------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------

    def name(self) -> str:
        return "nvd"

    def supports_fp_heuristic(self) -> bool:
        return True

    def supports_security_findings(self) -> bool:
        return True

    # ------------------------------------------------------------
    # Main
    # ------------------------------------------------------------

    def load_findings(self) -> List[Finding]:
        findings: List[Finding] = []

        components = sorted({
            (f.ecosystem, f.component, f.version)
            for f in self.ground_truth
        })

        log.info("NVD: resolving %d components", len(components))

        seen: Set[Tuple[str, str, str, str]] = set()

        for ecosystem, component, version in self.iter_with_progress(
            components,
            desc="NVD analysis",
            unit="component",
        ):
            rows = self.load_findings_for_component(
                ecosystem=ecosystem,
                component=component,
                version=version,
            )

            for r in rows:
                key = (r.ecosystem, r.component, r.version, r.cve)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(r)

            time.sleep(REQUEST_DELAY)

        log.info("NVD findings loaded: %d", len(findings))
        return findings

    # ------------------------------------------------------------
    # Core logic
    # ------------------------------------------------------------

    def load_findings_for_component(
        self,
        *,
        ecosystem: str,
        component: str,
        version: str,
    ) -> List[Finding]:

        raw = self._query_candidates(component)

        if not raw:
            return []

        tokens = self._tokens(component)

        findings: List[Finding] = []

        for cve in raw:
            desc = (cve.get("description") or "").lower()

            score = 0

            # --------------------------------------------------
            # PRODUCT MATCH
            # --------------------------------------------------
            if any(t in desc for t in tokens):
                score += 2

            # --------------------------------------------------
            # VERSION SIGNALS
            # --------------------------------------------------
            if version.lower() in desc:
                score += 3

            if self._version_range_match(version, desc):
                score += 2

            # --------------------------------------------------
            # STRONG SIGNALS (keywords)
            # --------------------------------------------------
            if "apache" in desc:
                score += 1

            if "library" in desc:
                score += 1

            # --------------------------------------------------
            # DECISION
            # --------------------------------------------------
            if score >= 2:
                findings.append(
                    Finding(
                        ecosystem=ecosystem,
                        component=component,
                        version=version,
                        cve=cve["cve_id"],
                        osv_id=None,
                        description=desc,
                        source="nvd",
                        affected_version_range=None,
                    )
                )

        return findings

    # ------------------------------------------------------------
    # Query (robust)
    # ------------------------------------------------------------

    def _query_candidates(self, component: str) -> List[Dict[str, str]]:
        queries = self._build_queries(component)

        for q in queries:
            try:
                results = self._query_nvd({"keywordSearch": q})
                if results:
                    return results
            except Exception as e:
                log.debug("Query failed: %s", e)

        return []

    def _build_queries(self, component: str) -> List[str]:
        if ":" in component:
            group, artifact = component.split(":", 1)
        else:
            group, artifact = "", component

        artifact = artifact.lower()

        queries = [
            artifact,
            artifact.replace("-", " "),
        ]

        if group:
            vendor = group.split(".")[-1]
            queries.append(f"{artifact} {vendor}")

        return queries

    # ------------------------------------------------------------
    # Token extraction
    # ------------------------------------------------------------

    def _tokens(self, component: str) -> Set[str]:
        name = component.split(":")[-1].lower()
        parts = re.split(r"[\-_.]+", name)

        tokens = {name}
        tokens.update(parts)

        return {t for t in tokens if len(t) >= 3}

    # ------------------------------------------------------------
    # Version range detection
    # ------------------------------------------------------------

    def _version_range_match(self, version: str, desc: str) -> bool:
        try:
            v = Version(version)
        except InvalidVersion:
            return False

        patterns = [
            r"before\s+([0-9][0-9a-zA-Z\.\-_]+)",
            r"before version\s+([0-9][0-9a-zA-Z\.\-_]+)",
            r"prior to\s+([0-9][0-9a-zA-Z\.\-_]+)",
            r"<\s*([0-9][0-9a-zA-Z\.\-_]+)",
        ]

        for p in patterns:
            for m in re.finditer(p, desc):
                try:
                    upper = Version(m.group(1))
                    if v < upper:
                        return True
                except InvalidVersion:
                    continue

        return False

    # ------------------------------------------------------------
    # NVD API
    # ------------------------------------------------------------

    def _query_nvd(self, params: Dict[str, str]) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []

        params.update({
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": 0,
        })

        r = self.session.get(NVD_API_URL, params=params, timeout=60)

        if r.status_code == 404:
            return []

        r.raise_for_status()

        data = r.json()
        vulns = data.get("vulnerabilities", [])

        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id")

            if not cve_id:
                continue

            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            results.append({
                "cve_id": cve_id,
                "description": desc,
            })

        return results