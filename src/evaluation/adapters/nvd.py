import logging
import time
import re
from typing import Dict, List, Optional, Set, Tuple

import requests
from packaging.version import Version, InvalidVersion

from evaluation.adapters.base import VulnerabilityToolAdapter
from evaluation.core.model import Finding

log = logging.getLogger("evaluation.adapters.nvd")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
REQUEST_DELAY = 0.6  # seconds, rate-limit friendly


class NVDAdapter(VulnerabilityToolAdapter):
    """
    NVD Adapter (keyword-based, conservative)

    RULE-CONFORM SEMANTICS:
    - CVE-only
    - project-centric (GT-driven)
    - explicit FP control via product tokens
    - canonical vulnerability deduplication
    - TP_RANGE supported via explicit upper-bound detection
    """

    def __init__(self, config: dict):
        super().__init__(config)

        self.env = config.get("env", {})
        self.ground_truth = config.get("ground_truth", [])

        self.api_key: Optional[str] = self.env.get("NVD_API_KEY")

        self.session = requests.Session()
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key

        log.info(
            "Initialized NVD adapters | api_key=%s",
            "yes" if self.api_key else "no",
        )

    # ------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------

    def name(self) -> str:
        return "nvd"

    def supports_fp_heuristic(self) -> bool:
        return False

    def supports_security_findings(self) -> bool:
        return True

    # ------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------

    def load_findings(self) -> List[Finding]:
        findings: List[Finding] = []

        components = sorted({
            (f.ecosystem, f.component, f.version)
            for f in self.ground_truth
        })

        log.info("NVD: resolving %d unique components", len(components))

        seen: Set[Tuple[str, str, str, str]] = set()

        for ecosystem, component, version in self.iter_with_progress(
            components,
            desc="NVD keyword analysis",
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

        log.info("NVD findings loaded (normalized): %d", len(findings))
        return findings

    # ------------------------------------------------------------
    # Required abstract method
    # ------------------------------------------------------------

    def load_findings_for_component(
        self,
        *,
        ecosystem: str,
        component: str,
        version: str,
    ) -> List[Finding]:

        findings: List[Finding] = []

        try:
            cves = self._query_nvd_keyword(component, version)
        except Exception as e:
            log.error("NVD keyword lookup failed: %s", e)
            return []

        for cve in cves:
            findings.append(
                Finding(
                    ecosystem=ecosystem,
                    component=component,
                    version=version,
                    cve=cve["cve_id"],
                    osv_id=None,
                    description=cve.get("description", ""),
                    source="nvd-keyword",
                    affected_version_range=cve.get("affected_range"),
                )
            )

        return findings

    # ------------------------------------------------------------
    # Keyword fallback with FP control
    # ------------------------------------------------------------

    def _query_nvd_keyword(
        self,
        component: str,
        version: str,
    ) -> List[Dict[str, str]]:
        raw = self._query_nvd({"keywordSearch": component})

        tokens = self._normalized_product_tokens(component)
        filtered: List[Dict[str, str]] = []

        for cve in raw:
            desc = (cve.get("description") or "").lower()

            # 1) Exact version mention
            if version.lower() in desc:
                filtered.append({
                    **cve,
                    "affected_range": None,
                })
                continue

            # 2) Conservative upper-bound detection
            if (
                self._version_mentioned_as_affected(
                    version=version,
                    description=desc,
                )
                and any(t in desc for t in tokens)
            ):
                filtered.append({
                    **cve,
                    "affected_range": f"< {version}",
                })

        log.debug(
            "NVD keyword fallback: %d raw → %d filtered",
            len(raw),
            len(filtered),
        )

        return filtered

    # ------------------------------------------------------------
    # Product-token extraction (FP control)
    # ------------------------------------------------------------

    def _normalized_product_tokens(self, component: str) -> Set[str]:
        name = component.split(":")[-1].lower()
        parts = re.split(r"[\-_.]+", name)
        return {p for p in parts if len(p) >= 4}

    # ------------------------------------------------------------
    # Conservative version-range detection
    # ------------------------------------------------------------

    def _version_mentioned_as_affected(self, *, version: str, description: str) -> bool:
        try:
            v = Version(version)
        except InvalidVersion:
            return False

        patterns = [
            r"before\s+([0-9][0-9a-zA-Z\.\-_]+)",
            r"prior to\s+([0-9][0-9a-zA-Z\.\-_]+)",
            r"earlier than\s+([0-9][0-9a-zA-Z\.\-_]+)",
            r"up to\s+([0-9][0-9a-zA-Z\.\-_]+)",
            r"through\s+([0-9][0-9a-zA-Z\.\-_]+)",
            r"<\s*([0-9][0-9a-zA-Z\.\-_]+)",
        ]

        for p in patterns:
            for m in re.finditer(p, description):
                try:
                    upper = Version(m.group(1))
                except InvalidVersion:
                    continue

                if v < upper:
                    return True

        return False

    # ------------------------------------------------------------
    # Low-level NVD API
    # ------------------------------------------------------------

    def _query_nvd(self, base_params: Dict[str, str]) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        start_index = 0
        retries = 0
        max_retries = 5
        backoff = 5.0

        while True:
            params = dict(base_params)
            params.update({
                "startIndex": start_index,
                "resultsPerPage": RESULTS_PER_PAGE,
            })

            try:
                r = self._api_call(
                    session=self.session,
                    method="GET",
                    url=NVD_API_URL,
                    params=params,
                    timeout=60,
                )

                if r.status_code == 429:
                    if retries >= max_retries:
                        log.error("NVD rate limit exceeded – aborting")
                        return results

                    wait = backoff * (2 ** retries)
                    time.sleep(wait)
                    retries += 1
                    continue

                r.raise_for_status()

            except requests.RequestException as e:
                log.error("NVD request failed: %s", e)
                return results

            data = r.json()
            vulns = data.get("vulnerabilities", [])

            for item in vulns:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id:
                    continue

                description = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        description = d.get("value", "")
                        break

                results.append({
                    "cve_id": cve_id,
                    "description": description,
                })

            total = data.get("totalResults", 0)
            start_index += RESULTS_PER_PAGE
            retries = 0

            if start_index >= total:
                break

            time.sleep(REQUEST_DELAY)

        return results
