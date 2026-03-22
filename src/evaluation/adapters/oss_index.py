from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests

from evaluation.adapters.base import VulnerabilityToolAdapter
from evaluation.core.model import Finding
from evaluation.core.normalization import normalize_identifier

log = logging.getLogger("adapters.ossindex")


@dataclass(frozen=True)
class _CoordKey:
    ecosystem: str
    component: str
    version: str


class OSSIndexAdapter(VulnerabilityToolAdapter):
    """
    Sonatype OSS Index Adapter (real OSS Index backend).

    Semantics (RULE-CONFORM):
    - project-centric: only GT component+version queried
    - no matching logic in adapters
    - findings MUST carry at least one identifier (CVE or GHSA)
    - advisory duplicates are collapsed to canonical GT granularity
    """

    BASE_URL = "https://ossindex.sonatype.org"
    COMPONENT_REPORT_PATH = "/api/v3/component-report"
    BATCH_SIZE = 128

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        env = config.get("env", {})

        self.username = env.get("OSSINDEX_USERNAME")
        self.token = env.get("OSSINDEX_TOKEN")

        self.max_retries = int(env.get("OSSINDEX_MAX_RETRIES", 3))
        self.retry_backoff_s = float(env.get("OSSINDEX_RETRY_BACKOFF_S", 1.5))

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "evaltech-report/ossindex-adapters",
            }
        )

        if self.username and self.token:
            self.session.auth = (self.username, self.token)
            log.info("OSS Index adapters initialized (authenticated)")
        else:
            log.info("OSS Index adapters initialized (anonymous)")

        self._cache_all_findings: Optional[List[Finding]] = None

    # ------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------

    def name(self) -> str:
        return "oss-index"

    def supports_security_findings(self) -> bool:
        return True

    def supports_fp_heuristic(self) -> bool:
        return False

    # ------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------

    def load_findings(self) -> List[Finding]:
        if self._cache_all_findings is not None:
            return self._cache_all_findings

        gt: List[Finding] = self.config.get("ground_truth") or []
        if not gt:
            log.warning("OSS Index: no ground truth provided")
            self._cache_all_findings = []
            return []

        coord_map: Dict[str, _CoordKey] = {}
        coordinates: List[str] = []

        for f in gt:
            coord: Optional[str] = None

            purl = getattr(f, "purl", None)
            if purl:
                coord = purl.strip()

            if not coord:
                coord = self._to_purl_coordinate(
                    ecosystem=f.ecosystem,
                    component=f.component,
                    version=f.version,
                )

            if not coord or coord in coord_map:
                continue

            coord_map[coord] = _CoordKey(
                ecosystem=f.ecosystem,
                component=f.component,
                version=f.version,
            )
            coordinates.append(coord)

        findings: List[Finding] = []

        for batch in self.iter_with_progress(
            self._chunks(coordinates, self.BATCH_SIZE),
            desc="OSS Index component-report",
            unit="batch",
        ):
            batch_findings = self._query_component_report(
                batch,
                coord_map=coord_map,
            )
            findings.extend(batch_findings)

        # ---------- Canonical deduplication ----------
        deduped: Dict[Tuple[str, str, str, str], Finding] = {}
        for f in findings:
            key = (
                f.ecosystem,
                f.component,
                f.version,
                f.cve or f.ghsa,
            )
            if key not in deduped:
                deduped[key] = f

        self._cache_all_findings = list(deduped.values())
        return self._cache_all_findings

    def load_findings_for_component(
        self,
        *,
        ecosystem: str,
        component: str,
        version: str,
    ) -> List[Finding]:
        all_findings = self.load_findings()
        return [
            f for f in all_findings
            if f.ecosystem == ecosystem and f.component == component and f.version == version
        ]

    # ------------------------------------------------------------
    # OSS Index interaction
    # ------------------------------------------------------------

    def _query_component_report(
        self,
        coordinates: List[str],
        *,
        coord_map: Dict[str, _CoordKey],
    ) -> List[Finding]:
        url = f"{self.BASE_URL}{self.COMPONENT_REPORT_PATH}"
        payload = {"coordinates": coordinates}

        for attempt in range(1, self.max_retries + 1):
            try:
                r = self._api_call(
                    session=self.session,
                    method="POST",
                    url=url,
                    json_body=payload,
                    timeout=45,
                )
            except requests.RequestException:
                self._sleep_backoff(attempt)
                continue

            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    return []
                return self._parse_component_report(data, coord_map=coord_map)

            if r.status_code == 429:
                self._sleep_backoff(attempt, honor_retry_after=r)
                continue

            if r.status_code in (401, 403):
                return []

            self._sleep_backoff(attempt)

        return []

    def _parse_component_report(
        self,
        data: Any,
        *,
        coord_map: Dict[str, _CoordKey],
    ) -> List[Finding]:
        if not isinstance(data, list):
            return []

        out: List[Finding] = []

        for comp_report in data:
            if not isinstance(comp_report, dict):
                continue

            coord = str(
                comp_report.get("coordinates")
                or comp_report.get("coordinate")
                or ""
            ).strip()

            key = coord_map.get(coord) or self._best_effort_key_from_purl(coord)
            if key is None:
                continue

            vulns = comp_report.get("vulnerabilities") or []
            if not isinstance(vulns, list):
                continue

            for v in vulns:
                if not isinstance(v, dict):
                    continue

                vid = (v.get("id") or "").strip()
                title = (v.get("title") or "").strip()
                description = (v.get("description") or "").strip()

                text = " ".join([vid, title, description])

                cve = self._extract_cve(v, fallback_text=text)
                ghsa = self._extract_ghsa(v, fallback_text=text)

                # ---------- RULE: require identifier ----------
                if not cve and not ghsa:
                    continue

                desc_line = (title or description or "").split("\n")[0].strip()
                if vid:
                    desc_line = f"[OSSINDEX:{vid}] {desc_line}".strip()

                out.append(
                    Finding(
                        ecosystem=key.ecosystem,
                        component=key.component,
                        version=key.version,
                        cve=cve,
                        ghsa=ghsa,
                        osv_id=None,
                        description=desc_line,
                        source="ossindex",
                        affected_version_range=None,
                    )
                )

        return out

    # ------------------------------------------------------------
    # Coordinate building
    # ------------------------------------------------------------

    def _to_purl_coordinate(
        self,
        *,
        ecosystem: str,
        component: str,
        version: str,
    ) -> Optional[str]:
        if not ecosystem or not component or not version:
            return None

        eco = ecosystem.strip().lower()
        comp = component.strip()
        ver = version.strip()

        if eco == "maven":
            if ":" in comp:
                group, artifact = comp.split(":", 1)
            elif "/" in comp:
                group, artifact = comp.split("/", 1)
            else:
                return None

            return f"pkg:maven/{quote(group)}/{quote(artifact)}@{quote(ver)}"

        if eco == "nuget":
            return f"pkg:nuget/{quote(comp)}@{quote(ver)}"

        if eco == "npm":
            return f"pkg:npm/{quote(comp, safe='/')}@{quote(ver)}"

        if eco == "pypi":
            return f"pkg:pypi/{quote(comp)}@{quote(ver)}"

        return None

    def _best_effort_key_from_purl(self, coord: str) -> Optional[_CoordKey]:
        if not coord or "@" not in coord:
            return None

        c = coord.strip()
        if c.startswith("pkg:"):
            c = c[4:]

        try:
            left, version = c.split("@", 1)
        except ValueError:
            return None

        version = version.split("?", 1)[0].split("#", 1)[0].strip()
        if not version:
            return None

        parts = left.split("/", 1)
        if len(parts) < 2:
            return None

        ptype = parts[0].lower()
        rest = parts[1]

        eco_map = {
            "maven": "maven",
            "npm": "npm",
            "pypi": "pypi",
            "nuget": "nuget",
        }
        eco = eco_map.get(ptype)
        if not eco:
            return None

        if eco == "maven":
            if "/" not in rest:
                return None
            group, artifact = rest.split("/", 1)
            return _CoordKey(eco, f"{group}:{artifact}", version)

        return _CoordKey(eco, rest, version)

    # ------------------------------------------------------------
    # Identifier extraction helpers
    # ------------------------------------------------------------

    def _extract_cve(self, vuln: Dict[str, Any], *, fallback_text: str) -> Optional[str]:
        for k in ("cve", "cveId", "cve_id"):
            v = vuln.get(k)
            if isinstance(v, str) and v.upper().startswith("CVE-"):
                return normalize_identifier(v)

        refs = vuln.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        for r in refs:
            if isinstance(r, str) and "CVE-" in r:
                c = self._find_token_with_prefix(r, "CVE-")
                if c:
                    return normalize_identifier(c)

        if "CVE-" in fallback_text:
            c = self._find_token_with_prefix(fallback_text, "CVE-")
            if c:
                return normalize_identifier(c)

        return None

    def _extract_ghsa(self, vuln: Dict[str, Any], *, fallback_text: str) -> Optional[str]:
        refs = vuln.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        for r in refs:
            if isinstance(r, str) and "GHSA-" in r:
                g = self._find_token_with_prefix(r, "GHSA-")
                if g:
                    return normalize_identifier(g)

        if "GHSA-" in fallback_text:
            g = self._find_token_with_prefix(fallback_text, "GHSA-")
            if g:
                return normalize_identifier(g)

        return None

    def _find_token_with_prefix(self, text: str, prefix: str) -> Optional[str]:
        if not text:
            return None
        i = text.find(prefix)
        if i < 0:
            return None
        j = i
        while j < len(text) and (text[j].isalnum() or text[j] in "-"):
            j += 1
        token = text[i:j]
        return token if token.startswith(prefix) else None

    # ------------------------------------------------------------
    # Small utilities
    # ------------------------------------------------------------

    def _chunks(self, xs: List[str], n: int) -> List[List[str]]:
        return [xs[i:i + n] for i in range(0, len(xs), n)]

    def _sleep_backoff(self, attempt: int, honor_retry_after: Optional[requests.Response] = None) -> None:
        if honor_retry_after is not None:
            ra = honor_retry_after.headers.get("Retry-After")
            if ra:
                try:
                    sec = float(ra)
                    time.sleep(min(sec, 60.0))
                    return
                except Exception:
                    pass

        delay = self.retry_backoff_s * attempt
        time.sleep(min(delay, 30.0))
