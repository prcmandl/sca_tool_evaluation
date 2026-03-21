import logging
import requests
from typing import List, Dict, Any, Optional, Tuple, Set
from urllib.parse import unquote

from evaluation.adapters.base import VulnerabilityToolAdapter
from evaluation.core.model import Finding
from evaluation.core.ecosystems import ECOSYSTEMS
from evaluation.core.normalization import (
    normalize_component,
    normalize_version,
    normalize_identifier,
)

log = logging.getLogger(""
                        "adapters.dtrack")


class DependencyTrackAdapter(VulnerabilityToolAdapter):
    """
    Adapter for OWASP Dependency-Track.

    RULE-CONFORM SEMANTICS:
    - project-centric (Dependency-Track project)
    - identifier-based findings only (CVE / GHSA)
    - canonical vulnerability deduplication
    - no matching logic in adapters
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        env = config["env"]
        self.base_url = (env.get("DTRACK_URL") or "").rstrip("/")
        self.api_key = env.get("DTRACK_API_KEY")
        self.project_name = env.get("DTRACK_PROJECT_NAME")

        if not self.base_url or not self.api_key or not self.project_name:
            raise SystemExit(
                "Missing environment variables for Dependency-Track:\n"
                "  DTRACK_API_KEY\n"
                "  DTRACK_URL\n"
                "  DTRACK_PROJECT_NAME"
            )

        self.s = requests.Session()
        self.s.headers["X-Api-Key"] = self.api_key

        self._cache_all_findings: Optional[List[Finding]] = None

        log.info("Dependency-Track adapters initialized")

    def name(self) -> str:
        return "dtrack"

    def supports_security_findings(self) -> bool:
        return True

    def supports_fp_heuristic(self) -> bool:
        return False

    # =========================================================
    # PUBLIC API
    # =========================================================

    def load_findings(self) -> List[Finding]:
        if self._cache_all_findings is not None:
            return self._cache_all_findings

        project_uuid = self._get_project_uuid(self.project_name)
        raw = self._get_findings(project_uuid)
        findings = self._extract_findings(raw)

        self._cache_all_findings = findings
        return findings

    def load_findings_for_component(
        self,
        *,
        ecosystem: str,
        component: str,
        version: str,
    ) -> List[Finding]:
        return [
            f for f in self.load_findings()
            if f.ecosystem == ecosystem
            and f.component == component
            and f.version == version
        ]

    # =========================================================
    # INTERNAL API
    # =========================================================

    def _get_project_uuid(self, name: str) -> str:
        r = self._api_call(
            session=self.s,
            method="GET",
            url=f"{self.base_url}/api/v1/project",
            params={"name": name},
            timeout=30,
        )
        r.raise_for_status()

        data = r.json()
        if not data:
            raise RuntimeError(
                f"Dependency-Track project not found or not accessible: {name}"
            )

        return data[0]["uuid"]

    def _get_findings(self, project_uuid: str) -> List[dict]:
        r = self._api_call(
            session=self.s,
            method="GET",
            url=f"{self.base_url}/api/v1/finding/project/{project_uuid}",
            timeout=60,
        )
        r.raise_for_status()
        return r.json()

    # =========================================================
    # NORMALIZATION HELPERS
    # =========================================================

    @staticmethod
    def _strip_qualifiers_and_subpath(version: str) -> str:
        # purl version may include qualifiers (?...) or subpath (#...)
        v = version.split("?", 1)[0]
        v = v.split("#", 1)[0]
        return v.strip()

    @staticmethod
    def _maven_name_from_purl_name(raw_name: str) -> str:
        # raw_name from purl is typically "group/artifact"
        # Must preserve group for component-identity with ground truth.
        if "/" in raw_name:
            group, artifact = raw_name.split("/", 1)
            return f"{group}:{artifact}"
        return raw_name

    # =========================================================
    # NORMALIZATION
    # =========================================================

    def _extract_findings(self, findings: List[dict]) -> List[Finding]:
        rows: List[Finding] = []
        seen: Set[Tuple[str, str, str, str]] = set()

        for f in self.iter_with_progress(
            findings,
            desc="Dependency-Track normalization",
            unit="finding",
        ):
            comp = f.get("component") or {}
            vuln = f.get("vulnerability") or {}

            purl = (comp.get("purl") or "").strip()
            if not purl:
                continue

            purl_l = purl.lower()
            matched = False

            for eco, eco_cfg in ECOSYSTEMS.items():
                prefix = f"pkg:{eco_cfg.purl}/"
                if not purl_l.startswith(prefix):
                    continue

                nv = purl[len(prefix):]
                if "@" not in nv:
                    continue

                raw_name, raw_version = nv.split("@", 1)

                # decode url-encoding (e.g., %40scope for npm)
                raw_name = unquote(raw_name).strip()
                raw_version = unquote(raw_version).strip()

                # strip qualifiers/subpath from version (common in DTrack purls)
                raw_version = self._strip_qualifiers_and_subpath(raw_version)

                # IMPORTANT: Maven needs group:artifact (not just artifact)
                if eco == "maven":
                    raw_name = self._maven_name_from_purl_name(raw_name)

                name = normalize_component(eco, raw_name)
                version = normalize_version(raw_version)

                raw_id = (vuln.get("vulnId") or "").strip()
                cve = None
                ghsa = None

                if raw_id.upper().startswith("CVE-"):
                    cve = normalize_identifier(raw_id)
                elif raw_id.upper().startswith("GHSA-"):
                    ghsa = normalize_identifier(raw_id)

                # RULE: require identifier
                if not cve and not ghsa:
                    continue

                canonical_id = cve or ghsa
                key = (eco, name, version, canonical_id)

                if key in seen:
                    continue
                seen.add(key)

                affected_range = (
                    vuln.get("vulnerableVersions")
                    or vuln.get("affectedVersionRange")
                )

                description = (
                    vuln.get("description") or ""
                ).split("\n")[0].strip()

                rows.append(
                    Finding(
                        ecosystem=eco,
                        component=name,
                        version=version,
                        cve=cve,
                        ghsa=ghsa,
                        osv_id=None,
                        description=description,
                        source="dependency-track",
                        cve_cpes=vuln.get("cwes"),
                        affected_version_range=affected_range,
                    )
                )

                matched = True
                break

            if not matched:
                continue

        log.info(
            "Dependency-Track normalization complete | kept=%d",
            len(rows),
        )

        return rows
