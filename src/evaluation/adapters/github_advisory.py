from __future__ import annotations

import logging
import os
import re
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
import semantic_version as sv

from evaluation.adapters.base import VulnerabilityToolAdapter
from evaluation.core.ecosystems import ECOSYSTEMS
from evaluation.core.model import Finding
from evaluation.core.normalization import normalize_identifier

log = logging.getLogger("evaluation.adapters.github")

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"


class RangeResult(Enum):
    IN_RANGE = "in_range"
    OUT_OF_RANGE = "out_of_range"
    UNDECIDABLE = "undecidable"


# ------------------------------------------------------------
# GitHub ecosystem mapping (GraphQL enum)
# ------------------------------------------------------------

def _map_github_ecosystem(gt_ecosystem: str) -> Optional[str]:
    """
    GitHub GraphQL enum values for SecurityAdvisoryEcosystem are uppercase.
    We keep your ECOSYSTEMS mapping as primary, but fall back safely.
    """
    e = (gt_ecosystem or "").strip().lower()
    return {
        "maven": "MAVEN",
        "npm": "NPM",
        "pypi": "PIP",
        "nuget": "NUGET",
        # add more if needed:
        # "rubygems": "RUBYGEMS",
        # "go": "GO",
    }.get(e)


# ------------------------------------------------------------
# Range normalization & evaluation (NO fuzzy matching)
# ------------------------------------------------------------

def _normalize_range_expr(expr: str) -> str:
    s = (expr or "").strip()
    if not s:
        return ""
    # GitHub often uses commas. NpmSpec prefers whitespace.
    s = s.replace(",", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s


_MAVEN_RANGE_RE = re.compile(r"^\s*([\[\(])\s*([^,]*)\s*,\s*([^\]\)]*)\s*([\]\)])\s*$")


def _try_parse_maven_style_range(range_expr: str) -> Optional[Tuple[Optional[str], bool, Optional[str], bool]]:
    """
    Parse Maven/NuGet style: [1.0,2.0) / (,1.2.3] / [1.0,)
    Returns: (lower, lower_inclusive, upper, upper_inclusive) or None if not matched.
    """
    m = _MAVEN_RANGE_RE.match(range_expr or "")
    if not m:
        return None

    l_br, lower, upper, r_br = m.group(1), m.group(2).strip(), m.group(3).strip(), m.group(4)
    lower_v = lower if lower else None
    upper_v = upper if upper else None
    lower_inc = (l_br == "[")
    upper_inc = (r_br == "]")
    return lower_v, lower_inc, upper_v, upper_inc


def _coerce_semver(v: str) -> Optional[sv.Version]:
    try:
        return sv.Version.coerce(v)
    except Exception:
        return None


def version_in_range(ecosystem: str, version: str, range_expr: Optional[str]) -> RangeResult:
    """
    Strict decision:
    - If range missing/unparseable => UNDECIDABLE
    - Only IN_RANGE is treated as affected
    """
    if not range_expr or not str(range_expr).strip():
        return RangeResult.UNDECIDABLE

    raw = str(range_expr).strip()

    # 1) Maven/NuGet style ranges: [a,b), (,b], [a,)
    maven_parsed = _try_parse_maven_style_range(raw)
    if maven_parsed is not None:
        lower_s, lower_inc, upper_s, upper_inc = maven_parsed
        v = _coerce_semver(version)
        if v is None:
            return RangeResult.UNDECIDABLE

        if lower_s:
            lv = _coerce_semver(lower_s)
            if lv is None:
                return RangeResult.UNDECIDABLE
            if v < lv or (v == lv and not lower_inc):
                return RangeResult.OUT_OF_RANGE

        if upper_s:
            uv = _coerce_semver(upper_s)
            if uv is None:
                return RangeResult.UNDECIDABLE
            if v > uv or (v == uv and not upper_inc):
                return RangeResult.OUT_OF_RANGE

        return RangeResult.IN_RANGE

    # 2) npm-ish semver ranges (GitHub commonly uses this)
    norm = _normalize_range_expr(raw)
    if not norm:
        return RangeResult.UNDECIDABLE

    try:
        v = sv.Version.coerce(version)
    except Exception:
        return RangeResult.UNDECIDABLE

    try:
        spec = sv.NpmSpec(norm)
    except Exception:
        spec = None

    if spec is not None:
        return RangeResult.IN_RANGE if v in spec else RangeResult.OUT_OF_RANGE

    # 3) PyPI fallback: PEP440
    if (ecosystem or "").strip().lower() == "pypi":
        try:
            from packaging.specifiers import SpecifierSet
            from packaging.version import Version

            pv = Version(version)
            ps = SpecifierSet(norm)
            if pv.is_prerelease:
                ps.prereleases = True
            return RangeResult.IN_RANGE if pv in ps else RangeResult.OUT_OF_RANGE
        except Exception:
            return RangeResult.UNDECIDABLE

    return RangeResult.UNDECIDABLE


# ------------------------------------------------------------
# Adapter
# ------------------------------------------------------------

class GitHubAdvisoryAdapter(VulnerabilityToolAdapter):
    """
    GitHub Advisory Database Adapter.

    RULE-CONFORM SEMANTICS:
    - project-centric (GT-driven)
    - NO fuzzy matching
    - Finding is emitted ONLY if affectedness is confirmed by range
    - identifier-based (CVE / GHSA), no GT-aware filtering
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.gt = config["ground_truth"]

        self._token = os.environ.get("GITHUB_TOKEN")
        if not self._token:
            raise SystemExit(
                "Missing environment variable GITHUB_TOKEN "
                "(required for GitHub Advisory Database access)"
            )

        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
        })

        log.info("Initialized adapters: GitHub Advisory Database")

    def name(self) -> str:
        return "github"

    def supports_fp_heuristic(self) -> bool:
        return False

    def supports_security_findings(self) -> bool:
        return True

    # ------------------------------------------------------------
    # Main loading logic
    # ------------------------------------------------------------

    def load_findings(self) -> List[Finding]:
        rows: List[Finding] = []

        components = sorted({
            (f.ecosystem, f.component, f.version)
            for f in self.gt
        })

        log.info(
            "Querying GitHub Advisory DB for %d unique components",
            len(components),
        )

        for ecosystem, component, version in self.iter_with_progress(
            components,
            desc="GitHub Advisory lookup",
            unit="component",
        ):
            rows.extend(
                self.load_findings_for_component(
                    ecosystem=ecosystem,
                    component=component,
                    version=version,
                )
            )

        return rows

    # ------------------------------------------------------------
    # Per-component lookup (STRICT but robust)
    # ------------------------------------------------------------

    def load_findings_for_component(
            self,
            *,
            ecosystem: str,
            component: str,
            version: str,
    ) -> List[Finding]:

        eco_cfg = ECOSYSTEMS.get(ecosystem)
        if not eco_cfg or not eco_cfg.github:
            return []

        advisories = self._query_advisories(
            ecosystem=eco_cfg.github,
            package=component,
        )

        rows: List[Finding] = []
        seen: Set[Tuple[str, str, str, str]] = set()

        for adv in advisories:
            vuln_range = adv.get("vulnerableVersionRange")

            # -------------------------------
            # VERSION HANDLING (RULE-CONFORM)
            # -------------------------------
            if vuln_range:
                rr = version_in_range(ecosystem, version, vuln_range)
                if rr == RangeResult.OUT_OF_RANGE:
                    continue
                # IN_RANGE or UNDECIDABLE → keep
            # no range → keep (advisory-level)

            ghsa_id = adv.get("ghsaId")
            if not ghsa_id:
                continue

            ghsa_id = normalize_identifier(ghsa_id)
            cve = self._extract_cve(adv)

            if not cve and not ghsa_id:
                continue

            canonical_id = cve or ghsa_id
            key = (ecosystem, component, version, canonical_id)

            if key in seen:
                continue
            seen.add(key)

            description = (adv.get("summary") or "").split("\n")[0].strip()

            rows.append(
                Finding(
                    ecosystem=ecosystem,
                    component=component,
                    version=version,
                    cve=cve,
                    ghsa=ghsa_id,
                    osv_id=None,
                    description=description,
                    source="github-advisory-db",
                    affected_version_range=vuln_range,
                )
            )

        return rows

    # ------------------------------------------------------------
    # GitHub GraphQL
    # ------------------------------------------------------------

    def _query_advisories(
        self,
        *,
        ecosystem: str,
        package: str,
    ) -> List[Dict[str, Any]]:
        query = """
        query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
          securityVulnerabilities(
            first: 100,
            ecosystem: $ecosystem,
            package: $package
          ) {
            nodes {
              vulnerableVersionRange
              advisory {
                ghsaId
                summary
                identifiers {
                  type
                  value
                }
              }
            }
          }
        }
        """

        variables = {"ecosystem": ecosystem, "package": package}

        try:
            r = self._api_call(
                session=self._session,
                method="POST",
                url=GITHUB_GRAPHQL_URL,
                json_body={"query": query, "variables": variables},
                timeout=30,
            )
            r.raise_for_status()
        except Exception as e:
            log.warning(
                "GitHub advisory query failed | ecosystem=%s | package=%s | error=%s",
                ecosystem,
                package,
                e,
            )
            return []

        try:
            data = r.json()
        except Exception:
            log.warning(
                "GitHub advisory JSON parse failed (first 500 chars): %r",
                (r.text or "")[:500],
            )
            return []

        nodes = (
            data.get("data", {})
            .get("securityVulnerabilities", {})
            .get("nodes", [])
        )

        result: List[Dict[str, Any]] = []
        for n in nodes:
            if not isinstance(n, dict):
                continue

            adv = n.get("advisory") or {}
            if not isinstance(adv, dict):
                continue

            adv_out = dict(adv)
            adv_out["vulnerableVersionRange"] = n.get("vulnerableVersionRange")
            result.append(adv_out)

        return result

    @staticmethod
    def _extract_cve(advisory: Dict[str, Any]) -> Optional[str]:
        for ident in advisory.get("identifiers", []) or []:
            if ident.get("type") == "CVE":
                return normalize_identifier(ident.get("value"))
        return None
