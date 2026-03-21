from __future__ import annotations

import logging
from typing import List, Optional
from urllib.parse import unquote

import requests

from evaluation.adapters.base import VulnerabilityToolAdapter
from evaluation.core.model import Finding

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

log = logging.getLogger("evaluation.adapters.osv")


class OSVAdapter(VulnerabilityToolAdapter):
    """
    OSV validation adapters (GROUND TRUTH CONFIRMATION MODE).

    Rule-accurate semantics (per methodology):
    - Ground Truth is authoritative
    - OSV is queried per PACKAGE (not per version)
    - Version checks are done locally
    - Identifier match uses set intersection: I ∩ I' ≠ ∅
      where I  = {gt.cve, gt.ghsa, gt.osv_id} \ {None}
            I' = {osv.id} ∪ osv.aliases
    """

    # ---------------------------------------------------------
    # Adapter capabilities
    # ---------------------------------------------------------

    def name(self) -> str:
        return "osv"

    def supports_security_findings(self) -> bool:
        return True

    def supports_fp_heuristic(self) -> bool:
        return False

    # ---------------------------------------------------------
    # Required abstract API (MUST exist)
    # ---------------------------------------------------------

    def load_findings_for_component(
        self,
        *,
        ecosystem: str,
        component: str,
        version: str,
    ) -> List[Finding]:
        """
        Not used: OSV is evaluated GT-row-wise via load_findings().
        """
        return []

    # ---------------------------------------------------------
    # Public entry point
    # ---------------------------------------------------------

    def load_findings(self) -> List[Finding]:
        findings: List[Finding] = []
        errors = 0

        for gt in self.iter_with_progress(
            self.config["ground_truth"],
            desc="OSV ground-truth validation",
            unit="vulnerability",
        ):
            try:
                f = self._check_ground_truth_row(gt)
                if f is not None:
                    findings.append(f)
            except Exception as e:
                errors += 1
                log.error(
                    "OSV check failed | %s:%s:%s | %s",
                    gt.ecosystem,
                    gt.component,
                    gt.version,
                    e,
                )

        # OSV is a reference adapters: silent total failure is not acceptable
        if errors > 0 and not findings:
            raise RuntimeError("OSV adapters failed completely; no findings produced")

        return self._dedup_to_gt_granularity(findings)

    # ---------------------------------------------------------
    # Core logic
    # ---------------------------------------------------------

    def _check_ground_truth_row(self, gt: Finding) -> Optional[Finding]:
        """
        Returns:
          - Finding with match_type="EXACT" or "RANGE"
          - None if OSV does not confirm the GT entry
        """

        pkg_name = self._osv_package_name(gt)
        if not pkg_name:
            return None

        payload = {
            "package": {
                "ecosystem": self._map_ecosystem(gt.ecosystem),
                "name": pkg_name,
            }
        }

        r = self._api_call(
            session=requests.Session(),
            method="POST",
            url=OSV_QUERY_URL,
            json_body=payload,
            timeout=30,
        )

        if r.status_code != 200:
            return None

        vulns = (r.json() or {}).get("vulns", []) or []

        # Ground-truth identifier set (I)
        gt_ids = {x for x in (gt.cve, gt.ghsa, gt.osv_id) if x}

        for v in vulns:
            osv_id = v.get("id")
            aliases = set(v.get("aliases", []) or [])

            # Tool identifier set (I')
            tool_ids = set()
            if osv_id:
                tool_ids.add(osv_id)
            tool_ids |= aliases

            # -------------------------------------------------
            # Identifier match (Rule-accurate): I ∩ I' ≠ ∅
            # If GT has no IDs (shouldn't happen), do not confirm.
            # -------------------------------------------------
            if not gt_ids:
                continue
            if gt_ids.isdisjoint(tool_ids):
                continue

            # -------------------------------------------------
            # Version evaluation (Exact or Range)
            # -------------------------------------------------
            for aff in v.get("affected", []):
                versions = set(aff.get("versions", []) or [])
                ranges = aff.get("ranges", []) or []

                # EXACT: v' == v (explicit listing)
                if gt.version in versions:
                    return self._build_finding(
                        gt=gt,
                        osv=v,
                        match_type="EXACT",
                        affected_range=None,
                    )

                # RANGE: v ∈ range(v')
                for rr in ranges:
                    spec = self._events_to_spec(rr.get("events", []))
                    if spec and self._version_in_spec(gt.version, spec):
                        return self._build_finding(
                            gt=gt,
                            osv=v,
                            match_type="RANGE",
                            affected_range=spec,
                        )

        return None

    # ---------------------------------------------------------
    # Deduplication
    # ---------------------------------------------------------

    def _dedup_to_gt_granularity(self, findings: List[Finding]) -> List[Finding]:
        """
        Collapse multiple OSV advisories that represent the same GT vulnerability.
        Dedup key uses (ecosystem, component, version, canonical id).
        """
        seen = set()
        out: List[Finding] = []

        for f in findings:
            key = (
                f.ecosystem,
                f.component,
                f.version,
                f.cve or f.ghsa or f.osv_id,  # prefer stable canonical ids
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(f)

        return out

    # ---------------------------------------------------------
    # Finding builder
    # ---------------------------------------------------------

    def _build_finding(
        self,
        *,
        gt: Finding,
        osv: dict,
        match_type: str,
        affected_range: Optional[str],
    ) -> Finding:
        aliases = set(osv.get("aliases", []) or [])
        osv_id = osv.get("id")

        # Keep GT identifiers if present (GT-authoritative)
        cve = gt.cve
        ghsa = gt.ghsa

        # Fill missing ids from OSV aliases (optional)
        if not cve:
            for a in aliases:
                if a.startswith("CVE-"):
                    cve = a
                    break
        if not ghsa:
            for a in aliases:
                if a.startswith("GHSA-"):
                    ghsa = a
                    break

        return Finding(
            ecosystem=gt.ecosystem,
            component=gt.component,
            version=gt.version,
            purl=gt.purl,
            cve=cve,
            ghsa=ghsa,
            osv_id=osv_id,
            description=osv.get("summary") or osv.get("details", ""),
            affected_version_range=affected_range,
            source="osv",
            match_type=match_type,
        )

    # ---------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------

    def _map_ecosystem(self, eco: str) -> str:
        return {
            "maven": "Maven",
            "npm": "npm",
            "pypi": "PyPI",
            "nuget": "NuGet",
        }.get(eco.lower(), eco)

    def _osv_package_name(self, gt: Finding) -> Optional[str]:
        """
        Derive canonical OSV package name.

        IMPORTANT:
        - Prefer PURL when available
        - Decode percent-encoding (e.g., npm scopes %40 -> @)
        """

        # Maven: pkg:maven/group/artifact@version  -> group:artifact
        if gt.ecosystem == "maven" and gt.purl:
            try:
                p = gt.purl.split("pkg:maven/", 1)[1]
                p = unquote(p)
                group, rest = p.split("/", 1)
                artifact = rest.split("@", 1)[0]
                return f"{group}:{artifact}"
            except Exception:
                return None

        # npm: pkg:npm/name@version OR pkg:npm/%40scope/name@version -> @scope/name
        if gt.ecosystem == "npm" and gt.purl:
            try:
                p = gt.purl.split("pkg:npm/", 1)[1]
                p = unquote(p)
                return p.split("@", 1)[0]
            except Exception:
                return None

        # NuGet: pkg:nuget/Name@version
        if gt.ecosystem == "nuget" and gt.purl:
            try:
                p = gt.purl.split("pkg:nuget/", 1)[1]
                p = unquote(p)
                return p.split("@", 1)[0]
            except Exception:
                return None

        # PyPI: OSV expects package name as-is
        if gt.ecosystem == "pypi":
            return gt.component

        # Fallback (if GT already stores OSV-canonical package name)
        if gt.component:
            return gt.component

        return None

    def _events_to_spec(self, events: list[dict]) -> Optional[str]:
        introduced = None
        fixed = None
        last_affected = None

        for e in events:
            if "introduced" in e:
                introduced = e["introduced"]
            if "fixed" in e:
                fixed = e["fixed"]
            if "last_affected" in e:
                last_affected = e["last_affected"]

        parts = []

        # introduced
        if introduced and introduced != "0":
            parts.append(f">={introduced}")

        # upper bound
        if fixed:
            parts.append(f"<{fixed}")
        elif last_affected:
            parts.append(f"<={last_affected}")

        # Special case: introduced == "0" and upper bound exists
        if introduced == "0" and (fixed or last_affected):
            pass  # upper bound already handled

        return ",".join(parts) if parts else None

    def _version_in_spec(self, version: str, spec: str) -> bool:
        """
        Conservative evaluation: returns False on any parsing error.
        """
        from packaging.version import Version, InvalidVersion
        from packaging.specifiers import SpecifierSet, InvalidSpecifier

        try:
            v = Version(version)
        except InvalidVersion:
            return False

        try:
            s = SpecifierSet(spec)
        except InvalidSpecifier:
            return False

        return v in s
