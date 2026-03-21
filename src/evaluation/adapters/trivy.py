import json
import os
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from evaluation.adapters.base import VulnerabilityToolAdapter
from evaluation.core.model import Finding
from evaluation.core.ecosystems import ECOSYSTEMS
from evaluation.core.normalization import normalize_identifier

log = logging.getLogger("evaluation.adapters.trivy")


class TrivyAdapter(VulnerabilityToolAdapter):
    """
    Trivy adapter using SBOM-based scanning.

    Semantics aligned with SnykAdapter:
    - project-centric
    - PURL-based ecosystem inference
    - identifier-based (CVE / GHSA)
    - canonical deduplication
    - no matching logic in adapter
    """

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        env = config.get("env", {})
        self.enabled = True

        self.trivy_bin = (
            env.get("TRIVY_BIN")
            or os.environ.get("TRIVY_BIN")
            or "/usr/local/bin/trivy"
        )

        self.sbom_file = (
            env.get("TRIVY_SBOM_FILE")
            or os.environ.get("TRIVY_SBOM_FILE")
        )

        if not self.sbom_file or not Path(self.sbom_file).exists():
            log.warning("Trivy adapter disabled: SBOM file missing")
            self.enabled = False
            return

        if not Path(self.trivy_bin).exists():
            log.warning("Trivy adapter disabled: TRIVY_BIN invalid")
            self.enabled = False
            return

        log.info("Initialized Trivy adapter (SBOM-based)")
        log.info("  sbom_file : %s", self.sbom_file)
        log.info("  trivy_bin : %s", self.trivy_bin)

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    def name(self) -> str:
        return "trivy"

    def supports_security_findings(self) -> bool:
        return self.enabled

    def supports_fp_heuristic(self) -> bool:
        return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_findings(self) -> List[Finding]:
        if not self.enabled:
            log.info("Trivy adapter disabled – returning no findings")
            return []

        data = self._run_trivy_sbom()
        if not data:
            return []

        return self._extract_findings(data)

    def load_findings_for_component(
        self,
        ecosystem: str,
        component: str,
        version: str,
    ) -> List[Finding]:
        return []

    # ------------------------------------------------------------------
    # CLI Execution
    # ------------------------------------------------------------------

    def _run_trivy_sbom(self) -> Dict[str, Any]:
        sbom_path = str(Path(self.sbom_file).resolve())

        cmd = [
            self.trivy_bin,
            "sbom",
            "--format",
            "json",
            sbom_path,
        ]

        log.info("Running Trivy SBOM scan")
        log.info("Command: %s", " ".join(cmd))

        try:
            p = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
            )
        except Exception as e:
            log.error("Failed to execute Trivy: %s", e)
            return {}

        stdout = (p.stdout or "").strip()
        stderr = (p.stderr or "").strip()

        self._log_cli_call(
            tool="trivy",
            command=cmd,
            exit_code=p.returncode,
            stdout=stdout,
            stderr=stderr,
        )

        if not stdout:
            return {}

        try:
            return json.loads(stdout)
        except Exception:
            log.error("Invalid JSON from Trivy")
            return {}

    # ------------------------------------------------------------------
    # Normalization (Snyk-equivalent logic)
    # ------------------------------------------------------------------

    def _extract_findings(self, data: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[Tuple[str, str, str, str]] = set()

        results = data.get("Results") or []
        if not isinstance(results, list):
            return findings

        for result in results:
            vulns = result.get("Vulnerabilities") or []
            if not isinstance(vulns, list):
                continue

            for v in self.iter_with_progress(
                vulns,
                desc="Trivy normalization",
                unit="vulnerability",
            ):
                pkg_name = v.get("PkgName")
                version = v.get("InstalledVersion")
                purl = (
                    v.get("PkgIdentifier", {})
                    .get("PURL")
                )

                if not pkg_name or not version or not purl:
                    continue

                ecosystem = self._infer_ecosystem_from_purl(purl)
                if not ecosystem:
                    continue

                # Maven normalization like Snyk
                if ecosystem == "maven" and "/" in pkg_name:
                    pkg_name = pkg_name.replace("/", ":", 1)

                cve, ghsa = self._extract_identifiers(v)

                if not cve and not ghsa:
                    continue

                canonical_id = cve or ghsa
                key = (ecosystem, pkg_name, version, canonical_id)

                if key in seen:
                    continue
                seen.add(key)

                affected_range = self._extract_affected_range(v)

                description = (v.get("Title") or "").split("\n")[0].strip()

                findings.append(
                    Finding(
                        ecosystem=ecosystem,
                        component=pkg_name,
                        version=version,
                        cve=cve,
                        ghsa=ghsa,
                        osv_id=None,
                        description=description,
                        source="trivy",
                        affected_version_range=affected_range,
                    )
                )

        log.info("Trivy: normalized %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Identifier extraction (like Snyk)
    # ------------------------------------------------------------------

    def _extract_identifiers(
        self,
        vuln: Dict[str, Any],
    ) -> Tuple[Optional[str], Optional[str]]:

        vuln_id = vuln.get("VulnerabilityID") or ""

        cve = None
        ghsa = None

        if vuln_id.startswith("CVE-"):
            cve = normalize_identifier(vuln_id)
        elif vuln_id.startswith("GHSA-"):
            ghsa = normalize_identifier(vuln_id)

        # Fallback: search GHSA in references
        if not ghsa:
            for ref in vuln.get("References", []) or []:
                if isinstance(ref, str) and "GHSA-" in ref:
                    ghsa = normalize_identifier(ref.split("/")[-1])
                    break

        return cve, ghsa

    # ------------------------------------------------------------------
    # Range extraction
    # ------------------------------------------------------------------

    def _extract_affected_range(
        self,
        vuln: Dict[str, Any],
    ) -> Optional[str]:

        fixed = vuln.get("FixedVersion")
        if fixed:
            return f"< {fixed}"

        return None

    # ------------------------------------------------------------------
    # PURL-based ecosystem inference (identical strategy as Snyk)
    # ------------------------------------------------------------------

    def _infer_ecosystem_from_purl(self, purl: str) -> Optional[str]:
        purl = (purl or "").lower()

        for eco, cfg in ECOSYSTEMS.items():
            if purl.startswith(f"pkg:{cfg.purl}/"):
                return eco

        return None