from __future__ import annotations

import json
import os
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from evaluation.adapters.base import VulnerabilityToolAdapter
from evaluation.core.model import Finding
from evaluation.core.ecosystems import ECOSYSTEMS
from evaluation.core.normalization import normalize_identifier

log = logging.getLogger("evaluation.adapters.snyk")


class SnykAdapter(VulnerabilityToolAdapter):
    """
    Snyk adapter using SBOM-based scanning.

    Semantics:
    - project-centric (SBOM describes exact project state)
    - identifier-based findings only (CVE / GHSA)
    - canonical vulnerability deduplication
    - ranges allowed but not required
    - no matching logic in adapter
    """

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        env = config.get("env", {})
        self.enabled = True

        self.snyk_bin = (
            env.get("SNYK_BIN")
            or os.environ.get("SNYK_BIN")
            or "/usr/local/bin/snyk"
        )

        self.sbom_file = (
            env.get("SNYK_SBOM_FILE")
            or os.environ.get("SNYK_SBOM_FILE")
        )

        self.bash_path = (
            env.get("BASH_PATH")
            or os.environ.get("BASH_PATH")
            or "/bin/bash"
        )

        self.bash_script = (
            env.get("SNYK_BASH_SCRIPT")
            or os.environ.get("SNYK_BASH_SCRIPT")
            or str(Path(__file__).resolve().parents[3] / "tools" / "evaluate_snyk.sh")
        )

        self.max_attempts = int(
            env.get("SNYK_CLI_MAX_ATTEMPTS")
            or os.environ.get("SNYK_CLI_MAX_ATTEMPTS")
            or "3"
        )

        self.retry_sleep = float(
            env.get("SNYK_CLI_RETRY_SLEEP")
            or os.environ.get("SNYK_CLI_RETRY_SLEEP")
            or "2"
        )

        self.timeout_seconds = int(
            env.get("SNYK_CLI_TIMEOUT")
            or os.environ.get("SNYK_CLI_TIMEOUT")
            or "180"
        )

        # ------------------------------------------------------------
        # Validation
        # ------------------------------------------------------------
        if not self.sbom_file or not Path(self.sbom_file).exists():
            log.warning("Snyk adapter disabled: SBOM file missing")
            self.enabled = False
            return

        if not self.bash_script or not Path(self.bash_script).exists():
            log.warning("Snyk adapter disabled: SNYK_BASH_SCRIPT missing")
            self.enabled = False
            return

        if not Path(self.bash_path).exists():
            log.warning("Snyk adapter disabled: BASH_PATH invalid")
            self.enabled = False
            return

        log.info("Initialized Snyk adapters (SBOM-based)")
        log.info("  sbom_file   : %s", self.sbom_file)
        log.info("  bash_script : %s", self.bash_script)
        log.info("  max_attempts: %s", self.max_attempts)
        log.info("  timeout_sec : %s", self.timeout_seconds)

    # ------------------------------------------------------------------
    # Adapter metadata
    # ------------------------------------------------------------------

    def name(self) -> str:
        return "snyk"

    def supports_security_findings(self) -> bool:
        return self.enabled

    def supports_fp_heuristic(self) -> bool:
        return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_findings(self) -> List[Finding]:
        if not self.enabled:
            log.info("Snyk adapter disabled – returning no findings")
            return []

        data = self._run_snyk_via_bash_script()
        findings = self._extract_findings(data)

        log.info("Snyk: normalized %d findings", len(findings))
        return findings

    def load_findings_for_component(
        self,
        ecosystem: str,
        component: str,
        version: str,
    ) -> List[Finding]:
        return []

    # ------------------------------------------------------------------
    # Bash-script execution
    # ------------------------------------------------------------------

    def _run_snyk_via_bash_script(self) -> Dict[str, Any]:
        sbom_path = str(Path(self.sbom_file).resolve())

        cmd = [
            self.bash_path,
            self.bash_script,
            sbom_path,
        ]

        log.info("Running Snyk via Bash script")
        log.info("Bash command: %s", " ".join(cmd))

        last_error: Optional[str] = None

        for attempt in range(1, self.max_attempts + 1):
            log.info("Snyk attempt %d/%d", attempt, self.max_attempts)

            try:
                p = subprocess.run(
                    cmd,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                )
            except subprocess.TimeoutExpired as e:
                stdout = self._safe_text(getattr(e, "stdout", None)).strip()
                stderr = self._safe_text(getattr(e, "stderr", None)).strip()

                self._log_cli_call(
                    tool="snyk",
                    command=cmd,
                    exit_code=-1,
                    stdout=stdout,
                    stderr=stderr or f"Timeout after {self.timeout_seconds}s",
                )

                last_error = f"Snyk CLI timed out after {self.timeout_seconds}s"
                log.error("%s (attempt %d/%d)", last_error, attempt, self.max_attempts)
                if stderr:
                    log.error("STDERR:\n%s", stderr)

                if attempt < self.max_attempts:
                    time.sleep(self.retry_sleep * attempt)
                    continue

                raise RuntimeError(last_error) from e

            except Exception as e:
                last_error = f"Failed to execute Snyk Bash script: {e}"
                log.error("%s (attempt %d/%d)", last_error, attempt, self.max_attempts)

                if attempt < self.max_attempts:
                    time.sleep(self.retry_sleep * attempt)
                    continue

                raise RuntimeError(last_error) from e

            stdout = self._safe_text(p.stdout).strip()
            stderr = self._safe_text(p.stderr).strip()

            self._log_cli_call(
                tool="snyk",
                command=cmd,
                exit_code=p.returncode,
                stdout=stdout,
                stderr=stderr,
            )

            if p.returncode != 0:
                last_error = f"Snyk CLI returned non-zero exit code: {p.returncode}"
                log.error("%s (attempt %d/%d)", last_error, attempt, self.max_attempts)
                if stderr:
                    log.error("STDERR:\n%s", stderr)

                if attempt < self.max_attempts:
                    time.sleep(self.retry_sleep * attempt)
                    continue

                raise RuntimeError(last_error)

            if not stdout:
                last_error = "Snyk returned empty stdout"
                log.error("%s (attempt %d/%d)", last_error, attempt, self.max_attempts)
                if stderr:
                    log.error("STDERR:\n%s", stderr)

                if attempt < self.max_attempts:
                    time.sleep(self.retry_sleep * attempt)
                    continue

                raise RuntimeError(last_error)

            try:
                data = json.loads(stdout)
            except Exception as e:
                last_error = f"Invalid JSON from Snyk (first 500 chars): {stdout[:500]!r}"
                log.error("%s (attempt %d/%d)", last_error, attempt, self.max_attempts)

                if attempt < self.max_attempts:
                    time.sleep(self.retry_sleep * attempt)
                    continue

                raise RuntimeError(last_error) from e

            vulns = data.get("vulnerabilities")
            if not isinstance(vulns, list):
                last_error = "Snyk output has no valid 'vulnerabilities' list"
                log.error("%s (attempt %d/%d)", last_error, attempt, self.max_attempts)

                if attempt < self.max_attempts:
                    time.sleep(self.retry_sleep * attempt)
                    continue

                raise RuntimeError(last_error)

            log.info("Snyk: processing %d vulnerabilities", len(vulns))
            return data

        raise RuntimeError(last_error or "Unknown Snyk execution failure")

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    def _extract_findings(self, data: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[Tuple[str, str, str, str]] = set()

        vulns = data.get("vulnerabilities")
        if not isinstance(vulns, list):
            raise RuntimeError("Snyk output has no 'vulnerabilities' list")

        for v in self.iter_with_progress(
            vulns,
            desc="Snyk normalization",
            unit="vulnerability",
        ):
            if not isinstance(v, dict):
                continue

            raw_component = v.get("packageName") or v.get("name")
            version = v.get("version")
            purl = v.get("packageUrl") or ""

            if not raw_component or not version:
                continue

            ecosystem = self._infer_ecosystem_from_purl(purl)
            if not ecosystem:
                continue

            if ecosystem == "maven" and "/" in raw_component:
                component = raw_component.replace("/", ":", 1)
            else:
                component = raw_component

            identifiers = self._extract_identifiers(v)
            cve = identifiers.get("cve")
            ghsa = identifiers.get("ghsa")

            if not cve and not ghsa:
                continue

            canonical_id = cve or ghsa
            key = (ecosystem, component, version, canonical_id)

            if key in seen:
                continue
            seen.add(key)

            affected_range = self._extract_affected_version_range(v)
            description = (v.get("title") or "").split("\n")[0].strip()

            findings.append(
                Finding(
                    ecosystem=ecosystem,
                    component=component,
                    version=version,
                    cve=cve,
                    ghsa=ghsa,
                    osv_id=None,
                    description=description,
                    source="snyk",
                    affected_version_range=affected_range,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _extract_identifiers(self, vuln: Dict[str, Any]) -> Dict[str, Optional[str]]:
        ids = vuln.get("identifiers") or {}

        cve = None
        ghsa = None

        for c in ids.get("CVE", []) or []:
            if isinstance(c, str) and c.startswith("CVE-"):
                cve = normalize_identifier(c)
                break

        for g in ids.get("GHSA", []) or []:
            if isinstance(g, str) and g.startswith("GHSA-"):
                ghsa = normalize_identifier(g)
                break

        return {
            "cve": cve,
            "ghsa": ghsa,
        }

    def _extract_affected_version_range(
        self,
        vuln: Dict[str, Any],
    ) -> Optional[str]:
        semver = vuln.get("semver")
        if not isinstance(semver, dict):
            return None

        vulnerable = semver.get("vulnerable")
        if isinstance(vulnerable, list) and vulnerable:
            return ",".join(vulnerable)

        return None

    def _infer_ecosystem_from_purl(self, purl: str) -> Optional[str]:
        purl = (purl or "").lower()
        for eco, cfg in ECOSYSTEMS.items():
            if purl.startswith(f"pkg:{cfg.purl}/"):
                return eco
        return None