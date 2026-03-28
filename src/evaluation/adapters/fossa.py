import logging
from typing import List

import requests

from evaluation.adapters.base import VulnerabilityToolAdapter
from evaluation.core.model import Finding

# ---------------------------------------------------------------------------
# Experimental / work in progress
# This module is under active development.
# It is not yet considered stable and may contain incomplete functionality.
# ---------------------------------------------------------------------------

log = logging.getLogger("evaluation.adapters.fossa")


class FossaAdapter(VulnerabilityToolAdapter):
    """
    FOSSA adapters (SBOM / License-focused).

    SBOM-based FOSSA projects do NOT expose security issues via API.
    This adapters therefore returns ZERO security findings,
    but fully conforms to the VulnerabilityToolAdapter contract.
    """

    def __init__(self, config: dict):
        super().__init__(config)

        env = config.get("env", {})

        self.base_url = (env.get("FOSSA_BASE_URL") or "").rstrip("/")
        self.api_key = env.get("FOSSA_API_KEY")
        self.project_id = env.get("FOSSA_PROJECT_ID")

        if not self.base_url or not self.api_key or not self.project_id:
            raise SystemExit(
                "Missing environment variables for FOSSA:\n"
                "  FOSSA_BASE_URL\n"
                "  FOSSA_API_KEY\n"
                "  FOSSA_PROJECT_ID"
            )

        self._probed = False

        log.info("FOSSA adapters initialized")
        log.info("FOSSA project locator: %s", self.project_id)

    # ------------------------------------------------------------
    # Adapter metadata
    # ------------------------------------------------------------

    def name(self) -> str:
        return "fossa"

    def supports_fp_heuristic(self) -> bool:
        return False

    # ------------------------------------------------------------
    # REQUIRED by evaluate.py
    # ------------------------------------------------------------

    def load_findings(self) -> List[Finding]:
        """
        Load and normalize FOSSA findings.

        For SBOM-based projects this ALWAYS returns an empty list.
        """
        self._probe_security_endpoint_once()

        findings: List[Finding] = []
        log.info("FOSSA: normalized %d findings", len(findings))
        return findings

    def load_findings_for_component(
        self,
        *,
        ecosystem: str,
        component: str,
        version: str,
    ) -> List[Finding]:
        """
        Component-level API required by wrapper adapters.
        Always empty for FOSSA.
        """
        return []

    # ------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------

    def _probe_security_endpoint_once(self) -> None:
        """
        Probe the FOSSA /issues endpoint once per run.

        Non-JSON response is EXPECTED for SBOM projects.
        """
        if self._probed:
            return
        self._probed = True

        url = f"{self.base_url}/api/projects/{self.project_id}/issues"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }

        try:
            r = requests.get(url, headers=headers, timeout=30)
        except Exception as e:
            log.warning(
                "FOSSA request failed for project %s: %s",
                self.project_id,
                e,
            )
            return

        content_type = r.headers.get("Content-Type", "")

        if not content_type.startswith("application/json"):
            log.info(
                "FOSSA project %s exposes no security issues via API "
                "(SBOM/license-only project)",
                self.project_id,
            )
