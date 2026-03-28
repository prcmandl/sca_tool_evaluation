# ---------------------------------------------------------------------------
# Experimental / work in progress
# This module is under active development.
# It is not yet considered stable and may contain incomplete functionality.
# ---------------------------------------------------------------------------

"""
Mend (WhiteSource) Adapter
=================================

Zweck
-----
Dieser Adapter bindet die Mend SCA API (v2.0) in die bestehende
Evaluation-Pipeline ein – analog zu vorhandenen Adaptern für
Snyk und Dependency-Track.

Ziel ist:
- Abruf von Vulnerability-Daten auf Projekt-Ebene
- Normalisierung auf das interne Finding-Modell
- Komponentenbasierte Filterung (ecosystem, component, version)

Wichtige Randbedingungen
-----------------------
- Mend liefert Security Alerts projektweit, nicht komponentenspezifisch
- JWT-basierte Authentifizierung mit kurzer Lebensdauer
- Feature- / Rollenprüfung erfolgt serverseitig (403 möglich)
- API liefert Mend-native IDs, CVEs sind optional

Erforderliche ENV-Variablen
---------------------------
MEND_EMAIL           : Benutzer-E-Mail
MEND_USER_KEY        : User Key (API Key)
MEND_ORG_TOKEN       : Organisationstoken
MEND_PROJECT_TOKEN   : Projekt-Token
MEND_BASE_URL        : optional, Default https://api-saas.mend.io
"""

import logging
import time
import requests
from typing import List, Dict, Any, Optional

from evaluation.adapters.base import VulnerabilityToolAdapter
from evaluation.core.model import Finding
from evaluation.core.ecosystems import ECOSYSTEMS

log = logging.getLogger("evaluation.adapters.mend")


class MendAdapter(VulnerabilityToolAdapter):
    """
    MendAdapter
    -----------

    Implementiert einen projektbasierten Mend-Adapter.

    Architektur:
    - einmaliger Projekt-Download aller Security Alerts
    - In-Memory-Cache
    - komponentenbasierte Filterung auf Client-Seite

    Warum so?
    ---------
    Mend bietet keine API, um gezielt *eine* Komponente abzufragen.
    Deshalb:
      1. einmal alles laden
      2. lokal filtern
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialisiert den Adapter.

        - liest ENV-Variablen
        - bereitet HTTP-Session vor
        - validiert Mindestkonfiguration
        """
        super().__init__(config)

        env = config.get("env", {})

        # Basis-URL der Mend API
        self.base_url = (env.get("MEND_BASE_URL") or "https://api-saas.mend.io").rstrip("/")

        # Authentifizierungsdaten
        self.email = env.get("MEND_EMAIL")
        self.user_key = env.get("MEND_USER_KEY")
        self.org_token = env.get("MEND_ORG_TOKEN")

        # Projekt-Kontext (zwingend!)
        self.project_token = env.get("MEND_PROJECT_TOKEN")

        # Wenn etwas fehlt → Adapter deaktivieren
        if not all([self.email, self.user_key, self.org_token, self.project_token]):
            log.warning(
                "Mend adapters disabled: missing env vars "
                "(MEND_EMAIL, MEND_USER_KEY, MEND_ORG_TOKEN, MEND_PROJECT_TOKEN)"
            )
            self.enabled = False
            return

        self.enabled = True

        # Wiederverwendbare HTTP-Session
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

        # JWT-Handling (kurzlebig)
        self._jwt: Optional[str] = None
        self._jwt_timestamp: Optional[float] = None

        # Cache für normalisierte Findings
        self._cached_findings: Optional[List[Finding]] = None

        log.info("Mend adapters initialized (project-scoped)")

    # ------------------------------------------------------------------
    # Metadaten
    # ------------------------------------------------------------------

    def name(self) -> str:
        """Name des Tools (für Reporting / Vergleich)."""
        return "mend"

    # ------------------------------------------------------------------
    # Öffentliche API
    # ------------------------------------------------------------------

    def load_findings(self) -> List[Finding]:
        """
        Lädt alle Findings für das konfigurierte Projekt.

        Ablauf:
        - Falls Cache vorhanden → zurückgeben
        - Sonst:
            * API-Abfrage
            * Normalisierung
            * Caching
        """
        if not self.enabled:
            return []

        if self._cached_findings is not None:
            return self._cached_findings

        raw = self._fetch_security_alerts()
        findings = self._normalize_findings(raw)

        self._cached_findings = findings
        return findings

    def load_findings_for_component(
            self,
            *,
            ecosystem: str,
            component: str,
            version: str,
    ) -> List[Finding]:
        """
        Required by VulnerabilityToolAdapter.

        Returns all findings matching exactly
        ecosystem + component + version.
        """
        all_findings = self.load_findings()

        return [
            f for f in all_findings
            if f.ecosystem == ecosystem
               and f.component == component
               and f.version == version
        ]

    # ------------------------------------------------------------------
    # Authentifizierung
    # ------------------------------------------------------------------

    def _login(self) -> str:
        """
        Führt ein Login gegen die Mend API aus.

        Endpoint:
            POST /api/v2.0/login

        Rückgabe:
            JWT Token (Bearer)
        """
        url = f"{self.base_url}/api/v2.0/login"

        payload = {
            "email": self.email,
            "orgToken": self.org_token,
            "userKey": self.user_key,
        }

        log.info("Mend login request")

        r = self.session.post(url, json=payload, timeout=30)

        if r.status_code != 200:
            raise RuntimeError(f"Mend login failed (HTTP {r.status_code})")

        data = r.json()

        token = (
            data.get("jwt")
            or data.get("token")
            or data.get("accessToken")
            or data.get("access_token")
        )

        if not token:
            raise RuntimeError("Mend login response did not contain a JWT token")

        self._jwt = token
        self._jwt_timestamp = time.time()
        return token

    def _auth_headers(self) -> Dict[str, str]:
        """
        Liefert HTTP-Header mit gültigem JWT.
        """
        if not self._jwt:
            self._login()
        return {"Authorization": f"Bearer {self._jwt}"}

    # ------------------------------------------------------------------
    # API-Zugriff
    # ------------------------------------------------------------------

    def _fetch_security_alerts(self) -> Dict[str, Any]:
        """
        Ruft alle Security Alerts gruppiert nach Komponente ab.

        Endpoint:
            GET /api/v2.0/projects/{projectToken}/alerts/security/groupBy/component
        """
        url = (
            f"{self.base_url}/api/v2.0/projects/"
            f"{self.project_token}/alerts/security/groupBy/component"
        )

        r = self.session.get(url, headers=self._auth_headers(), timeout=60)

        # JWT abgelaufen → neu anmelden und einmal retry
        if r.status_code == 401:
            self._jwt = None
            self._login()
            r = self.session.get(url, headers=self._auth_headers(), timeout=60)

        if r.status_code != 200:
            log.error("Mend API error %s: %s", r.status_code, r.text[:300])
            return {}

        return r.json()

    # ------------------------------------------------------------------
    # Normalisierung
    # ------------------------------------------------------------------

    def _normalize_findings(self, data: Dict[str, Any]) -> List[Finding]:
        """
        Wandelt Mend-Alerts in interne Finding-Objekte um.

        Erwartete Struktur:
        {
            "retVal": [
                {
                    "componentName": "...",
                    "componentVersion": "...",
                    "vulnerabilityName": "CVE-....",
                    ...
                }
            ]
        }
        """
        findings: List[Finding] = []

        rows = data.get("retVal") or []
        if not isinstance(rows, list):
            return []

        for item in rows:
            component = item.get("componentName") or item.get("libraryName")
            version = item.get("componentVersion") or item.get("libraryVersion")

            if not component or not version:
                continue

            ecosystem = self._infer_ecosystem(item)
            if not ecosystem:
                continue

            vuln = item.get("vulnerabilityName") or item.get("cve")

            cve = vuln if isinstance(vuln, str) and vuln.startswith("CVE-") else None

            description = (
                item.get("vulnerabilityDescription")
                or item.get("description")
                or vuln
                or ""
            )

            findings.append(
                Finding(
                    ecosystem=ecosystem,
                    component=str(component),
                    version=str(version),
                    cve=cve,
                    osv_id=None,
                    description=str(description).split("\n")[0],
                    source="mend",
                    cve_cpes=None,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Ecosystem-Erkennung
    # ------------------------------------------------------------------

    def _infer_ecosystem(self, item: Dict[str, Any]) -> Optional[str]:
        """
        Leitet das Ecosystem (npm, maven, pypi, nuget, …) ab.

        Priorität:
        1. PURL-Feld
        2. componentType / packageManager
        """
        purl = item.get("purl") or item.get("componentPurl")
        if isinstance(purl, str) and purl.startswith("pkg:"):
            purl_l = purl.lower()
            for eco, cfg in ECOSYSTEMS.items():
                if purl_l.startswith(f"pkg:{cfg.purl.lower()}/"):
                    return eco

        hint = (
            item.get("packageManager")
            or item.get("componentType")
            or ""
        ).lower()

        for eco, cfg in ECOSYSTEMS.items():
            if cfg.purl.lower() in hint:
                return eco

        return None
