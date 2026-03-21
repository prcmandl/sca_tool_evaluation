"""
Central normalization utilities.

These functions MUST be used symmetrically by:
- Ground truth loading
- Tool adapters
- Evaluation logic

Never normalize ad-hoc in adapters.
"""

from __future__ import annotations


# ------------------------------------------------------------
# Component normalization
# ------------------------------------------------------------

def normalize_component(ecosystem: str, name: str) -> str:
    """
    Normalize component names across ecosystems.

    INVARIANT (regelverbindlich):
    - Matching ist string-exakt auf (ecosystem, component, version)
    - Normalisierung MUSS symmetrisch sein (GT, Tools, Evaluation)
    - Keine Heuristiken, kein Fuzzy Matching

    Ecosystem-spezifische Identität:
    - maven:  groupId:artifactId  (exakt erhalten)
    - nuget:  PackageId (case-insensitive, aber vollständig)
    - npm:    lowercase (npm-Spezifikation)
    - pypi:   PEP 503 Canonical Form
    """

    if not name:
        return ""

    eco = (ecosystem or "").strip().lower()
    n = name.strip()

    # ------------------------------------------------------------
    # Maven
    # ------------------------------------------------------------
    # Identität = groupId:artifactId
    # KEINE Kürzung, KEINE Normalisierung außer Formatangleichung
    if eco == "maven":
        # akzeptiere sowohl group:artifact als auch group/artifact
        if "/" in n and ":" not in n:
            group, artifact = n.split("/", 1)
            return f"{group}:{artifact}"
        return n

    # ------------------------------------------------------------
    # NuGet
    # ------------------------------------------------------------
    # PackageId ist case-insensitive, aber vollständig Teil der Identität
    # KEIN Entfernen von Präfixen (System., Microsoft., etc.)
    if eco == "nuget":
        return n

    # ------------------------------------------------------------
    # npm
    # ------------------------------------------------------------
    # npm-Paketnamen sind kanonisch lowercase
    if eco == "npm":
        return n.lower()

    # ------------------------------------------------------------
    # PyPI
    # ------------------------------------------------------------
    # PEP 503: lowercase + '_' → '-'
    if eco == "pypi":
        return n.lower().replace("_", "-")

    # ------------------------------------------------------------
    # Fallback (konservativ)
    # ------------------------------------------------------------
    return n



# ------------------------------------------------------------
# Vulnerability identifier normalization
# ------------------------------------------------------------

def normalize_identifier(vuln_id: str | None) -> str | None:
    """
    Normalize vulnerability identifiers (CVE, GHSA, OSV).

    - uppercases CVE / GHSA
    - leaves OSV IDs as-is
    """
    if not vuln_id:
        return None

    v = vuln_id.strip()

    if v.upper().startswith("CVE-"):
        return v.upper()

    if v.upper().startswith("GHSA-"):
        return v.upper()

    return v


# ------------------------------------------------------------
# Version normalization (string-safe)
# ------------------------------------------------------------

def normalize_version(version: str | None) -> str:
    """
    Normalize version string.

    NOTE:
    - DO NOT parse or coerce semver here
    - Keep string semantics stable
    """
    return (version or "").strip()


def ecosystem_from_purl(purl: str) -> str | None:
    """
    Extract ecosystem from a Package URL (purl).
    Example: pkg:pypi/tensorflow@2.9.0 -> pypi
    """
    if not purl:
        return None

    purl = purl.strip().lower()
    if not purl.startswith("pkg:"):
        return None

    try:
        return purl.split(":", 1)[1].split("/", 1)[0]
    except Exception:
        return None

