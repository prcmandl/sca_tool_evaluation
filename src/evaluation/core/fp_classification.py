import requests

# ------------------------------------------------------------
# OSV API
# ------------------------------------------------------------

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# ------------------------------------------------------------
# Heuristic keywords indicating non-library products
# ------------------------------------------------------------

FP_KEYWORDS = [
    "server",
    "enterprise",
    "appliance",
    "console",
    "controller",
    "management",
    "plugin",
    "rsa archer",
]

# ------------------------------------------------------------
# OSV helper
# ------------------------------------------------------------

def osv_has_cve_for_package(ecosystem: str, package: str, cve: str) -> bool:
    """
    Checks whether a given CVE is listed as an alias of any OSV advisory
    for the given (ecosystem, package).
    """
    if not ecosystem or not package or not cve:
        return False

    payload = {
        "package": {
            "ecosystem": ecosystem,
            "name": package,
        }
    }

    try:
        r = requests.post(OSV_QUERY_URL, json=payload, timeout=30)
        r.raise_for_status()
    except Exception:
        # Conservative: treat lookup failure as "not confirmed"
        return False

    for v in r.json().get("vulns", []):
        if cve in (v.get("aliases") or []):
            return True

    return False


def description_indicates_product(description: str) -> bool:
    """
    Heuristic: checks whether the vulnerability description
    suggests a product rather than a reusable library.
    """
    d = (description or "").lower()
    return any(k in d for k in FP_KEYWORDS)

# ------------------------------------------------------------
# FP classification
# ------------------------------------------------------------

def classify_fp_candidate(row: dict):
    """
    Classifies a false-positive candidate based on OSV consistency
    and textual heuristics.

    Returns:
        (fp_class, fp_reason)
    """
    cve = row.get("cve")
    ecosystem = row.get("ecosystem")
    component = row.get("component")
    description = row.get("description", "")

    # --------------------------------------------------------
    # No CVE → cannot be validated against OSV aliases
    # --------------------------------------------------------
    if not cve:
        return ("FP-UNCLEAR", "no CVE identifier")

    # --------------------------------------------------------
    # OSV alias validation (ecosystem-aware)
    # --------------------------------------------------------
    if ecosystem and not osv_has_cve_for_package(ecosystem, component, cve):
        return (
            "FP-CERTAIN",
            "CVE not listed as alias of any OSV advisory for this component-version",
        )

    # --------------------------------------------------------
    # Product vs library heuristic
    # --------------------------------------------------------
    if description_indicates_product(description):
        return (
            "FP-LIKELY",
            "CVE description indicates non-library product",
        )

    # --------------------------------------------------------
    # Default
    # --------------------------------------------------------
    return ("FP-UNCLEAR", "no decisive indicator")
