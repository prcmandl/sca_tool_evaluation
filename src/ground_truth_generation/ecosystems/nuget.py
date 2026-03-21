import logging
import requests
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

from packaging.version import Version, InvalidVersion

from new_ground_truth_generation.osv_common import (
    request_json_with_retry,
    within_date_window,
    parse_iso_date,
)

from ..osv_common import API_CALL_TRACKER, env_int

log = logging.getLogger("nuget")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# --------------------------------------------------
# Configuration
# --------------------------------------------------

NUGET_MAX_VERSIONS_PER_PACKAGE = env_int(
    "NUGET_MAX_VERSIONS_PER_PACKAGE",
    10,
)

MAX_OSV_ENTRIES_PER_COMPONENT = env_int(
    "MAX_OSV_ENTRIES_PER_COMPONENT",
    3,
)

# --------------------------------------------------
# Package Universe
# --------------------------------------------------

NUGET_GROUND_TRUTH_PACKAGES = [
    "Newtonsoft.Json", "System.Text.Json", "YamlDotNet",
    "System.Buffers", "System.Memory",
    "log4net", "NLog", "Serilog",
    "Serilog.Sinks.File", "Serilog.Sinks.Console",
    "Microsoft.Data.SqlClient", "System.Data.SqlClient",
    "Npgsql", "MongoDB.Driver",
    "Dapper", "EntityFramework", "EntityFramework.SqlServer",
    "Microsoft.AspNetCore.Http",
    "Microsoft.AspNetCore.Mvc",
    "Microsoft.AspNetCore.Authentication.JwtBearer",
    "System.IdentityModel.Tokens.Jwt",
    "Microsoft.Identity.Client",
    "Microsoft.Identity.Web",
    "BCrypt.Net", "BCrypt.Net-Core",
    "Portable.BouncyCastle",
    "Polly", "Quartz", "Hangfire.Core",
    "RestSharp", "Refit",
    "MimeKit", "MailKit",
    "System.Security.Cryptography.Xml",
    "System.Security.Cryptography.OpenSsl",
    "SharpZipLib", "DotNetZip", "Ionic.Zip",
    "CsvHelper", "HtmlAgilityPack",
    "AngleSharp", "Markdig",
    "ImageSharp", "SkiaSharp",
    "System.IO.Pipelines",
    "System.Drawing.Common",
    "System.Net.Http", "WebSocketSharp",
    "StackExchange.Redis",
    "Moq", "NUnit", "xunit",
    "NuGet.Protocol", "NuGet.Frameworks",
    "Microsoft.Build", "Microsoft.Build.Utilities.Core",
    "OpenTelemetry.Api",
    "ServiceStack.Text",
    "Apache.NMS",
    "SuperSocket",
    "IdentityServer4",
    "FluentValidation",
    "FluentAssertions",
    "AutoMapper",
    "CsvHelper.Excel",
    "MiniProfiler",
    "Serilog.Extensions.Logging",
    "Azure.Storage.Blobs",
    "Azure.Identity",
]

# --------------------------------------------------
# Helpers
# --------------------------------------------------

def _fetch_nuget_versions_with_dates(pkg: str) -> List[Tuple[str, datetime]]:
    url = (
        f"https://api.nuget.org/v3/registration5-semver1/"
        f"{pkg.lower()}/index.json"
    )

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
    except Exception:
        log.exception("Failed to fetch NuGet versions for %s", pkg)
        return []

    out: List[Tuple[str, datetime]] = []

    for page in data.get("items", []):
        for item in page.get("items", []):
            entry = item.get("catalogEntry", {})
            ver = entry.get("version")
            pub = entry.get("published")

            if not ver or not pub:
                continue

            try:
                pv = Version(ver)
                if pv.is_prerelease or pv.is_devrelease:
                    continue

                published = datetime.fromisoformat(
                    pub.replace("Z", "+00:00")
                )
                out.append((ver, published))
            except (InvalidVersion, ValueError):
                continue

    return sorted(out, key=lambda x: Version(x[0]))


# --------------------------------------------------
# Collector
# --------------------------------------------------

def collect_nuget(
    samples: Optional[int],
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    osv_cache: Dict[Tuple[str, str, str], Dict[str, Any]] = None,
) -> List[Dict]:

    start_dt = parse_iso_date(start_date)
    end_dt = parse_iso_date(end_date)

    packages = NUGET_GROUND_TRUTH_PACKAGES
    if samples is not None:
        packages = packages[:samples]

    log.info(
        "NuGet scope: using %d/%d packages",
        len(packages),
        len(NUGET_GROUND_TRUTH_PACKAGES),
    )

    rows: List[Dict] = []

    total_packages = len(packages)

    for i, pkg in enumerate(packages, start=1):
        log.info("[%d/%d] Processing package: %s", i, total_packages, pkg)

        # ----------------------------
        # Fetch versions
        # ----------------------------
        nuget_token = API_CALL_TRACKER.start("NuGet")
        try:
            versions = _fetch_nuget_versions_with_dates(pkg)
        finally:
            API_CALL_TRACKER.end("NuGet", nuget_token)

        if not versions:
            log.warning("No versions found for %s", pkg)
            continue

        # ----------------------------
        # Sampling (gleichmäßig!)
        # ----------------------------
        if NUGET_MAX_VERSIONS_PER_PACKAGE is not None:
            N = NUGET_MAX_VERSIONS_PER_PACKAGE
            if len(versions) > N:
                step = max(1, len(versions) // N)
                versions = versions[::step][:N]
                log.debug("%s: sampled to %d versions", pkg, len(versions))

        for version, published in versions:
            if not within_date_window(published, start_dt, end_dt):
                continue

            log.debug("%s@%s: querying OSV", pkg, version)

            payload = {
                "package": {"ecosystem": "NuGet", "name": pkg},
                "version": version,
            }

            # ----------------------------
            # OSV Query
            # ----------------------------
            osv_token = API_CALL_TRACKER.start("OSV")
            try:
                res = request_json_with_retry(OSV_QUERY_URL, payload)
            except Exception:
                log.exception("%s@%s: OSV request failed", pkg, version)
                continue
            finally:
                API_CALL_TRACKER.end("OSV", osv_token)

            if not isinstance(res, dict):
                log.warning("%s@%s: invalid OSV response", pkg, version)
                continue

            if osv_cache is not None:
                osv_cache[("nuget", pkg, version)] = res

            # ----------------------------
            # Limit + Dedup
            # ----------------------------
            vulns = res.get("vulns", [])[:MAX_OSV_ENTRIES_PER_COMPONENT]

            log.debug(
                "%s@%s: %d vulnerabilities (after limit)",
                pkg,
                version,
                len(vulns),
            )

            seen = set()

            for vuln in vulns:
                osv_id = vuln.get("id")
                if not osv_id or osv_id in seen:
                    continue
                seen.add(osv_id)

                aliases = vuln.get("aliases") or []
                cve = next((a for a in aliases if a.startswith("CVE-")), None)

                rows.append({
                    "ecosystem": "nuget",
                    "component_name": pkg,
                    "component_version": version,
                    "purl": f"pkg:nuget/{pkg}@{version}",
                    "vulnerability_id": osv_id,
                    "cve": cve,
                    "is_vulnerable": True,
                })

    log.info(
        "NuGet finished | packages=%d | rows=%d",
        len(packages),
        len(rows),
    )

    return rows