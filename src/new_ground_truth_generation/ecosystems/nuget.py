import logging
import requests
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

from packaging.version import Version, InvalidVersion

from ground_truth_generation.osv_common import (
    request_json_with_retry,
    within_date_window,
    parse_iso_date,
)


from new_ground_truth_generation.osv_common import env_int

from new_ground_truth_generation.osv_common import API_CALL_TRACKER

from new_ground_truth_generation.osv_common import env_int

TARGET_VULNS_PER_ECOSYSTEM = env_int(
    "TARGET_VULNS_PER_ECOSYSTEM",
    None,
)

log = logging.getLogger("nuget")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# --------------------------------------------------
# Version cutoff (orthogonal zu samples)
# --------------------------------------------------
NUGET_MAX_VERSIONS_PER_PACKAGE = env_int("PYPI_MAX_VERSIONS_PER_PACKAGE", 10)
MAX_OSV_ENTRIES_PER_COMPONENT = env_int("MAX_OSV_ENTRIES_PER_COMPONENT", 10)


# --------------------------------------------------
# # Kuratierte Komponentenliste
# --------------------------------------------------
NUGET_GROUND_TRUTH_PACKAGES = [

# ----------------------------
# JSON / serialization
# ----------------------------
"Newtonsoft.Json","System.Text.Json","Jil","MessagePack","Utf8Json","protobuf-net","ZeroFormatter","JsonSubTypes","CsvHelper","YamlDotNet",

# ----------------------------
# Logging
# ----------------------------
"log4net","NLog","Serilog","Serilog.Sinks.File","Serilog.Sinks.Console","Serilog.AspNetCore","Serilog.Extensions.Logging","Common.Logging","Castle.Core","Microsoft.Extensions.Logging",

# ----------------------------
# Middleware / ASP.NET Core
# ----------------------------
"Microsoft.AspNetCore.Http","Microsoft.AspNetCore.Mvc","Microsoft.AspNetCore.Routing","Microsoft.AspNetCore.Hosting","Microsoft.AspNetCore.Server.Kestrel.Core","Microsoft.AspNetCore.Authentication.JwtBearer","Microsoft.AspNetCore.Authentication.Cookies","Microsoft.AspNetCore.Authorization","Microsoft.AspNetCore.Session","Microsoft.AspNetCore.WebUtilities",

# ----------------------------
# Identity / auth / security
# ----------------------------
"System.IdentityModel.Tokens.Jwt","Microsoft.IdentityModel.Tokens","Microsoft.IdentityModel.JsonWebTokens","Microsoft.Identity.Client","Microsoft.Identity.Web","IdentityServer4","Duende.IdentityServer","BCrypt.Net","BCrypt.Net-Core","Portable.BouncyCastle",

# ----------------------------
# Data / ORM / SQL
# ----------------------------
"EntityFramework","EntityFramework.SqlServer","Microsoft.EntityFrameworkCore","Microsoft.EntityFrameworkCore.SqlServer","Microsoft.EntityFrameworkCore.Relational","Dapper","Dapper.Contrib","System.Data.SqlClient","Microsoft.Data.SqlClient","RepoDb",

# ----------------------------
# Databases / NoSQL
# ----------------------------
"Npgsql","MySql.Data","MySqlConnector","MongoDB.Driver","MongoDB.Bson","StackExchange.Redis","ServiceStack.Redis","RavenDB.Client","LiteDB","CassandraCSharpDriver",

# ----------------------------
# HTTP / clients
# ----------------------------
"RestSharp","Refit","Flurl.Http","Flurl","IdentityModel","Polly","GraphQL.Client","Microsoft.Graph","Octokit","HttpClientFactory",

# ----------------------------
# Messaging / integration
# ----------------------------
"Quartz","Hangfire.Core","MassTransit","NServiceBus","EasyNetQ","RabbitMQ.Client","Apache.NMS","Apache.NMS.ActiveMQ","MQTTnet","Confluent.Kafka",

# ----------------------------
# Mail / parsing
# ----------------------------
"MimeKit","MailKit","HtmlAgilityPack","AngleSharp","Markdig","CommonMark.NET","ReverseMarkdown","CsvHelper.Excel","ExcelDataReader","ExcelDataReader.DataSet",

# ----------------------------
# Compression / archives
# ----------------------------
"SharpZipLib","DotNetZip","Ionic.Zip","SevenZipSharp","System.IO.Compression.ZipFile","ZstdSharp","K4os.Compression.LZ4","Snappy.Sharp","Brotli.NET","SharpCompress",

# ----------------------------
# Crypto / certificates
# ----------------------------
"System.Security.Cryptography.Xml","System.Security.Cryptography.OpenSsl","BouncyCastle.Cryptography","Pkcs11Interop","Jose.JWT","jose-jwt","SecurityDriven.Inferno","DnsClient","PeterO.Cbor","NSec.Cryptography",

# ----------------------------
# Files / IO / imaging
# ----------------------------
"System.IO.Pipelines","System.Drawing.Common","ImageSharp","SkiaSharp","Magick.NET-Q8-AnyCPU","PdfSharp","iTextSharp","UglyToad.PdfPig","TikaOnDotNet","FileHelpers",

# ----------------------------
# Validation / mapping
# ----------------------------
"FluentValidation","FluentAssertions","AutoMapper","Mapster","ExpressMapper","ValueInjecter","Compare-Net-Objects","Humanizer","GuardClauses","Fody",

# ----------------------------
# Build / tooling
# ----------------------------
"NuGet.Protocol","NuGet.Frameworks","NuGet.Packaging","NuGet.Versioning","NuGet.Configuration","Microsoft.Build","Microsoft.Build.Framework","Microsoft.Build.Utilities.Core","Microsoft.Build.Tasks.Core","Cake.Core",

# ----------------------------
# Cloud / SDKs
# ----------------------------
"Azure.Storage.Blobs","Azure.Storage.Files.Shares","Azure.Storage.Queues","Azure.Identity","Azure.Core","Azure.Security.KeyVault.Secrets","Azure.Messaging.ServiceBus","AWSSDK.S3","AWSSDK.Core","Google.Cloud.Storage.V1",

# ----------------------------
# Observability
# ----------------------------
"OpenTelemetry.Api","OpenTelemetry","OpenTelemetry.Extensions.Hosting","OpenTelemetry.Instrumentation.Http","OpenTelemetry.Exporter.Console","App.Metrics","prometheus-net","Serilog.Sinks.Seq","Elastic.Apm","Elastic.Apm.AspNetCore",

# ----------------------------
# Testing
# ----------------------------
"Moq","NUnit","NUnit3TestAdapter","xunit","xunit.runner.visualstudio","FluentValidation.TestHelper","coverlet.collector","coverlet.msbuild","AutoFixture","Shouldly",

# ----------------------------
# Legacy / web frameworks
# ----------------------------
"OWIN","Microsoft.Owin","Microsoft.Owin.Security","Microsoft.Owin.Security.Jwt","Microsoft.Owin.Host.SystemWeb","System.Web.Http","System.Web.Mvc","System.Web.Optimization","WebSocketSharp","SignalR",

# ----------------------------
# DI / utilities
# ----------------------------
"CommandLineParser","Polly.Extensions.Http","MediatR","MediatR.Extensions.Microsoft.DependencyInjection","Scrutor","Castle.Windsor","StructureMap","Autofac","SimpleInjector","NodaTime",

# ----------------------------
# Additional / ecosystem libs
# ----------------------------
"CsvTextFieldParser","Rebus","IdentityModel.OidcClient","Selenium.WebDriver","Selenium.Support","Bogus","CsvReader","LanguageExt.Core","ServiceStack.Text","MiniProfiler",

]

# --------------------------------------------------
# Helpers
# --------------------------------------------------

def _fetch_nuget_versions_with_dates(
    pkg: str,
) -> List[Tuple[str, datetime]]:
    """
    Fetch stable NuGet versions together with their published date.
    Versions without a published timestamp are discarded.
    """
    url = (
        f"https://api.nuget.org/v3/registration5-semver1/"
        f"{pkg.lower()}/index.json"
    )

    try:
        data = requests.get(url, timeout=30).json()
    except Exception:
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

    return sorted(out, key=lambda x: Version(x[0]), reverse=True)


# --------------------------------------------------
# Collector
# --------------------------------------------------

def collect_nuget(
    samples,
    start_date=None,
    end_date=None,
    osv_cache=None,
):
    start_dt = parse_iso_date(start_date)
    end_dt = parse_iso_date(end_date)

    TARGET = env_int("TARGET_VULNS_PER_ECOSYSTEM", None)

    packages = NUGET_GROUND_TRUTH_PACKAGES[:samples] if samples else NUGET_GROUND_TRUTH_PACKAGES

    rows = []
    total_vulns = 0
    total_packages = len(packages)

    for i, pkg in enumerate(packages, 1):
        component_vulns = 0

        versions = _fetch_nuget_versions_with_dates(pkg)

        if NUGET_MAX_VERSIONS_PER_PACKAGE:
            versions = versions[:NUGET_MAX_VERSIONS_PER_PACKAGE]

        for version, published in versions:
            if not within_date_window(published, start_dt, end_dt):
                continue

            payload = {"package": {"ecosystem": "NuGet", "name": pkg}, "version": version}
            res = request_json_with_retry(OSV_QUERY_URL, payload)

            if not isinstance(res, dict):
                continue

            if osv_cache is not None:
                osv_cache[("nuget", pkg, version)] = res

            vulns = res.get("vulns", [])[:MAX_OSV_ENTRIES_PER_COMPONENT]
            seen = set()

            for v in vulns:
                vid = v.get("id")
                if not vid or vid in seen:
                    continue
                seen.add(vid)

                rows.append({
                    "ecosystem": "nuget",
                    "component_name": pkg,
                    "component_version": version,
                    "purl": f"pkg:nuget/{pkg}@{version}",
                    "vulnerability_id": vid,
                    "cve": next((a for a in (v.get("aliases") or []) if a.startswith("CVE-")), None),
                    "is_vulnerable": True,
                })

                component_vulns += 1
                total_vulns += 1

                if TARGET and total_vulns >= TARGET:
                    log.info("[%d/%d] Processing package %s; %d vulnerabilities", i, total_packages, pkg, component_vulns)
                    log.info("Stopping early at %d vulnerabilities", total_vulns)
                    return rows

        log.info("[%d/%d] Processing package %s; %d vulnerabilities", i, total_packages, pkg, component_vulns)

    return rows
