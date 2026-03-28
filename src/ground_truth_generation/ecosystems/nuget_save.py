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


from ground_truth_generation.osv_common import env_int

from ground_truth_generation.osv_common import API_CALL_TRACKER

from ground_truth_generation.osv_common import env_int

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
# Kuratierte Komponentenliste
# This is a curated list of popular and relevant
# NuGet packages across various categories.
# --------------------------------------------------
NUGET_GROUND_TRUTH_PACKAGES = [
    "Newtonsoft.Json",
    "System.Text.Json",
    "YamlDotNet",
    "System.Buffers",
    "System.Memory",
    "log4net",
    "NLog",
    "Serilog",
    "Serilog.Sinks.File",
    "Serilog.Sinks.Console",
    "Microsoft.Data.SqlClient",
    "System.Data.SqlClient",
    "Npgsql",
    "MongoDB.Driver",
    "Dapper",
    "EntityFramework",
    "EntityFramework.SqlServer",
    "Microsoft.AspNetCore.Http",
    "Microsoft.AspNetCore.Mvc",
    "Microsoft.AspNetCore.Authentication.JwtBearer",
    "System.IdentityModel.Tokens.Jwt",
    "Microsoft.Identity.Client",
    "Microsoft.Identity.Web",
    "BCrypt.Net",
    "BCrypt.Net-Core",
    "Portable.BouncyCastle",
    "Polly",
    "Quartz",
    "Hangfire.Core",
    "RestSharp",
    "Refit",
    "MimeKit",
    "MailKit",
    "System.Security.Cryptography.Xml",
    "System.Security.Cryptography.OpenSsl",
    "SharpZipLib",
    "DotNetZip",
    "Ionic.Zip",
    "CsvHelper",
    "HtmlAgilityPack",
    "AngleSharp",
    "Markdig",
    "ImageSharp",
    "SkiaSharp",
    "System.IO.Pipelines",
    "System.Drawing.Common",
    "System.Net.Http",
    "WebSocketSharp",
    "StackExchange.Redis",
    "Moq",
    "NUnit",
    "xunit",
    "NuGet.Protocol",
    "NuGet.Frameworks",
    "Microsoft.Build",
    "Microsoft.Build.Utilities.Core",
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
    "Microsoft.Extensions.Logging",
    "Microsoft.Extensions.Logging.Abstractions",
    "Microsoft.Extensions.DependencyInjection",
    "Microsoft.Extensions.DependencyInjection.Abstractions",
    "Microsoft.Extensions.Configuration",
    "Microsoft.Extensions.Configuration.Abstractions",
    "Microsoft.Extensions.Configuration.Json",
    "Microsoft.Extensions.Configuration.EnvironmentVariables",
    "Microsoft.Extensions.Configuration.Binder",
    "Microsoft.Extensions.Options",
    "Microsoft.Extensions.Options.ConfigurationExtensions",
    "Microsoft.Extensions.Http",
    "Microsoft.Extensions.Caching.Memory",
    "Microsoft.Extensions.Caching.StackExchangeRedis",
    "Microsoft.Extensions.Hosting",
    "Microsoft.Extensions.Hosting.Abstractions",
    "Microsoft.Extensions.FileProviders.Abstractions",
    "Microsoft.Extensions.FileProviders.Physical",
    "Microsoft.Extensions.Primitives",
    "Microsoft.Extensions.Diagnostics.HealthChecks",
    "Microsoft.Extensions.Diagnostics.HealthChecks.Abstractions",
    "Microsoft.AspNetCore.Authentication.OpenIdConnect",
    "Microsoft.AspNetCore.Authentication.Cookies",
    "Microsoft.AspNetCore.Authentication.WsFederation",
    "Microsoft.AspNetCore.Authentication.Negotiate",
    "Microsoft.AspNetCore.Authorization",
    "Microsoft.AspNetCore.Authorization.Policy",
    "Microsoft.AspNetCore.Mvc.Core",
    "Microsoft.AspNetCore.Mvc.NewtonsoftJson",
    "Microsoft.AspNetCore.SignalR",
    "Microsoft.AspNetCore.SignalR.Client",
    "Microsoft.AspNetCore.SignalR.Protocols.Json",
    "Microsoft.AspNetCore.ResponseCompression",
    "Microsoft.AspNetCore.Rewrite",
    "Microsoft.AspNetCore.Routing",
    "Microsoft.AspNetCore.StaticFiles",
    "Microsoft.AspNetCore.Http.Abstractions",
    "Microsoft.AspNetCore.Http.Extensions",
    "Microsoft.AspNetCore.Http.Features",
    "Microsoft.AspNetCore.WebUtilities",
    "Microsoft.AspNetCore.DataProtection",
    "Microsoft.AspNetCore.DataProtection.AzureStorage",
    "Microsoft.AspNetCore.DataProtection.StackExchangeRedis",
    "Microsoft.AspNetCore.Mvc.Versioning",
    "Microsoft.AspNetCore.Mvc.Versioning.ApiExplorer",
    "Asp.Versioning.Mvc",
    "Asp.Versioning.Mvc.ApiExplorer",
    "Microsoft.AspNetCore.OpenApi",
    "Swashbuckle.AspNetCore",
    "Swashbuckle.AspNetCore.Annotations",
    "Swashbuckle.AspNetCore.Newtonsoft",
    "NSwag.AspNetCore",
    "NSwag.CodeGeneration.CSharp",
    "NSwag.CodeGeneration.TypeScript",
    "NSwag.MSBuild",
    "Microsoft.OpenApi",
    "Microsoft.EntityFrameworkCore",
    "Microsoft.EntityFrameworkCore.Relational",
    "Microsoft.EntityFrameworkCore.SqlServer",
    "Microsoft.EntityFrameworkCore.Sqlite",
    "Microsoft.EntityFrameworkCore.InMemory",
    "Microsoft.EntityFrameworkCore.Design",
    "Microsoft.EntityFrameworkCore.Tools",
    "Microsoft.EntityFrameworkCore.Proxies",
    "Pomelo.EntityFrameworkCore.MySql",
    "MySql.EntityFrameworkCore",
    "MySqlConnector",
    "Oracle.ManagedDataAccess.Core",
    "Oracle.EntityFrameworkCore",
    "Microsoft.Data.Sqlite",
    "System.Data.Odbc",
    "System.Data.OleDb",
    "linq2db",
    "linq2db.SqlServer",
    "linq2db.PostgreSQL",
    "RepoDb",
    "RepoDb.SqlServer",
    "NPoco",
    "PetaPoco.Core",
    "Dommel",
    "System.Text.Encodings.Web",
    "System.Text.RegularExpressions",
    "Utf8Json",
    "Jil",
    "MessagePack",
    "MessagePack.Annotations",
    "protobuf-net",
    "Google.Protobuf",
    "CsvHelper.Configuration",
    "JsonSubTypes",
    "JsonEverything.JsonSchema",
    "NJsonSchema",
    "NJsonSchema.Annotations",
    "Serilog.AspNetCore",
    "Serilog.Settings.Configuration",
    "Serilog.Sinks.Seq",
    "Serilog.Sinks.Async",
    "Serilog.Sinks.Debug",
    "Serilog.Sinks.RollingFile",
    "Serilog.Sinks.ApplicationInsights",
    "Serilog.Formatting.Compact",
    "Serilog.Exceptions",
    "NLog.Web.AspNetCore",
    "NLog.Extensions.Logging",
    "Microsoft.ApplicationInsights.AspNetCore",
    "Microsoft.ApplicationInsights",
    "OpenTelemetry",
    "OpenTelemetry.Extensions.Hosting",
    "OpenTelemetry.Instrumentation.AspNetCore",
    "OpenTelemetry.Instrumentation.Http",
    "OpenTelemetry.Instrumentation.Runtime",
    "OpenTelemetry.Exporter.Console",
    "OpenTelemetry.Exporter.OpenTelemetryProtocol",
    "prometheus-net.AspNetCore",
    "prometheus-net",
    "App.Metrics",
    "Duende.IdentityServer",
    "Duende.AccessTokenManagement",
    "IdentityModel",
    "IdentityModel.AspNetCore",
    "Microsoft.IdentityModel.Protocols.OpenIdConnect",
    "Microsoft.IdentityModel.JsonWebTokens",
    "Microsoft.IdentityModel.Logging",
    "Microsoft.AspNetCore.Identity.EntityFrameworkCore",
    "Microsoft.AspNetCore.Identity.UI",
    "Microsoft.AspNetCore.Identity",
    "Azure.Security.KeyVault.Secrets",
    "Azure.Security.KeyVault.Keys",
    "Azure.Security.KeyVault.Certificates",
    "Azure.Extensions.AspNetCore.Configuration.Secrets",
    "Microsoft.Graph",
    "Microsoft.Graph.Core",
    "Jose.JWT",
    "Sodium.Core",
    "NaCl.Core",
    "BouncyCastle.Cryptography",
    "FluentValidation.AspNetCore",
    "MediatR",
    "MediatR.Extensions.Microsoft.DependencyInjection",
    "Mapster",
    "Mapster.DependencyInjection",
    "Humanizer",
    "Ardalis.GuardClauses",
    "OneOf",
    "LanguageExt.Core",
    "ValueOf",
    "Flurl",
    "Flurl.Http",
    "IdentityModel.OidcClient",
    "Microsoft.Rest.ClientRuntime",
    "Refit.HttpClientFactory",
    "Polly.Extensions.Http",
    "Yarp.ReverseProxy",
    "Websocket.Client",
    "DnsClient",
    "SSH.NET",
    "MassTransit",
    "MassTransit.AspNetCore",
    "NServiceBus",
    "Rebus",
    "RabbitMQ.Client",
    "Azure.Messaging.ServiceBus",
    "Confluent.Kafka",
    "KafkaFlow",
    "EasyNetQ",
    "NetMQ",
    "MediatR.Pipeline",
    "Hangfire.AspNetCore",
    "Hangfire.SqlServer",
    "Hangfire.Redis.StackExchange",
    "Quartz.AspNetCore",
    "Coravel",
    "CacheManager.Core",
    "FusionCache",
    "LazyCache",
    "DistributedLock",
    "RedLock.net",
    "Azure.Storage.Queues",
    "Azure.Storage.Files.Shares",
    "Azure.Messaging.EventHubs",
    "Azure.Messaging.EventGrid",
    "Azure.Core",
    "Azure.Extensions.AspNetCore.Configuration.AppConfiguration",
    "Microsoft.Azure.Cosmos",
    "AWSSDK.Core",
    "AWSSDK.S3",
    "AWSSDK.SQS",
    "AWSSDK.SimpleNotificationService",
    "AWSSDK.SecretsManager",
    "AWSSDK.SecurityToken",
    "Google.Cloud.Storage.V1",
    "Google.Cloud.PubSub.V1",
    "Google.Cloud.SecretManager.V1",
    "xunit.runner.visualstudio",
    "xunit.extensibility.core",
    "xunit.extensibility.execution",
    "NUnit3TestAdapter",
    "Moq.AutoMock",
    "NSubstitute",
    "FakeItEasy",
    "Bogus",
    "AutoFixture",
    "AutoFixture.AutoMoq",
    "AutoFixture.Xunit2",
    "FluentAssertions.Json",
    "coverlet.collector",
    "coverlet.msbuild",
    "Microsoft.NET.Test.Sdk",
    "Shouldly",
    "Verify.Xunit",
    "RichardSzalay.MockHttp",
    "WireMock.Net",
    "RazorLight",
    "Scriban",
    "Handlebars.Net",
    "HtmlSanitizer",
    "ReverseMarkdown",
    "Ganss.XSS",
    "Microsoft.Playwright",
    "PuppeteerSharp",
    "SixLabors.Fonts",
    "QuestPDF",
    "PdfSharpCore",
    "iText7",
    "EPPlus",
    "ClosedXML",
    "NPOI",
    "DocumentFormat.OpenXml",
    "Lucene.Net",
    "Lucene.Net.Analysis.Common",
    "Lucene.Net.QueryParser",
    "Elastic.Clients.Elasticsearch",
    "NEST",
    "Elasticsearch.Net",
    "System.CommandLine",
    "CommandLineParser",
    "Mono.Cecil",
    "Fody",
    "Costura.Fody",
    "AutoBogus",
    "FsCheck",
    "UnitsNet",
    "NetTopologySuite",
    "GeoJSON.Text",
    "CsvHelper.TypeConversion",
    "Spectre.Console",
    "Spectre.Console.Cli",
    "CliWrap",
    "McMaster.Extensions.CommandLineUtils",
    "YamlDotNet.Analyzers",
    "Microsoft.IO.RecyclableMemoryStream",
    "Ben.Demystifier",
    "AsyncEx.Context",
    "System.Collections.Immutable",
    "System.Reactive",
    "System.Reactive.Linq",
    "System.Reactive.Interfaces",
    "System.Runtime.Caching",
    "System.ServiceModel.Http",
    "System.ServiceModel.Primitives",
    "System.ServiceModel.NetTcp",
    "System.Formats.Asn1",
    "System.Formats.Cbor",
    "System.Threading.Channels",
    "K4os.Compression.LZ4",
    "K4os.Hash.xxHash",
    "Snappier",
    "ZstdSharp.Port",
    "Google.Api.Gax",
    "Grpc.Net.Client",
    "Grpc.AspNetCore",
    "Grpc.Tools",
    "Grpc.Core",
    "Grpc.Core.Api",
    "MagicOnion.Client",
    "MagicOnion.Server",
    "RestEase",
    "GraphQL",
    "GraphQL.SystemTextJson",
    "GraphQL.Server.Transports.AspNetCore",
    "HotChocolate.AspNetCore",
    "HotChocolate.Data.EntityFramework",
    "HotChocolate.AspNetCore.Authorization",
    "SkiaSharp.Views",
    "SixLabors.ImageSharp.Drawing",
    "ImageProcessor",
    "SkiaSharp.NativeAssets.Linux",
    "PdfPig",
    "Newtonsoft.Json.Bson",
    "System.Linq.Async",
    "MoreLinq",
    "Ardalis.Specification",
    "Scrutor",
    "Hellang.Middleware.ProblemDetails",
    "ProblemDetails",
    "MicroElements.Swashbuckle.FluentValidation",
    "HealthChecks.UI.Client",
    "AspNetCore.HealthChecks.UI",
    "AspNetCoreRateLimit",
    "Marvin.Cache.Headers",
    "Autofac",
    "Autofac.Extensions.DependencyInjection",
    "Castle.Core",
    "DryIoc",
    "SimpleInjector",
    "SimpleInjector.Integration.ServiceCollection",
    "Lamar",
    "Unity.Container",
    "StructureMap",
    "LightInject",
    "MassTransit.RabbitMQ",
    "MassTransit.Azure.ServiceBus.Core",
    "NServiceBus.RabbitMQ",
    "NServiceBus.Transport.AzureServiceBus",
    "Rebus.ServiceProvider",
    "Rebus.RabbitMq",
    "Rebus.AzureServiceBus",
    "CAP",
    "DotPulsar",
    "MQTTnet",
    "Apache.NMS.ActiveMQ",
    "ActiveMQ.Artemis.Client",
    "Akka",
    "Akka.Remote",
    "Akka.Cluster",
    "Akka.Persistence",
    "Orleans",
    "Orleans.Server",
    "Orleans.Clustering.Redis",
    "Orleans.Serialization.SystemTextJson",
    "Elsa",
    "Elsa.Activities.Http",
    "Elsa.EntityFrameworkCore",
    "WorkflowCore",
    "Sentry",
    "Sentry.AspNetCore",
    "Sentry.Serilog",
    "Elastic.Apm.NetCoreAll",
    "Elastic.Apm.AspNetCore",
    "OpenTracing",
    "OpenTracing.Contrib.NetCore",
    "Jaeger",
    "OpenTelemetry.Exporter.Jaeger",
    "OpenTelemetry.Exporter.Zipkin",
    "Zipkin",
    "Steeltoe.Management.EndpointCore",
    "Steeltoe.Discovery.ClientCore",
    "Steeltoe.CircuitBreaker.HystrixCore",
    "Steeltoe.Configuration.ConfigServerCore",
    "Microsoft.Azure.AppConfiguration.AspNetCore",
    "Azure.Monitor.OpenTelemetry.AspNetCore",
    "Azure.Monitor.Query",
    "Azure.AI.OpenAI",
    "Azure.Search.Documents",
    "Azure.Storage.Files.DataLake",
    "Azure.Data.Tables",
    "Azure.Data.AppConfiguration",
    "Azure.Security.KeyVault.Administration",
    "AWSSDK.DynamoDBv2",
    "AWSSDK.Lambda",
    "AWSSDK.CloudWatchLogs",
    "AWSSDK.Extensions.NETCore.Setup",
    "Google.Cloud.Firestore",
    "Google.Cloud.Spanner.Data",
    "Google.Cloud.Logging.V2",
    "Google.Cloud.Diagnostics.AspNetCore3",
    "Grpc.Net.ClientFactory",
    "protobuf-net.Grpc",
    "protobuf-net.Grpc.AspNetCore",
    "MagicOnion.Abstractions",
    "Google.Api.Gax.Grpc",
    "Grpc.HealthCheck",
    "Grpc.Reflection",
    "StackExchange.Redis.Extensions.Core",
    "StackExchange.Redis.Extensions.Newtonsoft",
    "CacheTower",
    "EasyCaching.Core",
    "EasyCaching.Redis",
    "EntityFrameworkCore.Triggers",
    "Z.EntityFramework.Plus.EFCore",
    "EFCore.BulkExtensions",
    "Respawn",
    "DbUp",
    "FluentMigrator",
    "FluentMigrator.Runner",
    "RoundhousE",
    "RavenDB.Client",
    "Marten",
    "Marten.AspNetCore",
    "LiteDB",
    "Realm",
    "CouchbaseNetClient",
    "CassandraCSharpDriver",
    "Neo4j.Driver",
    "InfluxDB.Client",
    "SqlKata",
    "SqlKata.Execution",
    "SqlSugarCore",
    "FreeSql",
    "FreeSql.Provider.SqlServer",
    "FreeSql.Provider.Sqlite",
    "DinkToPdf",
    "WkHtmlToPdf-DotNet",
    "SelectPdf",
    "IronPdf",
    "Syncfusion.Pdf.Net.Core",
    "Syncfusion.XlsIO.Net.Core",
    "Syncfusion.DocIO.Net.Core",
    "GemBox.Document",
    "GemBox.Spreadsheet",
    "FastReport.OpenSource",
    "Tesseract",
    "ZXing.Net",
    "QRCoder",
    "BarcodeLib",
    "SkiaSharp.HarfBuzz",
    "ImageMagick",
    "Magick.NET-Q8-AnyCPU",
    "itext7.pdfhtml",
    "HtmlRenderer.PdfSharp",
    "System.Drawing.Primitives",
    "DeviceDetector.NET",
    "MaxMind.GeoIP2",
    "UAParser",
    "Mime-Detective",
    "Microsoft.AspNetCore.SpaServices.Extensions",
    "ElectronNET.API",
    "Avalonia",
    "Avalonia.Desktop",
    "ReactiveUI",
    "ReactiveUI.Fody",
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
