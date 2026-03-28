"""Thematisch strukturierte NuGet-Paketliste.

Diese Datei gruppiert die 500 Pakete nach fachlichen Themen,
damit die Liste leichter lesbar und pflegbar ist.
"""

# ------------------------------------------------------------
# Hinweise
# ------------------------------------------------------------
# - Die Pakete bleiben in deterministischer Reihenfolge je Gruppe.
# - Die Gesamtliste wird am Ende durch Konkatenation gebildet.
# - Eine Validierung prüft auf genau 500 Einträge und Duplikate.

# ------------------------------------------------------------
# WEB_MIDDLEWARE_AND_APIS
# Middleware, ASP.NET Core, HTTP-Pipeline, Routing, OpenAPI, API-Versionierung, GraphQL-Webserver
# ------------------------------------------------------------
WEB_MIDDLEWARE_AND_APIS = [
    "Asp.Versioning.Mvc",
    "Asp.Versioning.Mvc.ApiExplorer",
    "AspNetCore.HealthChecks.UI",
    "AspNetCoreRateLimit",
    "Azure.Extensions.AspNetCore.Configuration.AppConfiguration",
    "Azure.Extensions.AspNetCore.Configuration.Secrets",
    "Azure.Monitor.OpenTelemetry.AspNetCore",
    "Elastic.Apm.AspNetCore",
    "FluentValidation.AspNetCore",
    "Google.Cloud.Diagnostics.AspNetCore3",
    "GraphQL",
    "GraphQL.Server.Transports.AspNetCore",
    "GraphQL.SystemTextJson",
    "Grpc.AspNetCore",
    "Hangfire.AspNetCore",
    "HealthChecks.UI.Client",
    "Hellang.Middleware.ProblemDetails",
    "HotChocolate.AspNetCore",
    "HotChocolate.AspNetCore.Authorization",
    "HotChocolate.Data.EntityFramework",
    "IdentityModel.AspNetCore",
    "Marten.AspNetCore",
    "Marvin.Cache.Headers",
    "MassTransit.AspNetCore",
    "Microsoft.ApplicationInsights.AspNetCore",
    "Microsoft.AspNetCore.Authentication.Cookies",
    "Microsoft.AspNetCore.Authentication.JwtBearer",
    "Microsoft.AspNetCore.Authentication.Negotiate",
    "Microsoft.AspNetCore.Authentication.OpenIdConnect",
    "Microsoft.AspNetCore.Authentication.WsFederation",
    "Microsoft.AspNetCore.Authorization",
    "Microsoft.AspNetCore.Authorization.Policy",
    "Microsoft.AspNetCore.DataProtection",
    "Microsoft.AspNetCore.DataProtection.AzureStorage",
    "Microsoft.AspNetCore.DataProtection.StackExchangeRedis",
    "Microsoft.AspNetCore.Http",
    "Microsoft.AspNetCore.Http.Abstractions",
    "Microsoft.AspNetCore.Http.Extensions",
    "Microsoft.AspNetCore.Http.Features",
    "Microsoft.AspNetCore.Identity",
    "Microsoft.AspNetCore.Identity.EntityFrameworkCore",
    "Microsoft.AspNetCore.Identity.UI",
    "Microsoft.AspNetCore.Mvc",
    "Microsoft.AspNetCore.Mvc.Core",
    "Microsoft.AspNetCore.Mvc.NewtonsoftJson",
    "Microsoft.AspNetCore.Mvc.Versioning",
    "Microsoft.AspNetCore.Mvc.Versioning.ApiExplorer",
    "Microsoft.AspNetCore.OpenApi",
    "Microsoft.AspNetCore.ResponseCompression",
    "Microsoft.AspNetCore.Rewrite",
    "Microsoft.AspNetCore.Routing",
    "Microsoft.AspNetCore.SignalR",
    "Microsoft.AspNetCore.SignalR.Client",
    "Microsoft.AspNetCore.SignalR.Protocols.Json",
    "Microsoft.AspNetCore.SpaServices.Extensions",
    "Microsoft.AspNetCore.StaticFiles",
    "Microsoft.AspNetCore.WebUtilities",
    "Microsoft.Azure.AppConfiguration.AspNetCore",
    "Microsoft.OpenApi",
    "NLog.Web.AspNetCore",
    "NSwag.AspNetCore",
    "NSwag.CodeGeneration.CSharp",
    "NSwag.CodeGeneration.TypeScript",
    "NSwag.MSBuild",
    "OpenTelemetry.Instrumentation.AspNetCore",
    "ProblemDetails",
    "Quartz.AspNetCore",
    "Sentry.AspNetCore",
    "Serilog.AspNetCore",
    "Swashbuckle.AspNetCore",
    "Swashbuckle.AspNetCore.Annotations",
    "Swashbuckle.AspNetCore.Newtonsoft",
    "Yarp.ReverseProxy",
    "prometheus-net.AspNetCore",
    "protobuf-net.Grpc.AspNetCore",
]

# ------------------------------------------------------------
# SECURITY_IDENTITY_AND_CRYPTO
# Identität, Authentifizierung, Token, JWT/OIDC, Kryptographie, Key Vault, sichere Konfiguration
# ------------------------------------------------------------
SECURITY_IDENTITY_AND_CRYPTO = [
    "Azure.Identity",
    "Azure.Security.KeyVault.Administration",
    "Azure.Security.KeyVault.Certificates",
    "Azure.Security.KeyVault.Keys",
    "Azure.Security.KeyVault.Secrets",
    "BCrypt.Net",
    "BCrypt.Net-Core",
    "BouncyCastle.Cryptography",
    "Duende.AccessTokenManagement",
    "Duende.IdentityServer",
    "Ganss.XSS",
    "HtmlSanitizer",
    "IdentityModel",
    "IdentityModel.OidcClient",
    "IdentityServer4",
    "Jose.JWT",
    "Microsoft.Identity.Client",
    "Microsoft.Identity.Web",
    "Microsoft.IdentityModel.JsonWebTokens",
    "Microsoft.IdentityModel.Logging",
    "Microsoft.IdentityModel.Protocols.OpenIdConnect",
    "NaCl.Core",
    "Portable.BouncyCastle",
    "Sodium.Core",
    "System.IdentityModel.Tokens.Jwt",
    "System.Security.Cryptography.OpenSsl",
    "System.Security.Cryptography.Xml",
]

# ------------------------------------------------------------
# DATA_DATABASE_AND_ORM
# ORMs, relationale Datenbanken, Treiber, Migrationen, NoSQL- und Spezialdatenbanken
# ------------------------------------------------------------
DATA_DATABASE_AND_ORM = [
    "CassandraCSharpDriver",
    "CouchbaseNetClient",
    "Dapper",
    "DbUp",
    "Dommel",
    "EFCore.BulkExtensions",
    "Elsa.EntityFrameworkCore",
    "EntityFramework",
    "EntityFramework.SqlServer",
    "EntityFrameworkCore.Triggers",
    "FluentMigrator",
    "FluentMigrator.Runner",
    "FreeSql",
    "FreeSql.Provider.SqlServer",
    "FreeSql.Provider.Sqlite",
    "Hangfire.SqlServer",
    "InfluxDB.Client",
    "LiteDB",
    "Marten",
    "Microsoft.Azure.Cosmos",
    "Microsoft.Data.SqlClient",
    "Microsoft.Data.Sqlite",
    "Microsoft.EntityFrameworkCore",
    "Microsoft.EntityFrameworkCore.Design",
    "Microsoft.EntityFrameworkCore.InMemory",
    "Microsoft.EntityFrameworkCore.Proxies",
    "Microsoft.EntityFrameworkCore.Relational",
    "Microsoft.EntityFrameworkCore.SqlServer",
    "Microsoft.EntityFrameworkCore.Sqlite",
    "Microsoft.EntityFrameworkCore.Tools",
    "MongoDB.Driver",
    "MySql.EntityFrameworkCore",
    "MySqlConnector",
    "NPoco",
    "Neo4j.Driver",
    "Npgsql",
    "Oracle.EntityFrameworkCore",
    "Oracle.ManagedDataAccess.Core",
    "PetaPoco.Core",
    "Pomelo.EntityFrameworkCore.MySql",
    "RavenDB.Client",
    "Realm",
    "RepoDb",
    "RepoDb.SqlServer",
    "Respawn",
    "RoundhousE",
    "SqlKata",
    "SqlKata.Execution",
    "SqlSugarCore",
    "System.Data.Odbc",
    "System.Data.OleDb",
    "System.Data.SqlClient",
    "Z.EntityFramework.Plus.EFCore",
    "linq2db",
    "linq2db.PostgreSQL",
    "linq2db.SqlServer",
]

# ------------------------------------------------------------
# MESSAGING_JOBS_AND_DISTRIBUTED_SYSTEMS
# Queues, Busse, Streaming, Scheduler, Background Jobs, Caching, verteilte Laufzeitframeworks
# ------------------------------------------------------------
MESSAGING_JOBS_AND_DISTRIBUTED_SYSTEMS = [
    "ActiveMQ.Artemis.Client",
    "Akka",
    "Akka.Cluster",
    "Akka.Persistence",
    "Akka.Remote",
    "Apache.NMS",
    "Apache.NMS.ActiveMQ",
    "Azure.Messaging.ServiceBus",
    "CAP",
    "CacheManager.Core",
    "CacheTower",
    "Confluent.Kafka",
    "Coravel",
    "DistributedLock",
    "DotPulsar",
    "EasyCaching.Core",
    "EasyCaching.Redis",
    "EasyNetQ",
    "Elsa",
    "Elsa.Activities.Http",
    "FusionCache",
    "Hangfire.Core",
    "Hangfire.Redis.StackExchange",
    "KafkaFlow",
    "LazyCache",
    "MQTTnet",
    "MassTransit",
    "MassTransit.Azure.ServiceBus.Core",
    "MassTransit.RabbitMQ",
    "Microsoft.Extensions.Caching.StackExchangeRedis",
    "NServiceBus",
    "NServiceBus.RabbitMQ",
    "NServiceBus.Transport.AzureServiceBus",
    "NetMQ",
    "Orleans",
    "Orleans.Clustering.Redis",
    "Orleans.Serialization.SystemTextJson",
    "Orleans.Server",
    "Quartz",
    "RabbitMQ.Client",
    "Rebus",
    "Rebus.AzureServiceBus",
    "Rebus.RabbitMq",
    "Rebus.ServiceProvider",
    "RedLock.net",
    "StackExchange.Redis",
    "StackExchange.Redis.Extensions.Core",
    "StackExchange.Redis.Extensions.Newtonsoft",
    "System.Runtime.Caching",
    "WorkflowCore",
]

# ------------------------------------------------------------
# LOGGING_MONITORING_AND_OBSERVABILITY
# Logging, Metrics, Tracing, APM, Profiling, Monitoring und Telemetrie
# ------------------------------------------------------------
LOGGING_MONITORING_AND_OBSERVABILITY = [
    "App.Metrics",
    "Elastic.Apm.NetCoreAll",
    "Jaeger",
    "Microsoft.ApplicationInsights",
    "MiniProfiler",
    "NLog",
    "NLog.Extensions.Logging",
    "OpenTelemetry",
    "OpenTelemetry.Api",
    "OpenTelemetry.Exporter.Console",
    "OpenTelemetry.Exporter.Jaeger",
    "OpenTelemetry.Exporter.OpenTelemetryProtocol",
    "OpenTelemetry.Exporter.Zipkin",
    "OpenTelemetry.Extensions.Hosting",
    "OpenTelemetry.Instrumentation.Http",
    "OpenTelemetry.Instrumentation.Runtime",
    "OpenTracing",
    "OpenTracing.Contrib.NetCore",
    "Sentry",
    "Sentry.Serilog",
    "Serilog",
    "Serilog.Exceptions",
    "Serilog.Extensions.Logging",
    "Serilog.Formatting.Compact",
    "Serilog.Settings.Configuration",
    "Serilog.Sinks.ApplicationInsights",
    "Serilog.Sinks.Async",
    "Serilog.Sinks.Console",
    "Serilog.Sinks.Debug",
    "Serilog.Sinks.File",
    "Serilog.Sinks.RollingFile",
    "Serilog.Sinks.Seq",
    "Steeltoe.CircuitBreaker.HystrixCore",
    "Steeltoe.Configuration.ConfigServerCore",
    "Steeltoe.Discovery.ClientCore",
    "Steeltoe.Management.EndpointCore",
    "Zipkin",
    "log4net",
    "prometheus-net",
]

# ------------------------------------------------------------
# CLOUD_AND_PLATFORM_SDKS
# Azure-, AWS-, Google- und andere Plattform-/SaaS-SDKs
# ------------------------------------------------------------
CLOUD_AND_PLATFORM_SDKS = [
    "AWSSDK.CloudWatchLogs",
    "AWSSDK.Core",
    "AWSSDK.DynamoDBv2",
    "AWSSDK.Extensions.NETCore.Setup",
    "AWSSDK.Lambda",
    "AWSSDK.S3",
    "AWSSDK.SQS",
    "AWSSDK.SecretsManager",
    "AWSSDK.SecurityToken",
    "AWSSDK.SimpleNotificationService",
    "Azure.AI.OpenAI",
    "Azure.Core",
    "Azure.Data.AppConfiguration",
    "Azure.Data.Tables",
    "Azure.Messaging.EventGrid",
    "Azure.Messaging.EventHubs",
    "Azure.Monitor.Query",
    "Azure.Search.Documents",
    "Azure.Storage.Blobs",
    "Azure.Storage.Files.DataLake",
    "Azure.Storage.Files.Shares",
    "Azure.Storage.Queues",
    "Google.Api.Gax",
    "Google.Api.Gax.Grpc",
    "Google.Cloud.Firestore",
    "Google.Cloud.Logging.V2",
    "Google.Cloud.PubSub.V1",
    "Google.Cloud.SecretManager.V1",
    "Google.Cloud.Spanner.Data",
    "Google.Cloud.Storage.V1",
    "Microsoft.Graph",
    "Microsoft.Graph.Core",
    "Microsoft.Rest.ClientRuntime",
]

# ------------------------------------------------------------
# SERIALIZATION_TEXT_AND_CONTENT
# JSON/YAML/CSV/Protobuf, Template-Engines, Text-/Markup-Verarbeitung, MIME/Mail
# ------------------------------------------------------------
SERIALIZATION_TEXT_AND_CONTENT = [
    "AngleSharp",
    "CsvHelper",
    "CsvHelper.Configuration",
    "CsvHelper.Excel",
    "CsvHelper.TypeConversion",
    "FluentAssertions.Json",
    "GeoJSON.Text",
    "Google.Protobuf",
    "Handlebars.Net",
    "HtmlAgilityPack",
    "Humanizer",
    "Jil",
    "JsonEverything.JsonSchema",
    "JsonSubTypes",
    "LanguageExt.Core",
    "MailKit",
    "Markdig",
    "MessagePack",
    "MessagePack.Annotations",
    "Microsoft.Extensions.Configuration.Json",
    "Mime-Detective",
    "MimeKit",
    "MoreLinq",
    "NJsonSchema",
    "NJsonSchema.Annotations",
    "Newtonsoft.Json",
    "Newtonsoft.Json.Bson",
    "OneOf",
    "RazorLight",
    "ReactiveUI",
    "ReactiveUI.Fody",
    "ReverseMarkdown",
    "Scriban",
    "ServiceStack.Text",
    "System.Collections.Immutable",
    "System.Formats.Asn1",
    "System.Formats.Cbor",
    "System.Reactive",
    "System.Reactive.Interfaces",
    "System.Reactive.Linq",
    "System.Text.Encodings.Web",
    "System.Text.Json",
    "System.Text.RegularExpressions",
    "Utf8Json",
    "ValueOf",
    "YamlDotNet",
    "YamlDotNet.Analyzers",
    "protobuf-net",
    "protobuf-net.Grpc",
]

# ------------------------------------------------------------
# DOCUMENTS_REPORTING_AND_MEDIA
# PDF, Office, Reporting, OCR, Barcode, Bild- und Grafikverarbeitung
# ------------------------------------------------------------
DOCUMENTS_REPORTING_AND_MEDIA = [
    "BarcodeLib",
    "ClosedXML",
    "DinkToPdf",
    "DocumentFormat.OpenXml",
    "DotNetZip",
    "EPPlus",
    "FastReport.OpenSource",
    "GemBox.Document",
    "GemBox.Spreadsheet",
    "HtmlRenderer.PdfSharp",
    "ImageMagick",
    "ImageProcessor",
    "ImageSharp",
    "Ionic.Zip",
    "IronPdf",
    "Magick.NET-Q8-AnyCPU",
    "NPOI",
    "PdfPig",
    "PdfSharpCore",
    "QRCoder",
    "QuestPDF",
    "SelectPdf",
    "SharpZipLib",
    "SixLabors.Fonts",
    "SixLabors.ImageSharp.Drawing",
    "SkiaSharp",
    "SkiaSharp.HarfBuzz",
    "SkiaSharp.NativeAssets.Linux",
    "SkiaSharp.Views",
    "Syncfusion.DocIO.Net.Core",
    "Syncfusion.Pdf.Net.Core",
    "Syncfusion.XlsIO.Net.Core",
    "System.Drawing.Common",
    "System.Drawing.Primitives",
    "Tesseract",
    "WkHtmlToPdf-DotNet",
    "ZXing.Net",
    "iText7",
    "itext7.pdfhtml",
]

# ------------------------------------------------------------
# NETWORKING_RPC_AND_PROTOCOLS
# HTTP-Clients, RPC, gRPC, WebSockets, DNS, SSH, ServiceModel, Socket- und Protokollbibliotheken
# ------------------------------------------------------------
NETWORKING_RPC_AND_PROTOCOLS = [
    "DnsClient",
    "Flurl",
    "Flurl.Http",
    "Grpc.Core",
    "Grpc.Core.Api",
    "Grpc.HealthCheck",
    "Grpc.Net.Client",
    "Grpc.Net.ClientFactory",
    "Grpc.Reflection",
    "Grpc.Tools",
    "MagicOnion.Abstractions",
    "MagicOnion.Client",
    "MagicOnion.Server",
    "Microsoft.Extensions.Http",
    "Polly",
    "Polly.Extensions.Http",
    "Refit",
    "Refit.HttpClientFactory",
    "RestEase",
    "RestSharp",
    "RichardSzalay.MockHttp",
    "SSH.NET",
    "SuperSocket",
    "System.Net.Http",
    "System.ServiceModel.Http",
    "System.ServiceModel.NetTcp",
    "System.ServiceModel.Primitives",
    "WebSocketSharp",
    "Websocket.Client",
]

# ------------------------------------------------------------
# DEPENDENCY_INJECTION_INFRASTRUCTURE_AND_UTILS
# DI-Container, Mediation, Konfiguration, Guard-/Utility-Bibliotheken, Core-Infrastruktur
# ------------------------------------------------------------
DEPENDENCY_INJECTION_INFRASTRUCTURE_AND_UTILS = [
    "Ardalis.GuardClauses",
    "Ardalis.Specification",
    "AsyncEx.Context",
    "AutoMapper",
    "Autofac",
    "Autofac.Extensions.DependencyInjection",
    "Ben.Demystifier",
    "Castle.Core",
    "DryIoc",
    "FluentValidation",
    "K4os.Compression.LZ4",
    "K4os.Hash.xxHash",
    "Lamar",
    "LightInject",
    "Mapster",
    "Mapster.DependencyInjection",
    "MediatR",
    "MediatR.Extensions.Microsoft.DependencyInjection",
    "MediatR.Pipeline",
    "MicroElements.Swashbuckle.FluentValidation",
    "Microsoft.Extensions.Caching.Memory",
    "Microsoft.Extensions.Configuration",
    "Microsoft.Extensions.Configuration.Abstractions",
    "Microsoft.Extensions.Configuration.Binder",
    "Microsoft.Extensions.Configuration.EnvironmentVariables",
    "Microsoft.Extensions.DependencyInjection",
    "Microsoft.Extensions.DependencyInjection.Abstractions",
    "Microsoft.Extensions.Diagnostics.HealthChecks",
    "Microsoft.Extensions.Diagnostics.HealthChecks.Abstractions",
    "Microsoft.Extensions.FileProviders.Abstractions",
    "Microsoft.Extensions.FileProviders.Physical",
    "Microsoft.Extensions.Hosting",
    "Microsoft.Extensions.Hosting.Abstractions",
    "Microsoft.Extensions.Logging",
    "Microsoft.Extensions.Logging.Abstractions",
    "Microsoft.Extensions.Options",
    "Microsoft.Extensions.Options.ConfigurationExtensions",
    "Microsoft.Extensions.Primitives",
    "Microsoft.IO.RecyclableMemoryStream",
    "Scrutor",
    "SimpleInjector",
    "SimpleInjector.Integration.ServiceCollection",
    "Snappier",
    "StructureMap",
    "System.Buffers",
    "System.IO.Pipelines",
    "System.Linq.Async",
    "System.Memory",
    "System.Threading.Channels",
    "UnitsNet",
    "Unity.Container",
    "ZstdSharp.Port",
]

# ------------------------------------------------------------
# BUILD_TOOLING_AND_CLI
# Build, NuGet-Ökosystem, Codegen, CLI-Frameworks, Test-/Coverage-Tooling
# ------------------------------------------------------------
BUILD_TOOLING_AND_CLI = [
    "CliWrap",
    "CommandLineParser",
    "Costura.Fody",
    "Fody",
    "McMaster.Extensions.CommandLineUtils",
    "Microsoft.Build",
    "Microsoft.Build.Utilities.Core",
    "Microsoft.NET.Test.Sdk",
    "Mono.Cecil",
    "NuGet.Frameworks",
    "NuGet.Protocol",
    "Spectre.Console",
    "Spectre.Console.Cli",
    "System.CommandLine",
    "coverlet.collector",
    "coverlet.msbuild",
]

# ------------------------------------------------------------
# TESTING_AND_QUALITY
# Testframeworks, Mocks, Assertions, Generatoren, Test-Helfer
# ------------------------------------------------------------
TESTING_AND_QUALITY = [
    "AutoBogus",
    "AutoFixture",
    "AutoFixture.AutoMoq",
    "AutoFixture.Xunit2",
    "Bogus",
    "FakeItEasy",
    "FluentAssertions",
    "FsCheck",
    "Moq",
    "Moq.AutoMock",
    "NSubstitute",
    "NUnit",
    "NUnit3TestAdapter",
    "Shouldly",
    "Verify.Xunit",
    "WireMock.Net",
    "xunit",
    "xunit.extensibility.core",
    "xunit.extensibility.execution",
    "xunit.runner.visualstudio",
]

# ------------------------------------------------------------
# UI_AUTOMATION_AND_CLIENTS
# UI, Desktop, Browser-Automation, Client-Frameworks
# ------------------------------------------------------------
UI_AUTOMATION_AND_CLIENTS = [
    "Avalonia",
    "Avalonia.Desktop",
    "ElectronNET.API",
    "Microsoft.Playwright",
    "PuppeteerSharp",
]

# ------------------------------------------------------------
# SEARCH_GEO_AND_ANALYTICS
# Suche, Elasticsearch, Lucene, Geo, Device/User-Agent-Analyse
# ------------------------------------------------------------
SEARCH_GEO_AND_ANALYTICS = [
    "DeviceDetector.NET",
    "Elastic.Clients.Elasticsearch",
    "Elasticsearch.Net",
    "Lucene.Net",
    "Lucene.Net.Analysis.Common",
    "Lucene.Net.QueryParser",
    "MaxMind.GeoIP2",
    "NEST",
    "NetTopologySuite",
    "UAParser",
]

# ------------------------------------------------------------
# Finale Paketliste
# ------------------------------------------------------------
NUGET_GROUND_TRUTH_PACKAGES = (
    WEB_MIDDLEWARE_AND_APIS
    +
    SECURITY_IDENTITY_AND_CRYPTO
    +
    DATA_DATABASE_AND_ORM
    +
    MESSAGING_JOBS_AND_DISTRIBUTED_SYSTEMS
    +
    LOGGING_MONITORING_AND_OBSERVABILITY
    +
    CLOUD_AND_PLATFORM_SDKS
    +
    SERIALIZATION_TEXT_AND_CONTENT
    +
    DOCUMENTS_REPORTING_AND_MEDIA
    +
    NETWORKING_RPC_AND_PROTOCOLS
    +
    DEPENDENCY_INJECTION_INFRASTRUCTURE_AND_UTILS
    +
    BUILD_TOOLING_AND_CLI
    +
    TESTING_AND_QUALITY
    +
    UI_AUTOMATION_AND_CLIENTS
    +
    SEARCH_GEO_AND_ANALYTICS
)

# ------------------------------------------------------------
# Validierung
# ------------------------------------------------------------
def _validate_nuget_package_universe(expected_size: int = 500) -> None:
    seen = set()
    duplicates = []
    for pkg in NUGET_GROUND_TRUTH_PACKAGES:
        if pkg in seen:
            duplicates.append(pkg)
        seen.add(pkg)

    if duplicates:
        raise ValueError(f"Duplicate NuGet packages detected: {sorted(set(duplicates))}")

    if len(NUGET_GROUND_TRUTH_PACKAGES) != expected_size:
        raise ValueError(f"Expected {expected_size} NuGet packages, got {len(NUGET_GROUND_TRUTH_PACKAGES)}")

_validate_nuget_package_universe()