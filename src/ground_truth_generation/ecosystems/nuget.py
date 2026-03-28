import logging
import requests
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

from packaging.version import Version, InvalidVersion

from ground_truth_generation.osv_common import (
    request_json_with_retry,
    within_date_window,
    parse_iso_date,
    API_CALL_TRACKER,
    env_int,
)

log = logging.getLogger("nuget")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# --------------------------------------------------
# Version cutoff (orthogonal zu samples)
# --------------------------------------------------
NUGET_MAX_VERSIONS_PER_PACKAGE = env_int(
    "NUGET_MAX_VERSIONS_PER_PACKAGE",
    10,
)

MAX_OSV_ENTRIES_PER_COMPONENT = env_int(
    "MAX_OSV_ENTRIES_PER_COMPONENT",
    20,
)

TARGET_VULNS_PER_ECOSYSTEM = env_int(
    "TARGET_VULNS_PER_ECOSYSTEM",
    None,
)

EARLY_STOP_ON_TARGET_VULNS = bool(
    env_int("EARLY_STOP_ON_TARGET_VULNS", 1)
)

# --------------------------------------------------
# This is a curated list of popular and relevant
# NuGet packages across various categories.
# --------------------------------------------------
""" 
old list
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
"""
# ------------------------------------------------------------
# WEB_MIDDLEWARE_AND_APIS
# Middleware, ASP.NET Core, HTTP-Pipeline, Routing, OpenAPI,
# API-Versionierung, GraphQL-Webserver
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

def _fetch_json(url: str) -> Optional[dict]:
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else None
    except Exception:
        log.exception("Failed to fetch JSON from %s", url)
        return None


def _iter_registration_items(index_data: dict) -> List[dict]:
    """
    Flatten NuGet registration index items.
    Some pages inline their leaf items under page["items"].
    Others require an additional fetch via page["@id"].
    """
    out: List[dict] = []

    for page in index_data.get("items", []):
        page_items = page.get("items")
        if isinstance(page_items, list):
            out.extend(page_items)
            continue

        page_url = page.get("@id")
        if not page_url:
            continue

        page_data = _fetch_json(page_url)
        if not page_data:
            continue

        fetched_items = page_data.get("items", [])
        if isinstance(fetched_items, list):
            out.extend(fetched_items)

    return out


def _sample_evenly(
    versions: List[Tuple[str, datetime]],
    limit: Optional[int],
) -> List[Tuple[str, datetime]]:
    if limit is None or limit <= 0 or len(versions) <= limit:
        return versions

    if limit == 1:
        return [versions[-1]]

    max_idx = len(versions) - 1
    raw_indices = [
        round(k * max_idx / (limit - 1))
        for k in range(limit)
    ]

    seen = set()
    indices = []
    for idx in raw_indices:
        if idx not in seen:
            indices.append(idx)
            seen.add(idx)

    return [versions[idx] for idx in indices]



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
    log.info(
        "NuGet config | max_versions_per_package=%s | max_osv_entries_per_component=%s | target_vulns=%s | early_stop=%s",
        NUGET_MAX_VERSIONS_PER_PACKAGE,
        MAX_OSV_ENTRIES_PER_COMPONENT,
        TARGET_VULNS_PER_ECOSYSTEM,
        EARLY_STOP_ON_TARGET_VULNS,
    )

    rows: List[Dict] = []
    total_vulns = 0
    total_packages = len(packages)

    for i, pkg in enumerate(packages, start=1):
        component_vulns = 0

        nuget_token = API_CALL_TRACKER.start("NuGet")
        try:
            versions = _fetch_nuget_versions_with_dates(pkg)
        finally:
            API_CALL_TRACKER.end("NuGet", nuget_token)

        if not versions:
            log.info("[%d/%d] Processing package %s; no versions found", i, total_packages, pkg)
            continue

        # First apply the date window
        versions = [
            (version, published)
            for version, published in versions
            if within_date_window(published, start_dt, end_dt)
        ]

        if not versions:
            log.info(
                "[%d/%d] Processing package %s; 0 vulnerabilities (no versions in date window)",
                i,
                total_packages,
                pkg,
            )
            continue

        # Then sample evenly across the filtered version history
        versions = _sample_evenly(versions, NUGET_MAX_VERSIONS_PER_PACKAGE)

        log.debug(
            "%s: %d versions after date filter and sampling",
            pkg,
            len(versions),
        )

        for version, published in versions:
            _ = published

            payload = {
                "package": {"ecosystem": "NuGet", "name": pkg},
                "version": version,
            }

            osv_token = API_CALL_TRACKER.start("OSV")
            try:
                res = request_json_with_retry(OSV_QUERY_URL, payload)
            except Exception:
                log.exception("%s@%s: OSV request failed", pkg, version)
                continue
            finally:
                API_CALL_TRACKER.end("OSV", osv_token)

            if not isinstance(res, dict):
                log.info("%s@%s: invalid OSV response", pkg, version)
                continue

            if osv_cache is not None:
                osv_cache[("nuget", pkg, version)] = res

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

                component_vulns += 1
                total_vulns += 1

                if (
                    EARLY_STOP_ON_TARGET_VULNS
                    and TARGET_VULNS_PER_ECOSYSTEM is not None
                    and total_vulns >= TARGET_VULNS_PER_ECOSYSTEM
                ):
                    log.info(
                        "[%d/%d] Processing package %s; %d vulnerabilities",
                        i,
                        total_packages,
                        pkg,
                        component_vulns,
                    )
                    log.info("Stopping early at %d vulnerabilities", total_vulns)
                    return rows[:TARGET_VULNS_PER_ECOSYSTEM]

        log.info(
            "[%d/%d] Processing package %s; %d vulnerabilities",
            i,
            total_packages,
            pkg,
            component_vulns,
        )

    log.info(
        "NuGet finished | packages=%d | rows=%d",
        len(packages),
        len(rows),
    )

    return rows
