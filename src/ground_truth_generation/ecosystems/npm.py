import logging
import requests
from datetime import datetime
from typing import List, Tuple

from packaging.version import Version, InvalidVersion

from ground_truth_generation.osv_common import (
    request_json_with_retry,
    within_date_window,
    parse_iso_date,
    env_int,
)

TARGET_VULNS_PER_ECOSYSTEM = env_int(
    "TARGET_VULNS_PER_ECOSYSTEM",
    None,
)

log = logging.getLogger("npm")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# --------------------------------------------------
# Configuration
# --------------------------------------------------

NPM_MAX_VERSIONS_PER_PACKAGE = env_int(
    "NPM_MAX_VERSIONS_PER_PACKAGE",
    10,
)

MAX_OSV_ENTRIES_PER_COMPONENT = env_int(
    "MAX_OSV_ENTRIES_PER_COMPONENT",
    10,
)

# --------------------------------------------------
# # Kuratierte Komponentenliste
# --------------------------------------------------
NPM_GROUND_TRUTH_PACKAGES = [

# ----------------------------
# Core utils
# ----------------------------
"lodash","underscore","minimist","braces","micromatch","glob-parent","yargs-parser",

# ----------------------------
# HTTP / networking
# ----------------------------
"axios","request","node-fetch","got","superagent","follow-redirects","http-proxy","proxy-addr","send","serve-static",

# ----------------------------
# Web frameworks
# ----------------------------
"express","koa","hapi","restify","connect","fastify","polka","sails","total.js","derby",

# ----------------------------
# Middleware
# ----------------------------
"body-parser","cookie","cookie-parser","cors","helmet","morgan","multer","csurf","serve-favicon","compression",

# ----------------------------
# Auth / security
# ----------------------------
"jsonwebtoken","bcrypt","bcryptjs","crypto-js","uuid","passport","passport-local","passport-jwt","oauth2-server","node-forge",

# ----------------------------
# Build / bundling
# ----------------------------
"webpack","webpack-cli","webpack-dev-server","rollup","parcel","browserify","esbuild","vite","gulp","grunt",

# ----------------------------
# Minifiers / JS processing
# ----------------------------
"uglify-js","terser","babel-core","@babel/core","@babel/parser","@babel/runtime","babel-loader","swc","sucrase","acorn",

# ----------------------------
# Parsing / formats
# ----------------------------
"json5","yaml","js-yaml","qs","xml2js","fast-xml-parser","csv-parse","papaparse",

# ----------------------------
# CSS
# ----------------------------
"postcss","css-loader","style-loader","sass","less","node-sass","autoprefixer","cssnano","tailwindcss","styled-components",

# ----------------------------
# Databases
# ----------------------------
"mongodb","mongoose","mysql","mysql2","pg","redis","ioredis","sequelize","knex","nedb",

# ----------------------------
# Messaging / realtime
# ----------------------------
"socket.io","ws","mqtt","amqplib","stompjs","faye","sockjs","primus","engine.io","nats",

# ----------------------------
# Date / validation
# ----------------------------
"moment","dayjs","date-fns","ajv","joi","validator","yup","superstruct","zod","class-validator",

# ----------------------------
# Testing
# ----------------------------
"mocha","chai","jest","sinon","supertest","ava","tap","vitest","cypress","karma",

# ----------------------------
# CLI
# ----------------------------
"commander","yargs","inquirer","ora","execa","chalk","listr","enquirer","meow",

# ----------------------------
# Files / streams
# ----------------------------
"fs-extra","glob","rimraf","mkdirp","tar","archiver","unzipper","formidable","busboy",

# ----------------------------
# Process / env
# ----------------------------
"dotenv","cross-env","nodemon","pm2","forever","signal-exit","pidusage","env-cmd","config",

# ----------------------------
# Logging
# ----------------------------
"winston","bunyan","pino","debug","loglevel","npmlog","signale","roarr","electron-log",

# ----------------------------
# Cloud / APIs
# ----------------------------
"aws-sdk","@aws-sdk/client-s3","@google-cloud/storage","@azure/storage-blob","firebase-admin","twilio","stripe","sendgrid","mailgun-js","algoliasearch",

# ----------------------------
# Frontend frameworks
# ----------------------------
"react","react-dom","vue","angular","svelte","preact","lit","next","nuxt","gatsby",

# ----------------------------
# Observability
# ----------------------------
"prom-client","elastic-apm-node","@sentry/node","opentelemetry-api","opentelemetry-sdk","newrelic","dd-trace","zipkin","jaeger-client",

# ----------------------------
# Misc vuln-relevant
# ----------------------------
"serialize-javascript","handlebars","ejs","pug","mustache","marked","showdown","dompurify","sanitize-html","xss",
]

# --------------------------------------------------
# Helpers
# --------------------------------------------------

def _fetch_npm_versions_with_dates(pkg: str) -> List[Tuple[str, datetime]]:
    url = f"https://registry.npmjs.org/{pkg}"

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
    except Exception:
        log.exception("Failed to fetch npm versions for %s", pkg)
        return []

    time_index = data.get("time", {})
    versions = []

    for ver in data.get("versions", {}).keys():
        try:
            pv = Version(ver)
            if pv.is_prerelease or pv.is_devrelease:
                continue
        except InvalidVersion:
            continue

        published_raw = time_index.get(ver)
        if not published_raw:
            continue

        try:
            published = datetime.fromisoformat(
                published_raw.replace("Z", "+00:00")
            )
        except ValueError:
            continue

        versions.append((ver, published))

    return sorted(versions, key=lambda x: Version(x[0]))

# --------------------------------------------------
# Collector
# --------------------------------------------------

def collect_npm(
    samples,
    start_date=None,
    end_date=None,
    osv_cache=None,
):
    start_dt = parse_iso_date(start_date)
    end_dt = parse_iso_date(end_date)

    TARGET = env_int("TARGET_VULNS_PER_ECOSYSTEM", None)

    packages = NPM_GROUND_TRUTH_PACKAGES[:samples] if samples else NPM_GROUND_TRUTH_PACKAGES

    rows = []
    total_vulns = 0
    total_packages = len(packages)

    for i, pkg in enumerate(packages, 1):
        component_vulns = 0

        versions = _fetch_npm_versions_with_dates(pkg)

        if NPM_MAX_VERSIONS_PER_PACKAGE:
            versions = versions[:NPM_MAX_VERSIONS_PER_PACKAGE]

        for version, published in versions:
            if not within_date_window(published, start_dt, end_dt):
                continue

            payload = {"package": {"ecosystem": "npm", "name": pkg}, "version": version}
            res = request_json_with_retry(OSV_QUERY_URL, payload)

            if not isinstance(res, dict):
                continue

            if osv_cache is not None:
                osv_cache[("npm", pkg, version)] = res

            vulns = res.get("vulns", [])[:MAX_OSV_ENTRIES_PER_COMPONENT]
            seen = set()

            for v in vulns:
                vid = v.get("id")
                if not vid or vid in seen:
                    continue
                seen.add(vid)

                rows.append({
                    "ecosystem": "npm",
                    "component_name": pkg,
                    "component_version": version,
                    "purl": f"pkg:npm/{pkg}@{version}",
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