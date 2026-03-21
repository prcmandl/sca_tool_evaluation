import logging
import requests
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple

from packaging.version import Version, InvalidVersion

from ground_truth_generation.osv_common import (
    request_json_with_retry,
    within_date_window,
    parse_iso_date,
)

from ..osv_common import API_CALL_TRACKER

log = logging.getLogger("npm")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# --------------------------------------------------
# Version cutoff (orthogonal zu samples)
# --------------------------------------------------

from ..osv_common import env_int

NPM_MAX_VERSIONS_PER_PACKAGE = env_int(
    "NPM_MAX_VERSIONS_PER_PACKAGE",
    9,
)

# --------------------------------------------------
# Explicit npm universe
# --------------------------------------------------

NPM_GROUND_TRUTH_PACKAGES = [
    # Core utilities
    "lodash", "underscore", "minimist", "kind-of", "braces",
    "micromatch", "semver", "chalk", "debug", "ms",

    # HTTP / networking
    "axios", "follow-redirects", "request", "got", "node-fetch",
    "superagent", "http-proxy", "proxy-addr", "send", "serve-static",

    # Web frameworks
    "express", "body-parser", "cookie", "cookie-parser", "cors",
    "helmet", "morgan", "multer", "koa", "koa-router",

    # Auth / security
    "jsonwebtoken", "bcrypt", "bcryptjs", "crypto-js", "uuid",
    "passport", "passport-local", "passport-jwt",

    # Build / bundling
    "webpack", "webpack-cli", "webpack-dev-server",
    "html-webpack-plugin", "terser", "uglify-js", "rollup", "parcel",

    # Parsing
    "acorn", "esprima", "espree", "json5", "yaml",

    # Linting / transpile
    "eslint", "eslint-scope", "eslint-utils",
    "babel-core", "@babel/core", "@babel/parser", "@babel/runtime",

    # CSS
    "postcss", "css-loader", "style-loader", "sass", "less",

    # Databases
    "mongodb", "mongoose", "mysql", "mysql2", "pg",
    "redis", "ioredis", "sequelize", "knex",

    # Messaging
    "amqplib", "ws", "socket.io", "mqtt", "stompjs",

    # Date / validation
    "moment", "dayjs", "date-fns", "ajv", "joi", "validator",

    # Testing
    "mocha", "chai", "jest", "sinon", "supertest",

    # CLI
    "commander", "yargs", "inquirer", "ora", "execa",

    # Files / streams
    "fs-extra", "glob", "rimraf", "mkdirp", "tar",

    # Process / env
    "dotenv", "cross-env", "node-notifier", "nodemon",

    # Logging
    "winston", "bunyan", "pino",

    # Cloud / APIs
    "aws-sdk", "@google-cloud/storage", "@azure/storage-blob",

    # Frontend
    "react", "react-dom", "vue", "angular", "svelte",

    # Observability
    "prom-client", "elastic-apm-node", "@sentry/node",

    # Final padding to reach 200
    "uuidv4", "shortid", "nanoid", "classnames", "prop-types",
    "immer", "rxjs", "zone.js", "core-js", "tslib",
]



# --------------------------------------------------
# Helpers
# --------------------------------------------------

def _fetch_npm_versions_with_dates(
    pkg: str,
) -> List[Tuple[str, datetime]]:
    """
    Fetch stable npm versions together with their published date.

    Versions without a published timestamp are discarded.
    """
    url = f"https://registry.npmjs.org/{pkg}"

    try:
        data = requests.get(url, timeout=30).json()
    except Exception:
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

    return sorted(versions, key=lambda x: Version(x[0]), reverse=True)


# --------------------------------------------------
# Collector
# --------------------------------------------------

def collect_npm(
    samples: Optional[int],
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    osv_cache: Dict[Tuple[str, str, str], Dict[str, Any]] = None,
) -> List[Dict]:

    start_dt = parse_iso_date(start_date)
    end_dt = parse_iso_date(end_date)

    packages = NPM_GROUND_TRUTH_PACKAGES
    if samples is not None:
        packages = packages[:samples]

    log.info(
        "npm scope: using %d/%d packages",
        len(packages),
        len(NPM_GROUND_TRUTH_PACKAGES),
    )

    rows: List[Dict] = []

    for pkg in packages:
        log.info("npm package selected: %s", pkg)

        # --------------------------------------------------
        # npm REGISTRY API CALL (TRACKED)
        # --------------------------------------------------
        npm_token = API_CALL_TRACKER.start("npm")
        try:
            versions = _fetch_npm_versions_with_dates(pkg)
        finally:
            API_CALL_TRACKER.end("npm", npm_token)

        if not versions:
            continue

        if NPM_MAX_VERSIONS_PER_PACKAGE is not None:
            versions = versions[:NPM_MAX_VERSIONS_PER_PACKAGE]

        log.info(
            "npm %s: processing %d versions",
            pkg,
            len(versions),
        )

        for version, published in versions:
            if not within_date_window(published, start_dt, end_dt):
                continue

            log.info(
                "Examining component: ecosystem=npm | name=%s | version=%s",
                pkg,
                version,
            )

            payload = {
                "package": {"ecosystem": "npm", "name": pkg},
                "version": version,
            }

            # --------------------------------------------------
            # OSV QUERY API CALL (TRACKED)
            # --------------------------------------------------
            osv_token = API_CALL_TRACKER.start("OSV")
            try:
                res = request_json_with_retry(OSV_QUERY_URL, payload)
            finally:
                API_CALL_TRACKER.end("OSV", osv_token)

            if not isinstance(res, dict):
                continue

            if osv_cache is not None:
                osv_cache[("npm", pkg, version)] = res

            for vuln in res.get("vulns", []):
                osv_id = vuln.get("id")
                if not osv_id:
                    continue

                aliases = vuln.get("aliases") or []
                cve = next((a for a in aliases if a.startswith("CVE-")), None)

                purl = f"pkg:npm/{pkg}@{version}"

                rows.append({
                    "ecosystem": "npm",
                    "component_name": pkg,
                    "component_version": version,
                    "purl": purl,
                    "vulnerability_id": osv_id,
                    "cve": cve,
                    "is_vulnerable": True,
                })

    log.info(
        "npm finished | packages=%d | rows=%d",
        len(packages),
        len(rows),
    )

    return rows
