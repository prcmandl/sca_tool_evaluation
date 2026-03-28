import logging
import requests

from ground_truth_generation.osv_common import (
    request_json_with_retry,
    parse_iso_date,
    env_int
)


TARGET_VULNS_PER_ECOSYSTEM = env_int(
    "TARGET_VULNS_PER_ECOSYSTEM",
    None,
)

PYPI_MAX_VERSIONS_PER_PACKAGE = env_int("PYPI_MAX_VERSIONS_PER_PACKAGE", 5)
MAX_OSV_ENTRIES_PER_COMPONENT = env_int("MAX_OSV_ENTRIES_PER_COMPONENT", 10)

log = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


# -----------------------------
# Kuratierte Komponentenliste
# -----------------------------
PYPI_GROUND_TRUTH_PACKAGES = [

# ----------------------------
# Networking / HTTP (10)
# ----------------------------
"requests","urllib3","httpx","aiohttp","httpcore","h11","h2","wsproto","websockets","anyio",

# ----------------------------
# Web frameworks (10)
# ----------------------------
"flask","django","fastapi","starlette","werkzeug","quart","falcon","bottle","tornado","sanic",

# ----------------------------
# Security / crypto (10)
# ----------------------------
"cryptography","pyopenssl","bcrypt","passlib","paramiko","pynacl","itsdangerous","python-jose","jwcrypto","hashids",

# ----------------------------
# Parsing / formats (10)
# ----------------------------
"pyyaml","ruamel.yaml","lxml","beautifulsoup4","html5lib","markdown","mistune","docutils","xmltodict","defusedxml",

# ----------------------------
# JSON / serialization (10)
# ----------------------------
"orjson","ujson","jsonschema","pydantic","msgpack","cbor2","marshmallow","dataclasses-json","jsonpickle","simplejson",

# ----------------------------
# Data / ML (10)
# ----------------------------
"numpy","pandas","scipy","scikit-learn","xgboost","lightgbm","catboost","statsmodels","sympy","networkx",

# ----------------------------
# Deep learning (10)
# ----------------------------
"torch","torchvision","torchaudio","tensorflow","keras","jax","flax","transformers","datasets","accelerate",

# ----------------------------
# Packaging (10)
# ----------------------------
"pip","setuptools","wheel","build","twine","virtualenv","pipenv","poetry","installer","distlib",

# ----------------------------
# CLI / tooling (10)
# ----------------------------
"click","typer","rich","loguru","argcomplete","colorama","tqdm","fire","cement","docopt",

# ----------------------------
# Async / concurrency (10)
# ----------------------------
"trio","curio","gevent","eventlet","asyncio","aiomysql","aiosqlite","uvloop","janus","sniffio",

# ----------------------------
# DB / storage (10)
# ----------------------------
"sqlalchemy","psycopg2","psycopg2-binary","pymysql","mysqlclient","redis","mongoengine","pymongo","tinydb","dataset",

# ----------------------------
# Testing (10)
# ----------------------------
"pytest","pytest-cov","pytest-asyncio","tox","hypothesis","nose2","coverage","unittest2","pytest-mock","pytest-xdist",

# ----------------------------
# Images / files (10)
# ----------------------------
"pillow","opencv-python","imageio","python-magic","filetype","wand","pdfminer.six","PyPDF2","reportlab","python-docx",

# ----------------------------
# Logging / monitoring (10)
# ----------------------------
"structlog","logbook","sentry-sdk","prometheus-client","elastic-apm","opentelemetry-api","opentelemetry-sdk","watchdog","psutil","statsd",

# ----------------------------
# Dev / utilities (10)
# ----------------------------
"attrs","boltons","toolz","funcy","more-itertools","sortedcontainers","zipp","importlib-metadata","pluggy","packaging",

# ----------------------------
# Misc high CVE relevance (10)
# ----------------------------
"jinja2","markupsafe","bleach","python-dateutil","pytz","pendulum","dateparser","croniter","tzlocal","arrow",

# ----------------------------
# Networking / protocols (10)
# ----------------------------
"dnspython","netaddr","ifaddr","scapy","pyroute2","fabric","asyncssh","pysftp","ftplib3","async-timeout",

# ----------------------------
# Compression / archive (10)
# ----------------------------
"zipfile36","rarfile","py7zr","lz4","zstandard","brotli","python-snappy","patool","gzipstream","tarfile",

# ----------------------------
# Cloud / SDKs (10)
# ----------------------------
"boto3","botocore","google-cloud-storage","google-cloud-core","azure-storage-blob","azure-identity","minio","s3fs","gcsfs","adlfs",

# ----------------------------
# Config / env (10)
# ----------------------------
"python-dotenv","dynaconf","omegaconf","configparser","envparse","decouple","yacs","hydra-core","confuse","configobj",

# ----------------------------
# Validation / schema (10)
# ----------------------------
"cerberus","voluptuous","trafaret","schema","pydantic-settings","validators","email-validator","phonenumbers","rfc3987","jsonschema-rs",

]


# --------------------------------------------------
# OSV URL
# --------------------------------------------------

OSV_QUERY_URL = "https://api.osv.dev/v1/query"



def collect_pypi(
    samples,
    start_date=None,
    end_date=None,
    osv_cache=None,
):
    start_dt = parse_iso_date(start_date)
    end_dt = parse_iso_date(end_date)

    TARGET = env_int("TARGET_VULNS_PER_ECOSYSTEM", None)

    packages = PYPI_GROUND_TRUTH_PACKAGES[:samples] if samples else PYPI_GROUND_TRUTH_PACKAGES

    rows = []
    total_vulns = 0
    total_packages = len(packages)

    for i, pkg in enumerate(packages, 1):
        component_vulns = 0

        try:
            meta = requests.get(f"https://pypi.org/pypi/{pkg}/json", timeout=30).json()
        except Exception:
            log.info("[%d/%d] Processing package %s; 0 vulnerabilities", i, total_packages, pkg)
            continue

        versions = sorted(meta.get("releases", {}).keys(), reverse=True)

        if PYPI_MAX_VERSIONS_PER_PACKAGE:
            versions = versions[:PYPI_MAX_VERSIONS_PER_PACKAGE]

        for version in versions:
            payload = {"package": {"ecosystem": "PyPI", "name": pkg}, "version": version}

            res = request_json_with_retry(OSV_QUERY_URL, payload)
            if not isinstance(res, dict):
                continue

            if osv_cache is not None:
                osv_cache[("pypi", pkg, version)] = res

            vulns = res.get("vulns", [])[:MAX_OSV_ENTRIES_PER_COMPONENT]
            seen = set()

            for v in vulns:
                vid = v.get("id")
                if not vid or vid in seen:
                    continue
                seen.add(vid)

                rows.append({
                    "ecosystem": "pypi",
                    "component_name": pkg,
                    "component_version": version,
                    "purl": f"pkg:pypi/{pkg}@{version}",
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
