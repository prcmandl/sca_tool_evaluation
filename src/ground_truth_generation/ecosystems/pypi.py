import logging
import requests
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple

from ..osv_common import request_json_with_retry
from ..osv_common import within_date_window
from ..osv_common import API_CALL_TRACKER


log = logging.getLogger(__name__)


# --------------------------------------------------
# Version cutoff (orthogonal zu samples)
# --------------------------------------------------

from ground_truth_generation.osv_common import env_int

PYPI_MAX_VERSIONS_PER_PACKAGE = env_int(
    "PYPI_MAX_VERSIONS_PER_PACKAGE",
    5,
)


# ------------------------------------------------------------------
# Explicit PyPI package universe for ground truth construction
# ------------------------------------------------------------------

PYPI_GROUND_TRUTH_PACKAGES = [
    # Core networking / utils
    "requests", "urllib3", "idna", "certifi", "charset-normalizer",
    "six", "setuptools", "wheel", "packaging", "pip",

    # Web frameworks
    "flask", "django", "fastapi", "starlette", "uvicorn",
    "gunicorn", "jinja2", "werkzeug", "itsdangerous", "markupsafe",

    # Data / ORM
    "sqlalchemy", "alembic", "psycopg2", "psycopg2-binary",
    "pymysql", "redis", "mongoengine", "peewee", "dataset", "pony",

    # Task queues
    "celery", "kombu", "billiard", "rq", "dramatiq",

    # Scientific stack
    "numpy", "scipy", "pandas", "matplotlib", "seaborn",
    "scikit-learn", "statsmodels", "sympy", "numba", "xarray",

# "tensorflow" ausgewechseltdurch "transformers", weil es so oft vorkommt

    # ML / AI
    "transformers", "keras", "torch", "torchvision", "torchaudio",
    "onnx", "onnxruntime", "lightgbm", "xgboost", "catboost",

    # Parsing / formats
    "pyyaml", "toml", "tomli", "configparser", "click",
    "typer", "rich", "colorama", "tqdm",

    # HTML / parsing
    "lxml", "beautifulsoup4", "soupsieve", "bleach", "markdown",
    "mistune", "docutils", "html5lib", "feedparser", "readme-renderer",

    # Images / media
    "pillow", "opencv-python", "imageio", "moviepy", "wand",

    # Security / crypto
    "cryptography", "pyopenssl", "paramiko", "bcrypt", "passlib",
    "python-jwt", "jwt", "pycryptodome", "argon2-cffi", "itsdangerous",

    # Testing
    "pytest", "hypothesis", "coverage", "tox", "virtualenv",
    "nose", "nose2", "pytest-cov", "pytest-mock", "freezegun",

    # Async / IO
    "aiohttp", "asyncio", "trio", "curio", "httpx",

    # CLI / tooling
    "invoke", "fabric", "cliff", "cement", "docopt",

    # Serialization
    "pickle5", "msgpack", "ujson", "orjson", "simplejson",

    # Misc
    "python-dateutil", "pytz", "tzdata", "attrs", "dataclasses",
    "importlib-metadata", "importlib-resources", "typing-extensions",
    "pathlib2", "filelock",

    # Cloud / APIs
    "boto3", "botocore", "s3transfer", "google-cloud-storage",
    "google-api-python-client",

    # Monitoring
    "prometheus-client", "sentry-sdk", "opencensus", "elastic-apm",

    # Config / env
    "python-dotenv", "dynaconf", "envparse", "configobj",

    # Final padding to reach 200
    "tabulate", "humanize", "watchdog", "psutil", "setproctitle",
    "retrying", "tenacity", "backoff", "cachetools", "diskcache",
]



# --------------------------------------------------
# OSV URL
# --------------------------------------------------

OSV_QUERY_URL = "https://api.osv.dev/v1/query"



# --------------------------------------------------
# Helpers
# --------------------------------------------------

def _parse_iso_date(date_str: Optional[str]) -> Optional[datetime]:
    """
    Parse YYYY-MM-DD into a timezone-aware UTC datetime.
    """
    if date_str is None:
        return None
    return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)


# --------------------------------------------------
# PyPI Ground Truth Collector
# --------------------------------------------------

def collect_pypi(
    samples: Optional[int],
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    osv_cache: Dict[Tuple[str, str, str], Dict[str, Any]] = None,
) -> List[Dict]:

    start_dt = _parse_iso_date(start_date)
    end_dt = _parse_iso_date(end_date)

    # --------------------------------------------------
    # APPLY SAMPLES (EXACTLY like Maven)
    # --------------------------------------------------
    packages = PYPI_GROUND_TRUTH_PACKAGES
    if samples is not None:
        packages = packages[:samples]

    log.info(
        "PyPI scope: using %d/%d packages",
        len(packages),
        len(PYPI_GROUND_TRUTH_PACKAGES),
    )

    rows: List[Dict] = []

    for pkg in packages:
        log.info("PyPI package selected: %s", pkg)

        # --------------------------------------------------
        # PyPI METADATA API CALL (TRACKED)
        # --------------------------------------------------
        pypi_token = API_CALL_TRACKER.start("PyPI")
        try:
            meta = requests.get(
                f"https://pypi.org/pypi/{pkg}/json",
                timeout=30,
            ).json()
        except Exception:
            continue
        finally:
            API_CALL_TRACKER.end("PyPI", pypi_token)

        releases = meta.get("releases", {})
        versions = sorted(releases.keys(), reverse=True)

        if PYPI_MAX_VERSIONS_PER_PACKAGE is not None:
            versions = versions[:PYPI_MAX_VERSIONS_PER_PACKAGE]

        log.info(
            "PyPI %s: processing %d versions",
            pkg,
            len(versions),
        )

        for version in versions:
            files = releases.get(version, [])
            if not files:
                continue

            # PyPI: multiple files per version → take earliest upload timestamp
            upload_times = [
                f.get("upload_time_iso_8601")
                for f in files
                if f.get("upload_time_iso_8601")
            ]
            if not upload_times:
                continue

            published = datetime.fromisoformat(
                min(upload_times).replace("Z", "+00:00")
            )

            # --------------------------------------------------
            # DATE WINDOW FILTER
            # --------------------------------------------------
            if not within_date_window(published, start_dt, end_dt):
                log.info(
                    "Skipping PyPI version due to date window | "
                    "pkg=%s | version=%s | published=%s",
                    pkg,
                    version,
                    published.date(),
                )
                continue

            log.info(
                "Examining component: ecosystem=pypi | name=%s | version=%s",
                pkg,
                version,
            )

            payload = {
                "package": {"ecosystem": "PyPI", "name": pkg},
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

            cache_key = ("pypi", pkg, version)
            if osv_cache is not None:
                osv_cache[cache_key] = res

            for vuln in res.get("vulns", []):
                osv_id = vuln.get("id")
                if not osv_id:
                    continue

                aliases = vuln.get("aliases") or []
                cve = next((a for a in aliases if a.startswith("CVE-")), None)

                purl = f"pkg:pypi/{pkg}@{version}"

                rows.append({
                    "ecosystem": "pypi",
                    "component_name": pkg,
                    "component_version": version,
                    "purl": purl,
                    "vulnerability_id": osv_id,
                    "cve": cve,
                    "is_vulnerable": True,
                })

    log.info(
        "PyPI finished | packages=%d | rows=%d",
        len(packages),
        len(rows),
    )

    return rows
