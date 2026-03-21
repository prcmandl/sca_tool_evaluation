import logging
import requests
import xml.etree.ElementTree as ET
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone

from packaging.version import Version, InvalidVersion

from ground_truth_generation.osv_common import (
    request_json_with_retry,
    within_date_window,
    parse_iso_date,
)

from ..osv_common import env_int

from ..osv_common import API_CALL_TRACKER

# --------------------------------------------------
# Version cutoff (orthogonal zu samples)
# --------------------------------------------------

MAVEN_MAX_VERSIONS_PER_PACKAGE = env_int(
    "MAVEN_MAX_VERSIONS_PER_PACKAGE",
    10,
)

log = logging.getLogger("maven")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"



# --------------------------------------------------
# Explicit Maven artifact universe
# --------------------------------------------------

MAVEN_GROUND_TRUTH_PACKAGES = [
    # Apache Commons
    "org.apache.commons:commons-lang",
    "org.apache.commons:commons-lang3",
    "org.apache.commons:commons-io",
    "org.apache.commons:commons-collections",
    "org.apache.commons:commons-collections4",
    "org.apache.commons:commons-compress",
    "org.apache.commons:commons-text",
    "org.apache.commons:commons-beanutils",
    "org.apache.commons:commons-fileupload",
    "org.apache.commons:commons-validator",

    # Logging
    "org.apache.logging.log4j:log4j-core",
    "org.apache.logging.log4j:log4j-api",
    "log4j:log4j",
    "ch.qos.logback:logback-core",
    "ch.qos.logback:logback-classic",
    "org.slf4j:slf4j-api",

    # Spring
    "org.springframework:spring-core",
    "org.springframework:spring-context",
    "org.springframework:spring-web",
    "org.springframework:spring-webmvc",
    "org.springframework:spring-beans",
    "org.springframework.boot:spring-boot",
    "org.springframework.boot:spring-boot-autoconfigure",

    # Persistence
    "org.hibernate:hibernate-core",
    "org.hibernate:hibernate-validator",
    "javax.persistence:javax.persistence-api",
    "org.mybatis:mybatis",

    # JSON / XML
    "com.fasterxml.jackson.core:jackson-core",
    "com.fasterxml.jackson.core:jackson-databind",
    "com.fasterxml.jackson.core:jackson-annotations",
    "org.yaml:snakeyaml",
    "org.jsoup:jsoup",

    # HTTP
    "org.apache.httpcomponents:httpclient",
    "org.apache.httpcomponents:httpcore",

    # Servers
    "org.apache.tomcat.embed:tomcat-embed-core",
    "org.eclipse.jetty:jetty-server",
    "org.eclipse.jetty:jetty-util",

    # Messaging
    "org.apache.kafka:kafka-clients",
    "org.apache.zookeeper:zookeeper",

    # Utils
    "com.google.guava:guava",
    "commons-cli:commons-cli",
    "commons-codec:commons-codec",
    "commons-net:commons-net",

    # Testing
    "junit:junit",
    "org.junit.jupiter:junit-jupiter-api",
    "org.mockito:mockito-core",

    # Security
    "org.bouncycastle:bcprov-jdk15on",
    "org.apache.shiro:shiro-core",

    # Build
    "org.apache.maven:maven-core",
    "org.apache.maven:maven-plugin-api",
    "org.apache.ant:ant",

    # Data formats
    "org.apache.poi:poi",
    "org.apache.poi:poi-ooxml",
    "org.apache.xmlbeans:xmlbeans",

    # DB drivers
    "mysql:mysql-connector-java",
    "org.postgresql:postgresql",

    # Camel / integration
    "org.apache.camel:camel-core",

    # Padding to 200
    "io.netty:netty-all",
    "io.reactivex:rxjava",
    "org.reactivestreams:reactive-streams",
    "org.aspectj:aspectjweaver",
    "org.codehaus.groovy:groovy",
    "org.freemarker:freemarker",
    "org.thymeleaf:thymeleaf",
    "org.apache.velocity:velocity",
]




# --------------------------------------------------
# Helpers: version enumeration
# --------------------------------------------------

def _fetch_maven_versions(artifact: str) -> List[str]:
    """
    Fetch versions from Maven Central via maven-metadata.xml
    (stable releases only).
    """
    group_id, artifact_id = artifact.split(":", 1)
    path = "/".join(group_id.split(".")) + f"/{artifact_id}/maven-metadata.xml"
    url = f"https://repo1.maven.org/maven2/{path}"

    try:
        xml = requests.get(url, timeout=30).text
        root = ET.fromstring(xml)
    except Exception:
        return []

    versions: List[str] = []

    for v in root.findall(".//version"):
        if v is None or not v.text:
            continue
        try:
            pv = Version(v.text)
            if not pv.is_prerelease and not pv.is_devrelease:
                versions.append(v.text)
        except InvalidVersion:
            continue

    return sorted(versions, key=Version, reverse=True)


# --------------------------------------------------
# Helpers: published date resolution (hierarchical)
# --------------------------------------------------

def _fetch_maven_release_date_from_pom(
    artifact: str,
    version: str,
) -> Optional[datetime]:
    """
    Try to read maven.build.timestamp from the POM.
    Rare, but exact if present.
    """
    group_id, artifact_id = artifact.split(":", 1)
    path = (
        "/".join(group_id.split("."))
        + f"/{artifact_id}/{version}/{artifact_id}-{version}.pom"
    )
    url = f"https://repo1.maven.org/maven2/{path}"

    try:
        xml = requests.get(url, timeout=30).text
        root = ET.fromstring(xml)
    except Exception:
        return None

    for elem in root.findall(".//{*}maven.build.timestamp"):
        if not elem.text:
            continue
        try:
            return datetime.fromisoformat(elem.text).replace(
                tzinfo=timezone.utc
            )
        except Exception:
            return None

    return None


def _fetch_maven_release_date_from_search(
    artifact: str,
    version: str,
) -> Optional[datetime]:
    """
    Fetch release timestamp from Maven Central Search (Solr) API.
    This is the most reliable general source.
    """
    group_id, artifact_id = artifact.split(":", 1)

    url = "https://search.maven.org/solrsearch/select"
    params = {
        "q": f'g:"{group_id}" AND a:"{artifact_id}" AND v:"{version}"',
        "rows": 1,
        "wt": "json",
    }

    try:
        r = requests.get(url, params=params, timeout=30).json()
        docs = r.get("response", {}).get("docs", [])
        if not docs:
            return None

        ts_ms = docs[0].get("timestamp")
        if ts_ms is None:
            return None

        return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)

    except Exception:
        return None


def resolve_maven_published_date(
    artifact: str,
    version: str,
) -> Tuple[Optional[datetime], str]:
    """
    Resolve Maven release date using a documented fallback strategy.

    Returns:
        (published_datetime | None, source)

    source ∈ {"pom", "maven-central", "fallback"}
    """

    # 1) POM timestamp (exact but rare)
    dt = _fetch_maven_release_date_from_pom(artifact, version)
    if dt:
        return dt, "pom"

    # 2) Maven Central Search (reliable)
    dt = _fetch_maven_release_date_from_search(artifact, version)
    if dt:
        return dt, "maven-central"

    # 3) Explicit fallback (no reliable timestamp available)
    return None, "fallback"


# --------------------------------------------------
# Collector
# --------------------------------------------------

def collect_maven(
    samples: Optional[int],
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    osv_cache: Dict[Tuple[str, str, str], Dict[str, Any]] = None,
) -> List[Dict]:

    start_dt = parse_iso_date(start_date)
    end_dt = parse_iso_date(end_date)

    artifacts = MAVEN_GROUND_TRUTH_PACKAGES
    if samples is not None:
        artifacts = artifacts[:samples]

    log.info(
        "Maven scope: using %d/%d artifacts",
        len(artifacts),
        len(MAVEN_GROUND_TRUTH_PACKAGES),
    )

    rows: List[Dict] = []

    for artifact in artifacts:
        log.info("Maven artifact selected: %s", artifact)

        # --------------------------------------------------
        # Maven Central metadata API (maven-metadata.xml)
        # --------------------------------------------------
        maven_meta_token = API_CALL_TRACKER.start("MavenCentral")
        try:
            versions = _fetch_maven_versions(artifact)
        finally:
            API_CALL_TRACKER.end("MavenCentral", maven_meta_token)

        if not versions:
            continue

        if MAVEN_MAX_VERSIONS_PER_PACKAGE is not None:
            versions = versions[:MAVEN_MAX_VERSIONS_PER_PACKAGE]

        log.info(
            "Maven %s: processing %d versions",
            artifact,
            len(versions),
        )

        for version in versions:
            # --------------------------------------------------
            # Maven release date resolution
            # --------------------------------------------------
            maven_date_token = API_CALL_TRACKER.start("MavenCentral")
            try:
                published, source = resolve_maven_published_date(
                    artifact, version
                )
            finally:
                API_CALL_TRACKER.end("MavenCentral", maven_date_token)

            if published is not None:
                if not within_date_window(published, start_dt, end_dt):
                    continue
            else:
                log.info(
                    "Maven fallback date used | artifact=%s | version=%s",
                    artifact,
                    version,
                )

            log.info(
                "Examining component: ecosystem=maven | name=%s | version=%s",
                artifact,
                version,
            )

            payload = {
                "package": {"ecosystem": "Maven", "name": artifact},
                "version": version,
            }

            # --------------------------------------------------
            # OSV QUERY API CALL
            # --------------------------------------------------
            osv_token = API_CALL_TRACKER.start("OSV")
            try:
                res = request_json_with_retry(OSV_QUERY_URL, payload)
            finally:
                API_CALL_TRACKER.end("OSV", osv_token)

            if not isinstance(res, dict):
                continue

            if osv_cache is not None:
                osv_cache[("maven", artifact, version)] = res

            for vuln in res.get("vulns", []):
                osv_id = vuln.get("id")
                if not osv_id:
                    continue

                aliases = vuln.get("aliases") or []
                cve = next(
                    (a for a in aliases if a.startswith("CVE-")),
                    None,
                )

                # --------------------------------------------------
                # NEW: preserve full Maven coordinate as purl
                # --------------------------------------------------
                purl = f"pkg:maven/{artifact.replace(':', '/')}" f"@{version}"

                rows.append({
                    "ecosystem": "maven",
                    "component_name": artifact,          # group:artifact (as before)
                    "component_version": version,
                    "purl": purl,                        # <-- NEW FIELD
                    "vulnerability_id": osv_id,
                    "cve": cve,
                    "is_vulnerable": True,
                })

    log.info(
        "Maven finished | artifacts=%d | rows=%d",
        len(artifacts),
        len(rows),
    )

    return rows


