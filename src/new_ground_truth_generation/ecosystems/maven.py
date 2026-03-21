import logging
import requests
import xml.etree.ElementTree as ET
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone

from packaging.version import Version, InvalidVersion

from new_ground_truth_generation.osv_common import (
    request_json_with_retry,
    within_date_window,
    parse_iso_date,
    env_int,
    API_CALL_TRACKER,
)

from new_ground_truth_generation.osv_common import env_int

TARGET_VULNS_PER_ECOSYSTEM = env_int(
    "TARGET_VULNS_PER_ECOSYSTEM",
    None,
)

log = logging.getLogger("maven")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# --------------------------------------------------
# Configuration
# --------------------------------------------------

MAVEN_MAX_VERSIONS_PER_PACKAGE = env_int(
    "MAVEN_MAX_VERSIONS_PER_PACKAGE",
    10,
)

MAX_OSV_ENTRIES_PER_COMPONENT = env_int(
    "MAX_OSV_ENTRIES_PER_COMPONENT",
    10,
)

# --------------------------------------------------
# # Kuratierte Komponentenliste
# --------------------------------------------------
MAVEN_GROUND_TRUTH_PACKAGES = [

# --- Apache Commons (20)
"org.apache.commons:commons-lang3",
"org.apache.commons:commons-io",
"org.apache.commons:commons-collections4",
"org.apache.commons:commons-compress",
"org.apache.commons:commons-text",
"org.apache.commons:commons-beanutils",
"org.apache.commons:commons-fileupload",
"org.apache.commons:commons-validator",
"org.apache.commons:commons-exec",
"org.apache.commons:commons-dbcp2",
"org.apache.commons:commons-pool2",
"org.apache.commons:commons-csv",
"org.apache.commons:commons-math3",
"org.apache.commons:commons-email",
"org.apache.commons:commons-vfs2",
"org.apache.commons:commons-configuration2",
"org.apache.commons:commons-imaging",
"org.apache.commons:commons-jexl3",
"org.apache.commons:commons-cli",
"org.apache.commons:commons-codec",

# --- Logging (10)
"org.apache.logging.log4j:log4j-core",
"org.apache.logging.log4j:log4j-api",
"org.apache.logging.log4j:log4j-web",
"ch.qos.logback:logback-core",
"ch.qos.logback:logback-classic",
"org.slf4j:slf4j-api",
"org.slf4j:slf4j-simple",
"org.slf4j:jcl-over-slf4j",
"org.slf4j:jul-to-slf4j",
"org.slf4j:log4j-over-slf4j",

# --- Spring (25)
"org.springframework:spring-core",
"org.springframework:spring-context",
"org.springframework:spring-beans",
"org.springframework:spring-aop",
"org.springframework:spring-expression",
"org.springframework:spring-web",
"org.springframework:spring-webmvc",
"org.springframework:spring-jdbc",
"org.springframework:spring-tx",
"org.springframework:spring-orm",
"org.springframework.security:spring-security-core",
"org.springframework.security:spring-security-web",
"org.springframework.security:spring-security-config",
"org.springframework.security:spring-security-crypto",
"org.springframework.security:spring-security-oauth2-core",
"org.springframework.security:spring-security-oauth2-client",
"org.springframework.security:spring-security-oauth2-resource-server",
"org.springframework.boot:spring-boot",
"org.springframework.boot:spring-boot-autoconfigure",
"org.springframework.boot:spring-boot-starter-web",
"org.springframework.boot:spring-boot-starter-security",
"org.springframework.boot:spring-boot-starter-data-jpa",
"org.springframework:spring-test",
"org.springframework:spring-aspects",
"org.springframework:spring-instrument",

# --- Hibernate / Persistence (10)
"org.hibernate:hibernate-core",
"org.hibernate:hibernate-validator",
"org.hibernate:hibernate-entitymanager",
"javax.persistence:javax.persistence-api",
"jakarta.persistence:jakarta.persistence-api",
"org.hibernate.common:hibernate-commons-annotations",
"org.hibernate:hibernate-jcache",
"org.hibernate:hibernate-envers",
"org.hibernate:hibernate-spatial",
"org.hibernate:hibernate-search-engine",

# --- JSON / Parsing (15)
"com.fasterxml.jackson.core:jackson-core",
"com.fasterxml.jackson.core:jackson-databind",
"com.fasterxml.jackson.core:jackson-annotations",
"com.fasterxml.jackson.dataformat:jackson-dataformat-yaml",
"com.fasterxml.jackson.dataformat:jackson-dataformat-xml",
"com.google.code.gson:gson",
"net.minidev:json-smart",
"org.json:json",
"org.yaml:snakeyaml",
"org.jsoup:jsoup",
"org.codehaus.jettison:jettison",
"org.jsonschema2pojo:jsonschema2pojo-core",
"com.fasterxml.jackson.module:jackson-module-kotlin",
"com.fasterxml.jackson.module:jackson-module-parameter-names",
"com.fasterxml.jackson.module:jackson-module-afterburner",

# --- XML / Serialization (10)
"xerces:xercesImpl",
"xalan:xalan",
"com.thoughtworks.xstream:xstream",
"javax.xml.bind:jaxb-api",
"org.glassfish.jaxb:jaxb-runtime",
"org.dom4j:dom4j",
"jaxen:jaxen",
"org.apache.xmlgraphics:batik-dom",
"org.apache.xmlgraphics:batik-parser",
"org.apache.xmlgraphics:batik-svggen",

# --- HTTP / Networking (15)
"org.apache.httpcomponents:httpclient",
"org.apache.httpcomponents:httpcore",
"org.apache.httpcomponents.client5:httpclient5",
"io.netty:netty-all",
"io.netty:netty-handler",
"io.netty:netty-codec-http",
"io.netty:netty-transport",
"io.netty:netty-buffer",
"io.netty:netty-codec",
"org.asynchttpclient:async-http-client",
"org.eclipse.jetty:jetty-client",
"org.apache.httpcomponents:httpmime",
"org.apache.httpcomponents:fluent-hc",
"org.apache.httpcomponents:httpasyncclient",
"org.eclipse.jetty:jetty-http",

# --- Servers (10)
"org.apache.tomcat.embed:tomcat-embed-core",
"org.apache.tomcat.embed:tomcat-embed-websocket",
"org.eclipse.jetty:jetty-server",
"org.eclipse.jetty:jetty-util",
"org.eclipse.jetty:jetty-servlet",
"org.eclipse.jetty:jetty-webapp",
"org.eclipse.jetty:jetty-io",
"org.eclipse.jetty:jetty-security",
"org.eclipse.jetty:jetty-xml",
"org.apache.catalina:catalina",

# --- Messaging (10)
"org.apache.kafka:kafka-clients",
"org.apache.zookeeper:zookeeper",
"org.apache.activemq:activemq-client",
"org.apache.activemq:activemq-broker",
"org.apache.qpid:qpid-client",
"org.apache.pulsar:pulsar-client",
"org.apache.rocketmq:rocketmq-client",
"org.apache.camel:camel-core",
"org.apache.camel:camel-http",
"org.apache.camel:camel-jms",

# --- Security / Crypto (10)
"org.bouncycastle:bcprov-jdk15on",
"org.bouncycastle:bcpkix-jdk15on",
"org.apache.shiro:shiro-core",
"org.keycloak:keycloak-core",
"org.keycloak:keycloak-adapter-core",
"org.owasp.encoder:encoder",
"org.owasp.esapi:esapi",
"org.jasypt:jasypt",
"org.apache.santuario:xmlsec",
"org.apache.wss4j:wss4j",

# --- Utils (10)
"com.google.guava:guava",
"commons-cli:commons-cli",
"commons-codec:commons-codec",
"commons-net:commons-net",
"commons-logging:commons-logging",
"org.apache.commons:commons-lang",
"org.apache.commons:commons-collections",
"org.apache.commons:commons-digester",
"org.apache.commons:commons-chain",
"org.apache.commons:commons-proxy",

# --- DB Drivers (5)
"mysql:mysql-connector-java",
"org.postgresql:postgresql",
"com.oracle.database.jdbc:ojdbc8",
"com.microsoft.sqlserver:mssql-jdbc",
"org.mariadb.jdbc:mariadb-java-client",

# --- Testing (5)
"junit:junit",
"org.junit.jupiter:junit-jupiter-api",
"org.mockito:mockito-core",
"org.assertj:assertj-core",
"org.hamcrest:hamcrest",

# --- Misc (5)
"io.reactivex:rxjava",
"io.projectreactor:reactor-core",
"org.reactivestreams:reactive-streams",
"org.codehaus.groovy:groovy",
"org.aspectj:aspectjweaver",

# --- Additional Apache / Commons / Utils (10)
"org.apache.commons:commons-rng-simple",
"org.apache.commons:commons-rng-core",
"org.apache.commons:commons-rng-client-api",
"org.apache.commons:commons-rng-sampling",
"org.apache.commons:commons-weaver-privilizer",
"org.apache.commons:commons-numbers-core",
"org.apache.commons:commons-numbers-complex",
"org.apache.commons:commons-numbers-fraction",
"org.apache.commons:commons-crypto",
"org.apache.commons:commons-statistics-distribution",

# --- HTTP / Networking extensions (5)
"org.apache.httpcomponents.core5:httpcore5",
"org.apache.httpcomponents.client5:httpclient5-cache",
"org.apache.httpcomponents:httpclient-cache",
"org.apache.httpcomponents:httpcore-nio",
"org.apache.httpcomponents:httpasyncclient-cache",

# --- Logging extensions (3)
"org.apache.logging.log4j:log4j-layout-template-json",
"org.apache.logging.log4j:log4j-jul",
"org.apache.logging.log4j:log4j-to-slf4j",

# --- Spring extensions (5)
"org.springframework:spring-jcl",
"org.springframework:spring-messaging",
"org.springframework:spring-oxm",
"org.springframework:spring-webflux",
"org.springframework:spring-context-support",

# --- Spring Security extensions (2)
"org.springframework.security:spring-security-messaging",
"org.springframework.security:spring-security-taglibs",

# --- Jackson extensions (3)
"com.fasterxml.jackson.module:jackson-module-scala",
"com.fasterxml.jackson.module:jackson-module-jaxb-annotations",
"com.fasterxml.jackson.module:jackson-module-jsonSchema",

# --- Messaging / integration extensions (5)
"org.apache.kafka:kafka-streams",
"org.apache.kafka:connect-api",
"org.apache.activemq:activemq-kahadb-store",
"org.apache.activemq:activemq-openwire-legacy",
"org.apache.camel:camel-jackson",

# --- XML / Web services (3)
"org.apache.cxf:cxf-rt-transports-http",
"org.apache.cxf:cxf-rt-bindings-soap",
"org.apache.cxf:cxf-core",

# --- Data / file processing (2)
"org.apache.poi:poi-scratchpad",
"org.apache.tika:tika-core",

# --- Security extensions (2)
"org.apache.shiro:shiro-web",
"org.keycloak:keycloak-services",
]

# --------------------------------------------------
# Helpers
# --------------------------------------------------

def _fetch_maven_versions(artifact: str) -> List[str]:
    """
    Fetch versions from Maven Central via maven-metadata.xml.
    Handles 404 (missing metadata) gracefully.
    """
    group_id, artifact_id = artifact.split(":", 1)
    path = "/".join(group_id.split(".")) + f"/{artifact_id}/maven-metadata.xml"
    url = f"https://repo1.maven.org/maven2/{path}"

    try:
        response = requests.get(url, timeout=30)

        # ----------------------------
        # Expected case: artifact not present at this path
        # ----------------------------
        if response.status_code == 404:
            log.debug("No metadata found (404) for %s", artifact)
            return []

        response.raise_for_status()

        if not response.text.strip():
            log.debug("Empty metadata response for %s", artifact)
            return []

        root = ET.fromstring(response.text)

    except requests.exceptions.RequestException:
        log.warning("HTTP error while fetching versions for %s", artifact)
        return []

    except ET.ParseError:
        log.warning("Invalid XML for %s", artifact)
        return []

    except Exception:
        log.exception("Unexpected error while fetching versions for %s", artifact)
        return []

    versions: List[str] = []

    for v in root.findall(".//version"):
        if not v.text:
            continue

        try:
            pv = Version(v.text)

            # Filter unstable versions
            if pv.is_prerelease or pv.is_devrelease:
                continue

            versions.append(v.text)

        except InvalidVersion:
            continue

    if not versions:
        log.debug("No valid versions extracted for %s", artifact)

    return sorted(versions, key=Version)


def resolve_maven_published_date(artifact: str, version: str) -> Optional[datetime]:
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

        ts = docs[0].get("timestamp")
        if ts:
            return datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
    except Exception:
        pass

    return None

# --------------------------------------------------
# Collector
# --------------------------------------------------

def collect_maven(
    samples,
    start_date=None,
    end_date=None,
    osv_cache=None,
):
    start_dt = parse_iso_date(start_date)
    end_dt = parse_iso_date(end_date)

    TARGET = env_int("TARGET_VULNS_PER_ECOSYSTEM", None)

    artifacts = MAVEN_GROUND_TRUTH_PACKAGES[:samples] if samples else MAVEN_GROUND_TRUTH_PACKAGES

    rows = []
    total_vulns = 0
    total_packages = len(artifacts)

    for i, artifact in enumerate(artifacts, 1):
        component_vulns = 0

        versions = _fetch_maven_versions(artifact)

        if MAVEN_MAX_VERSIONS_PER_PACKAGE:
            versions = versions[:MAVEN_MAX_VERSIONS_PER_PACKAGE]

        for version in versions:
            published = resolve_maven_published_date(artifact, version)

            if published and not within_date_window(published, start_dt, end_dt):
                continue

            payload = {"package": {"ecosystem": "Maven", "name": artifact}, "version": version}
            res = request_json_with_retry(OSV_QUERY_URL, payload)

            if not isinstance(res, dict):
                continue

            if osv_cache is not None:
                osv_cache[("maven", artifact, version)] = res

            vulns = res.get("vulns", [])[:MAX_OSV_ENTRIES_PER_COMPONENT]
            seen = set()

            for v in vulns:
                vid = v.get("id")
                if not vid or vid in seen:
                    continue
                seen.add(vid)

                rows.append({
                    "ecosystem": "maven",
                    "component_name": artifact,
                    "component_version": version,
                    "purl": f"pkg:maven/{artifact.replace(':','/')}" f"@{version}",
                    "vulnerability_id": vid,
                    "cve": next((a for a in (v.get("aliases") or []) if a.startswith("CVE-")), None),
                    "is_vulnerable": True,
                })

                component_vulns += 1
                total_vulns += 1

                if TARGET and total_vulns >= TARGET:
                    log.info("[%d/%d] Processing artifact %s; %d vulnerabilities", i, total_packages, artifact, component_vulns)
                    log.info("Stopping early at %d vulnerabilities", total_vulns)
                    return rows

        log.info("[%d/%d] Processing artifact %s; %d vulnerabilities", i, total_packages, artifact, component_vulns)

    return rows