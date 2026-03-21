from dataclasses import dataclass


@dataclass(frozen=True)
class EcosystemMapping:
    canonical: str
    purl: str
    osv: str
    github: str | None


ECOSYSTEMS = {
    "pypi": EcosystemMapping(
        canonical="pypi",
        purl="pypi",
        osv="PyPI",
        github="PIP",
    ),
    "npm": EcosystemMapping(
        canonical="npm",
        purl="npm",
        osv="npm",
        github="NPM",
    ),
    "maven": EcosystemMapping(
        canonical="maven",
        purl="maven",
        osv="Maven",
        github="MAVEN",
    ),
    "nuget": EcosystemMapping(
        canonical="nuget",
        purl="nuget",
        osv="NuGet",
        github="NUGET",
    ),
}
