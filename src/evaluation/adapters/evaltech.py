from typing import List, Dict, Any, Set, Tuple

from evaluation.adapters.base import VulnerabilityToolAdapter
from evaluation.adapters.dtrack import DependencyTrackAdapter
from evaluation.core.model import Finding
from evaluation.core.ecosystems import ECOSYSTEMS
from evaluation.fp_engine.evaltech_vulnerability_false_positive_engine import (
    EvaltechFalsePositiveEngine,
)


class EvaltechAdapter(VulnerabilityToolAdapter):
    """
    Evaltech adapters.

    - Delegates detection to Dependency-Track
    - Applies Evaltech FP heuristics
    - Provides unified logging + progress bar
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.gt = config["ground_truth"]
        self.dt = DependencyTrackAdapter(config)
        self.log.info("Initialized adapters: Evaltech")

    # ------------------------------------------------------------
    # Adapter metadata
    # ------------------------------------------------------------

    def name(self) -> str:
        return "evaltech"

    def supports_fp_heuristic(self) -> bool:
        return True

    # ------------------------------------------------------------
    # Required by abstract base
    # ------------------------------------------------------------

    def load_findings_for_component(
        self,
        *,
        ecosystem: str,
        component: str,
        version: str,
    ) -> List[Finding]:
        """
        Single component execution:
        - get DT findings
        - apply FP heuristics
        """

        findings = self.dt.load_findings_for_component(
            ecosystem=ecosystem,
            component=component,
            version=version,
        )

        eco_cfg = ECOSYSTEMS.get(ecosystem)
        if not eco_cfg:
            return findings

        for f in findings:
            if not f.cve:
                continue

            purl = f"pkg:{eco_cfg.purl}/{f.component}@{f.version}"
            description = (f.description or "").split("\n")[0].strip()

            result = EvaltechFalsePositiveEngine.detect_fp(
                cve_id=f.cve,
                component=f.component,
                purl=purl,
                description=description,
                cve_cpes=f.cve_cpes,
            )

            if result.get("is_fp"):
                f.fp_class = result.get("primary_rule")
                f.fp_score = result.get("score")
                f.fp_rules = result.get("rules")

        return findings

    # ------------------------------------------------------------
    # Batch API (like GitHub)
    # ------------------------------------------------------------

    def load_findings(self) -> List[Finding]:
        """
        Batch execution with progress bar.
        Mirrors GitHub adapters behaviour.
        """

        rows: List[Finding] = []

        components = sorted({
            (f.ecosystem, f.component, f.version)
            for f in self.gt
        })

        self.log.info(
            "Evaltech FP analysis for %d unique components",
            len(components),
        )

        for ecosystem, component, version in self.iter_with_progress(
                components,
                desc="Evaltech FP analysis",
                unit="component",
        ):
            rows.extend(
                self.load_findings_for_component(
                    ecosystem=ecosystem,
                    component=component,
                    version=version,
                )
            )

        self.log.info(
            "Evaltech analysis finished | findings=%d",
            len(rows),
        )

        return rows

