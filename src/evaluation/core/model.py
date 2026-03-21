# evaluation/core/model.py
from dataclasses import dataclass
from typing import Optional, Any, Set


@dataclass
class Finding:
    ecosystem: str
    component: str
    version: str

    # canonical package identifier
    purl: Optional[str] = None

    # Identifiers
    cve: Optional[str] = None
    ghsa: Optional[str] = None
    osv_id: Optional[str] = None

    # Metadata
    description: str = ""
    source: str = ""
    cve_cpes: Optional[Any] = None

    # Version / range info
    affected_version_range: Optional[str] = None

    # NEW: Evaluation match type (TP_EXACT / TP_RANGE)
    match_type: Optional[str] = None

    # FP heuristic fields
    fp_class: Optional[str] = None
    fp_reason: Optional[str] = None
    fp_score: Optional[float] = None
    fp_rules: Optional[list] = None

    def identifiers(self) -> Set[str]:
        ids: Set[str] = set()
        if self.cve:
            ids.add(self.cve)
        if self.ghsa:
            ids.add(self.ghsa)
        if self.osv_id:
            ids.add(self.osv_id)
        return ids
