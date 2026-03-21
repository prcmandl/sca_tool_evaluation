# evaluation/core/version_matching.py

from __future__ import annotations

import re
from typing import Optional

from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier


_V_PREFIX = re.compile(r"^\s*v", re.IGNORECASE)
_WS = re.compile(r"\s+")
_HYPHEN = re.compile(r"^\s*([^ ]+)\s*-\s*([^ ]+)\s*$")
_MAVEN_RANGE = re.compile(r"^\s*([\[\(])\s*([^,]*)\s*,\s*([^)\]]*)\s*([\)\]])\s*$")


def _norm_version_token(x: str) -> str:
    """
    Normalize a single version token:
    - trim
    - drop leading 'v'
    - drop build metadata '+...'
    - collapse whitespace
    """
    s = (x or "").strip()
    s = _WS.sub("", s)
    s = _V_PREFIX.sub("", s)
    if "+" in s:
        s = s.split("+", 1)[0]
    return s


def normalize_specifier(spec: str) -> Optional[str]:
    """
    Normalize common range notations into PEP 440 specifiers for SpecifierSet.
    Returns a comma-separated spec string or None if not parseable.
    """
    if not spec:
        return None

    s = spec.strip()

    # Remove surrounding whitespace, keep internal commas/operators meaningful
    # Example: ">= 1.0, < 2.0" -> ">= 1.0,< 2.0" (SpecifierSet tolerates spaces anyway)
    # We'll keep as-is mostly, but normalize tokens when we split.
    # 1) Maven/Ivy: [1.0,2.0) or (,1.4.4] or [1.0,)
    m = _MAVEN_RANGE.match(s)
    if m:
        lb, left, right, ub = m.groups()
        left = _norm_version_token(left) if left else ""
        right = _norm_version_token(right) if right else ""

        parts: list[str] = []
        if left:
            parts.append(f">={left}" if lb == "[" else f">{left}")
        if right:
            parts.append(f"<={right}" if ub == "]" else f"<{right}")

        return ",".join(parts) if parts else None

    # 2) Hyphen range: "1.2.3 - 2.0.0" -> ">=1.2.3,<=2.0.0"
    m = _HYPHEN.match(s)
    if m:
        a, b = m.groups()
        a = _norm_version_token(a)
        b = _norm_version_token(b)
        if a and b:
            return f">={a},<={b}"
        return None

    # 3) Already operator-based (PEP440-ish): "< 1.2.3", ">=1.0,<2.0", "==1.2.*"
    # Normalize tokens a bit: strip 'v' and build metadata after operators.
    # We do a light rewrite by splitting on commas.
    if any(op in s for op in ("<", ">", "=", "~", "^")):
        out_parts: list[str] = []
        for part in s.split(","):
            p = part.strip()
            if not p:
                continue

            # Split operator from version token
            # operators in SpecifierSet: ~=, ==, !=, <=, >=, <, >
            for op in ("~=", "==", "!=", "<=", ">=", "<", ">"):
                if p.startswith(op):
                    tok = _norm_version_token(p[len(op):])
                    if not tok:
                        return None
                    out_parts.append(f"{op}{tok}")
                    break
            else:
                # If no operator found, cannot normalize reliably
                return None

        return ",".join(out_parts) if out_parts else None

    return None


def version_in_range(version: str, spec: str) -> bool:
    """
    True iff `version` satisfies the normalized specifier.
    """
    if not version or not spec:
        return False

    v_str = _norm_version_token(version)
    if not v_str:
        return False

    try:
        v = Version(v_str)
    except InvalidVersion:
        return False

    norm = normalize_specifier(spec)
    if not norm:
        return False

    try:
        ss = SpecifierSet(norm)
    except InvalidSpecifier:
        return False

    return v in ss
