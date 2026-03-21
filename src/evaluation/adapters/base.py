from abc import ABC, abstractmethod
from typing import List, Dict, Any, Iterable, Iterator, Optional, TypeVar
import os
import sys
import logging
import json
import requests
import time
from pathlib import Path

from tqdm import tqdm

from evaluation.core.model import Finding

T = TypeVar("T")

log = logging.getLogger("adapters.base")


class VulnerabilityToolAdapter(ABC):
    """
    Unified adapters interface for all vulnerability tools.
    Provides generic API call tracing to a dedicated per-tool log file.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.log = log

        self._init_api_logger()
        self._init_api_stats()

    # ============================================================
    # API LOGGER SETUP
    # ============================================================

    def _init_api_logger(self) -> None:
        """
        Initialize file-based API logger.

        File name:
          <GROUND_TRUTH>_<tool>_api.log

        Directory:
          $GROUND_TRUTH_BUILD_PATH (fallback: current working directory)
        """

        logger_name = f"evaluation.api.{self.name()}"
        api_logger = logging.getLogger(logger_name)

        if api_logger.handlers:
            self._api_logger = api_logger
            return

        # ---------- ground truth name ----------
        gt_raw = os.environ.get("GROUND_TRUTH", "groundtruth")
        gt_name = os.path.basename(gt_raw)
        if gt_name.lower().endswith(".csv"):
            gt_name = gt_name[:-4]

        # ---------- output directory ----------
        build_path = os.environ.get("GROUND_TRUTH_BUILD_PATH", "")
        out_dir = Path(build_path)
        out_dir.mkdir(parents=True, exist_ok=True)

        tool = self.name()
        filename = f"{gt_name}_{tool}_api.log"
        path = out_dir / filename

        handler = logging.FileHandler(path, mode="w", encoding="utf-8")
        handler.setLevel(logging.INFO)

        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)

        api_logger.setLevel(logging.INFO)
        api_logger.addHandler(handler)
        api_logger.propagate = False

        self._api_logger = api_logger

        log.info("API trace log initialized: %s", path.resolve())

    # ============================================================
    # REQUIRED ADAPTER INTERFACE
    # ============================================================

    @abstractmethod
    def name(self) -> str:
        ...

    def supports_fp_heuristic(self) -> bool:
        return False

    @abstractmethod
    def load_findings_for_component(
        self,
        *,
        ecosystem: str,
        component: str,
        version: str,
    ) -> List[Finding]:
        ...

    # ============================================================
    # GENERIC API CALL WRAPPER
    # ============================================================

    def _api_call(
        self,
        *,
        session: requests.Session,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> requests.Response:
        """
        Execute an HTTP API call with full request/response tracing
        into the dedicated per-tool API log file.
        """

        self._api_logger.info(
            "REQUEST %s %s\nparams=%s\njson=%s\nheaders=%s\ntimeout=%s",
            method,
            url,
            params,
            json.dumps(json_body, ensure_ascii=False, indent=2)
            if json_body is not None
            else None,
            headers,
            timeout,
        )

        start = time.perf_counter()
        try:
            r = session.request(
                method=method,
                url=url,
                params=params,
                json=json_body,
                headers=headers,
                timeout=timeout,
            )
        except Exception as e:
            self._api_logger.error(
                "REQUEST FAILED %s %s | exception=%s",
                method,
                url,
                e,
            )
            raise
        finally:
            duration_ms = (time.perf_counter() - start) * 1000.0
            self._record_api_stat(
                api=self.api_label(),
                duration_ms=duration_ms,
            )

        try:
            body = r.json()
            self._api_logger.info(
                "RESPONSE BODY (json)\n%s",
                json.dumps(body, indent=2, ensure_ascii=False),
            )
        except Exception:
            self._api_logger.info(
                "RESPONSE BODY (text)\n%s",
                r.text,
            )

        self._api_logger.info("-" * 80)

        return r

    # ============================================================
    # CLI / EXTERNAL TOOL CALL LOGGING
    # ============================================================

    def _log_cli_call(
        self,
        *,
        tool: str,
        command: List[str],
        exit_code: int,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        truncate_stdout: int = 5000,
        truncate_stderr: int = 2000,
    ) -> None:
        """
        Log a non-HTTP external tool invocation (CLI).

        This is intentionally separate from _api_call().
        """

        self._api_logger.info(
            "CLI REQUEST %s\ncommand=%s",
            tool,
            " ".join(command),
        )

        self._api_logger.info(
            "CLI RESPONSE %s | exit_code=%s",
            tool,
            exit_code,
        )

        if stdout:
            self._api_logger.info(
                "CLI STDOUT (truncated)\n%s",
                stdout[:truncate_stdout],
            )

        if stderr:
            self._api_logger.info(
                "CLI STDERR (truncated)\n%s",
                stderr[:truncate_stderr],
            )

        self._api_logger.info("-" * 80)

    # ============================================================
    # EVALUATION LOGGING
    # ============================================================

    @staticmethod
    def log_evaluation_sample(
        *,
        idx: int,
        total: int,
        result: str,
        finding: Finding,
    ) -> None:
        log.info(
            "[%d/%d] Evaluation %s | ecosystem=%s | component=%s | version=%s | cve=%s | osv_id=%s",
            idx,
            total,
            result,
            finding.ecosystem,
            finding.component,
            finding.version,
            finding.cve or "-",
            finding.osv_id or "-",
        )

    # ============================================================
    # PROGRESS ITERATORS
    # ============================================================

    def iter_components(
        self,
        items: Iterable[T],
        *,
        desc: str,
        unit: str = "item",
        total: Optional[int] = None,
    ) -> Iterator[T]:

        env = os.environ.get("EVAL_PROGRESS", "1").strip().lower()
        enabled = env not in {"0", "false", "no", "off"}
        use_tqdm = enabled and sys.stderr.isatty()

        if not use_tqdm:
            for x in items:
                yield x
            return

        if total is None:
            try:
                total = len(items)
            except Exception:
                total = None

        for x in tqdm(
            items,
            desc=desc,
            unit=unit,
            total=total,
            dynamic_ncols=True,
            mininterval=0.2,
        ):
            yield x

    def iter_with_progress(
        self,
        items: Iterable[T],
        *,
        desc: str,
        unit: str = "item",
        total: Optional[int] = None,
    ) -> Iterator[T]:
        return self.iter_components(
            items,
            desc=desc,
            unit=unit,
            total=total,
        )

    # ============================================================
    # Helpers to record API Call Statistics
    # ============================================================

    def _init_api_stats(self) -> None:
        self._api_stats: Dict[str, Dict[str, float]] = {}

    def _record_api_stat(self, *, api: str, duration_ms: float) -> None:
        s = self._api_stats.setdefault(
            api,
            {"calls": 0, "total_ms": 0.0},
        )
        s["calls"] += 1
        s["total_ms"] += duration_ms

    def api_label(self) -> str:
        return self.name()

    def get_api_statistics(self) -> Dict[str, Dict[str, float]]:
        out = {}
        for api, s in self._api_stats.items():
            calls = int(s["calls"])
            total = float(s["total_ms"])
            out[api] = {
                "calls": calls,
                "total_ms": total,
                "avg_ms": (total / calls) if calls else 0.0,
            }
        return out
