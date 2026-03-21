import time
from collections import defaultdict
from typing import Dict, Any


class ApiCallTracker:
    """
    Tracks API call counts and timing statistics per logical API.

    Usage pattern:
        token = tracker.start("OSV")
        ... perform API call ...
        tracker.end("OSV", token)
    """

    def __init__(self) -> None:
        # absolute counts
        self._counts: Dict[str, int] = defaultdict(int)

        # accumulated wall-clock time in seconds
        self._total_time: Dict[str, float] = defaultdict(float)

    # --------------------------------------------------
    # Timing hooks
    # --------------------------------------------------
    def start(self, api_name: str) -> float:
        """
        Marks the start of an API call.

        Returns a token (timestamp) that must be passed to `end`.
        """
        return time.perf_counter()

    def end(self, api_name: str, start_token: float) -> None:
        """
        Marks the end of an API call and records duration.
        """
        duration = time.perf_counter() - start_token
        self._counts[api_name] += 1
        self._total_time[api_name] += duration

    # --------------------------------------------------
    # Readout
    # --------------------------------------------------
    def get_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns aggregated statistics per API.
        """
        stats = {}
        for api, count in self._counts.items():
            total = self._total_time[api]
            stats[api] = {
                "calls": count,
                "total_time_sec": round(total, 6),
                "avg_time_sec": round(total / count, 6) if count else 0.0,
            }
        return stats

    def reset(self) -> None:
        """
        Clears all collected statistics.
        """
        self._counts.clear()
        self._total_time.clear()
