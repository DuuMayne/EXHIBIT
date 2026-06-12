"""
Retry logic and run state persistence for EXHIBIT.

Provides:
- retry_collect(): wraps a collector call with configurable retries + exponential backoff
- RunState: tracks which (request_id, system) pairs have completed, enabling --resume
"""
import json
import os
import time
from pathlib import Path
from typing import Callable, Optional

from .models import EvidenceRequest, EvidenceResult, System

STATE_DIR = Path(os.environ.get("EXHIBIT_STATE_DIR", Path.home() / ".exhibit" / "state"))

MAX_RETRIES = int(os.environ.get("EXHIBIT_MAX_RETRIES", "2"))
RETRY_BASE_DELAY = float(os.environ.get("EXHIBIT_RETRY_DELAY", "2.0"))

# Errors that are likely transient and worth retrying
TRANSIENT_INDICATORS = [
    "timeout", "timed out", "rate limit", "throttl", "429",
    "503", "502", "connection reset", "connection refused",
    "temporary", "unavailable", "retry",
]


def _is_transient(error: str) -> bool:
    """Heuristic: is this error likely transient?"""
    lower = error.lower()
    return any(indicator in lower for indicator in TRANSIENT_INDICATORS)


def retry_collect(
    collector,
    request: EvidenceRequest,
    system: System,
    max_retries: int = MAX_RETRIES,
    base_delay: float = RETRY_BASE_DELAY,
) -> EvidenceResult:
    """
    Call collector.collect(request) with retry logic for transient failures.
    Returns the result (which may still have .error set if all retries exhausted).
    """
    last_error: Optional[str] = None

    for attempt in range(1 + max_retries):
        try:
            result = collector.collect(request)

            # If the collector returned an error, check if it's retryable
            if result.error and attempt < max_retries and _is_transient(result.error):
                last_error = result.error
                delay = base_delay * (2 ** attempt)
                print(f"RETRY ({attempt + 1}/{max_retries}, {delay:.0f}s)...", end=" ", flush=True)
                time.sleep(delay)
                continue

            return result

        except Exception as e:
            last_error = str(e)
            if attempt < max_retries and _is_transient(last_error):
                delay = base_delay * (2 ** attempt)
                print(f"RETRY ({attempt + 1}/{max_retries}, {delay:.0f}s)...", end=" ", flush=True)
                time.sleep(delay)
                continue
            # Non-transient or retries exhausted — raise so caller can handle
            raise

    # All retries exhausted with a soft error (result.error set but no exception)
    return EvidenceResult(
        request_id=request.id,
        system=system,
        error=f"Retries exhausted ({max_retries}): {last_error}",
    )


class RunState:
    """
    Persists which (request_id, system) pairs have been collected in a run,
    enabling --resume to skip already-completed items.
    """

    def __init__(self, engagement: str):
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        safe_name = engagement.replace(" ", "_").replace("/", "_")[:60]
        self.path = STATE_DIR / f"{safe_name}.json"
        self._completed: set[str] = set()
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text())
                self._completed = set(data.get("completed", []))
            except (json.JSONDecodeError, OSError):
                self._completed = set()

    def _save(self):
        self.path.write_text(json.dumps({
            "completed": sorted(self._completed),
            "updated_at": time.time(),
        }, indent=2))

    def is_done(self, request_id: str, system: System) -> bool:
        return f"{request_id}:{system.value}" in self._completed

    def mark_done(self, request_id: str, system: System):
        self._completed.add(f"{request_id}:{system.value}")
        self._save()

    def clear(self):
        self._completed.clear()
        if self.path.exists():
            self.path.unlink()

    @property
    def completed_count(self) -> int:
        return len(self._completed)
