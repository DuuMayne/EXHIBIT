"""
Persistent run logging for EXHIBIT evidence collection.

Each run creates a JSON log file in the configured runs directory
(default: ~/.exhibit/runs/). Logs include:
- Run metadata (engagement, timestamp, duration, flags)
- Per-item results (system, status, file count, errors)
- Summary stats (total collected, errors, skipped)
"""
import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import EvidenceRequest, EvidenceResult, System

RUNS_DIR = Path(os.environ.get("EXHIBIT_RUNS_DIR", Path.home() / ".exhibit" / "runs"))


@dataclass
class CollectorLog:
    request_id: str
    system: str
    status: str  # "ok", "error", "skipped"
    files_collected: int = 0
    error: Optional[str] = None
    duration_ms: int = 0


@dataclass
class RunLog:
    run_id: str
    engagement: str
    questionnaire: str
    started_at: str
    finished_at: Optional[str] = None
    duration_seconds: float = 0.0
    flags: dict = field(default_factory=dict)
    total_requests: int = 0
    total_files: int = 0
    total_errors: int = 0
    total_skipped: int = 0
    collector_logs: list[CollectorLog] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


class RunLogger:
    """Tracks a single evidence collection run and persists results to disk."""

    def __init__(self, engagement: str, questionnaire: str, flags: dict | None = None):
        RUNS_DIR.mkdir(parents=True, exist_ok=True)

        now = datetime.now(timezone.utc)
        self.run_id = now.strftime("%Y%m%d_%H%M%S")
        self._start_time = time.monotonic()

        self.log = RunLog(
            run_id=self.run_id,
            engagement=engagement,
            questionnaire=questionnaire,
            started_at=now.isoformat(),
            flags=flags or {},
        )
        self._item_timers: dict[str, float] = {}

    def set_total_requests(self, count: int):
        self.log.total_requests = count

    def start_item(self, request_id: str, system: System):
        self._item_timers[f"{request_id}:{system.value}"] = time.monotonic()

    def log_result(self, request_id: str, system: System, result: EvidenceResult):
        key = f"{request_id}:{system.value}"
        start = self._item_timers.pop(key, time.monotonic())
        duration_ms = int((time.monotonic() - start) * 1000)

        status = "error" if result.error else "ok"
        self.log.collector_logs.append(CollectorLog(
            request_id=request_id,
            system=system.value,
            status=status,
            files_collected=len(result.files),
            error=result.error,
            duration_ms=duration_ms,
        ))
        self.log.total_files += len(result.files)
        if result.error:
            self.log.total_errors += 1

    def log_skip(self, request_id: str, system: System, reason: str):
        self.log.collector_logs.append(CollectorLog(
            request_id=request_id,
            system=system.value,
            status="skipped",
            error=reason,
        ))
        self.log.total_skipped += 1

    def finalize(self) -> Path:
        """Write the run log to disk and return the file path."""
        now = datetime.now(timezone.utc)
        self.log.finished_at = now.isoformat()
        self.log.duration_seconds = round(time.monotonic() - self._start_time, 2)

        filename = f"{self.run_id}_{self.log.engagement.replace(' ', '_')[:40]}.json"
        path = RUNS_DIR / filename
        path.write_text(json.dumps(self.log.to_dict(), indent=2, default=str))
        return path

    @staticmethod
    def list_runs(limit: int = 20) -> list[dict]:
        """List recent run logs."""
        if not RUNS_DIR.exists():
            return []
        files = sorted(RUNS_DIR.glob("*.json"), reverse=True)[:limit]
        runs = []
        for f in files:
            try:
                data = json.loads(f.read_text())
                runs.append({
                    "run_id": data["run_id"],
                    "engagement": data["engagement"],
                    "started_at": data["started_at"],
                    "duration_seconds": data.get("duration_seconds"),
                    "total_files": data.get("total_files", 0),
                    "total_errors": data.get("total_errors", 0),
                })
            except (json.JSONDecodeError, KeyError):
                continue
        return runs
