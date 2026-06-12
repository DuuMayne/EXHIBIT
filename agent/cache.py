"""
File-based response cache for EXHIBIT collectors.

Prevents duplicate API calls across repeated runs. Each cached response is
stored as a JSON file keyed by (system, request_id, content_hash). Entries
expire after a configurable TTL (default: 4 hours).

Usage in collectors:
    from ..cache import ResponseCache

    cache = ResponseCache()

    # Check cache before making API call
    cached = cache.get("aws", request_id, call_key="iam_users")
    if cached is not None:
        return cached  # bytes

    # Make API call...
    data = api_call()

    # Store result
    cache.set("aws", request_id, call_key="iam_users", data=data)
"""
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional

CACHE_DIR = Path(os.environ.get("EXHIBIT_CACHE_DIR", Path.home() / ".exhibit" / "cache"))
DEFAULT_TTL_SECONDS = int(os.environ.get("EXHIBIT_CACHE_TTL", 4 * 3600))  # 4 hours


class ResponseCache:
    def __init__(self, ttl_seconds: int | None = None):
        self.ttl = ttl_seconds if ttl_seconds is not None else DEFAULT_TTL_SECONDS
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

    def _key_path(self, system: str, request_id: str, call_key: str) -> Path:
        """Generate a deterministic file path for a cache entry."""
        raw = f"{system}:{request_id}:{call_key}"
        hashed = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return CACHE_DIR / system / f"{request_id}_{call_key}_{hashed}.json"

    def get(self, system: str, request_id: str, call_key: str) -> Optional[bytes]:
        """Retrieve cached data if it exists and hasn't expired. Returns None on miss."""
        path = self._key_path(system, request_id, call_key)
        if not path.exists():
            return None

        try:
            meta_path = path.with_suffix(".meta")
            if meta_path.exists():
                meta = json.loads(meta_path.read_text())
                stored_at = meta.get("stored_at", 0)
                if time.time() - stored_at > self.ttl:
                    # Expired
                    path.unlink(missing_ok=True)
                    meta_path.unlink(missing_ok=True)
                    return None
            else:
                # No metadata, check file mtime
                if time.time() - path.stat().st_mtime > self.ttl:
                    path.unlink(missing_ok=True)
                    return None

            return path.read_bytes()
        except (OSError, json.JSONDecodeError):
            return None

    def set(self, system: str, request_id: str, call_key: str, data: bytes):
        """Store data in the cache."""
        path = self._key_path(system, request_id, call_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

        # Write metadata
        meta_path = path.with_suffix(".meta")
        meta_path.write_text(json.dumps({
            "system": system,
            "request_id": request_id,
            "call_key": call_key,
            "stored_at": time.time(),
            "ttl_seconds": self.ttl,
            "size_bytes": len(data),
        }))

    def invalidate(self, system: str | None = None):
        """Clear cache entries. If system is given, only clear that system's cache."""
        if system:
            system_dir = CACHE_DIR / system
            if system_dir.exists():
                for f in system_dir.iterdir():
                    f.unlink(missing_ok=True)
                system_dir.rmdir()
        else:
            for system_dir in CACHE_DIR.iterdir():
                if system_dir.is_dir():
                    for f in system_dir.iterdir():
                        f.unlink(missing_ok=True)
                    system_dir.rmdir()

    def stats(self) -> dict:
        """Return cache statistics."""
        total_entries = 0
        total_bytes = 0
        expired = 0
        by_system: dict[str, int] = {}

        if not CACHE_DIR.exists():
            return {"entries": 0, "bytes": 0, "expired": 0, "by_system": {}}

        for system_dir in CACHE_DIR.iterdir():
            if not system_dir.is_dir():
                continue
            count = 0
            for f in system_dir.glob("*.json"):
                meta_path = f.with_suffix(".meta")
                if meta_path.exists():
                    try:
                        meta = json.loads(meta_path.read_text())
                        if time.time() - meta.get("stored_at", 0) > self.ttl:
                            expired += 1
                            continue
                    except (json.JSONDecodeError, OSError):
                        pass
                total_entries += 1
                total_bytes += f.stat().st_size
                count += 1
            by_system[system_dir.name] = count

        return {
            "entries": total_entries,
            "bytes": total_bytes,
            "expired": expired,
            "by_system": by_system,
        }
