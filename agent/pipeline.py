"""
Pipeline abstraction for EXHIBIT evidence collection.

Separates the monolithic run() into distinct, resumable stages:
  1. parse    — questionnaire → EvidenceRequests (serializable)
  2. collect  — EvidenceRequests → evidence files on disk
  3. upload   — evidence files → Google Drive folder

Each stage produces a CollectionRun that can be saved to/loaded from
a workspace directory. This enables:
  - Collecting evidence, reviewing locally, then uploading
  - Re-uploading with different Drive organization
  - Inspecting collected evidence without Drive access
  - Resuming a failed collection without re-parsing

Workspace layout:
  ~/.exhibit/workspaces/<run_id>/
    manifest.json          — run metadata + stage state
    requests.json          — parsed EvidenceRequests
    evidence/
      <request_id>/
        <system>/
          <filename>       — raw evidence files
          _meta.json       — file descriptions, summaries, errors
    explainers/
      <request_id>.md      — generated explainer docs
"""
from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from .models import EvidenceFile, EvidenceRequest, EvidenceResult, System

WORKSPACES_DIR = Path(os.environ.get("EXHIBIT_WORKSPACES_DIR", Path.home() / ".exhibit" / "workspaces"))


class Stage(str, Enum):
    INITIALIZED = "initialized"
    PARSED = "parsed"
    COLLECTED = "collected"
    UPLOADED = "uploaded"


@dataclass
class CollectionRun:
    """Represents the full state of an evidence collection pipeline run."""

    run_id: str
    engagement: str
    questionnaire_path: str
    stage: Stage = Stage.INITIALIZED
    created_at: str = ""
    updated_at: str = ""
    flags: dict = field(default_factory=dict)
    requests: list[EvidenceRequest] = field(default_factory=list)
    drive_link: Optional[str] = None
    error: Optional[str] = None

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at

    @property
    def workspace(self) -> Path:
        return WORKSPACES_DIR / self.run_id

    @property
    def evidence_dir(self) -> Path:
        return self.workspace / "evidence"

    @property
    def explainers_dir(self) -> Path:
        return self.workspace / "explainers"

    def save(self):
        """Persist run state to the workspace directory."""
        self.updated_at = datetime.now(timezone.utc).isoformat()
        self.workspace.mkdir(parents=True, exist_ok=True)

        manifest = {
            "run_id": self.run_id,
            "engagement": self.engagement,
            "questionnaire_path": self.questionnaire_path,
            "stage": self.stage.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "flags": self.flags,
            "drive_link": self.drive_link,
            "error": self.error,
        }
        (self.workspace / "manifest.json").write_text(
            json.dumps(manifest, indent=2)
        )

        # Save parsed requests
        if self.requests:
            requests_data = [
                {
                    "id": r.id,
                    "question": r.question,
                    "category": r.category,
                    "systems": [s.value for s in r.systems],
                    "hints": r.hints,
                    "notes": r.notes,
                }
                for r in self.requests
            ]
            (self.workspace / "requests.json").write_text(
                json.dumps(requests_data, indent=2)
            )

    @classmethod
    def load(cls, run_id: str) -> "CollectionRun":
        """Load a run from its workspace directory."""
        workspace = WORKSPACES_DIR / run_id
        manifest_path = workspace / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"No workspace found for run: {run_id}")

        manifest = json.loads(manifest_path.read_text())
        run = cls(
            run_id=manifest["run_id"],
            engagement=manifest["engagement"],
            questionnaire_path=manifest["questionnaire_path"],
            stage=Stage(manifest["stage"]),
            created_at=manifest["created_at"],
            updated_at=manifest["updated_at"],
            flags=manifest.get("flags", {}),
            drive_link=manifest.get("drive_link"),
            error=manifest.get("error"),
        )

        # Load requests if present
        requests_path = workspace / "requests.json"
        if requests_path.exists():
            requests_data = json.loads(requests_path.read_text())
            run.requests = [
                EvidenceRequest(
                    id=r["id"],
                    question=r["question"],
                    category=r["category"],
                    systems=[System(s) for s in r["systems"]],
                    hints=r.get("hints", []),
                    notes=r.get("notes", ""),
                )
                for r in requests_data
            ]

        return run

    @classmethod
    def list_runs(cls, limit: int = 20) -> list[dict]:
        """List recent workspaces."""
        if not WORKSPACES_DIR.exists():
            return []
        runs = []
        for d in sorted(WORKSPACES_DIR.iterdir(), reverse=True):
            if not d.is_dir():
                continue
            manifest_path = d / "manifest.json"
            if not manifest_path.exists():
                continue
            try:
                m = json.loads(manifest_path.read_text())
                runs.append({
                    "run_id": m["run_id"],
                    "engagement": m["engagement"],
                    "stage": m["stage"],
                    "created_at": m["created_at"],
                })
            except (json.JSONDecodeError, KeyError):
                continue
            if len(runs) >= limit:
                break
        return runs

    def save_evidence(self, request_id: str, result: EvidenceResult):
        """Write an EvidenceResult's files to the workspace."""
        item_dir = self.evidence_dir / request_id / result.system.value
        item_dir.mkdir(parents=True, exist_ok=True)

        # Write each evidence file
        for ef in result.files:
            (item_dir / ef.filename).write_bytes(ef.content)

        # Write metadata
        meta = {
            "request_id": result.request_id,
            "system": result.system.value,
            "text_summary": result.text_summary,
            "error": result.error,
            "files": [
                {
                    "filename": ef.filename,
                    "mime_type": ef.mime_type,
                    "description": ef.description,
                    "size_bytes": len(ef.content),
                }
                for ef in result.files
            ],
        }
        (item_dir / "_meta.json").write_text(json.dumps(meta, indent=2))

    def load_evidence(self, request_id: str, system: System) -> Optional[EvidenceResult]:
        """Load a previously saved EvidenceResult from the workspace."""
        item_dir = self.evidence_dir / request_id / system.value
        meta_path = item_dir / "_meta.json"
        if not meta_path.exists():
            return None

        meta = json.loads(meta_path.read_text())
        files = []
        for f_meta in meta["files"]:
            file_path = item_dir / f_meta["filename"]
            if file_path.exists():
                files.append(EvidenceFile(
                    filename=f_meta["filename"],
                    content=file_path.read_bytes(),
                    mime_type=f_meta["mime_type"],
                    description=f_meta["description"],
                ))

        return EvidenceResult(
            request_id=meta["request_id"],
            system=System(meta["system"]),
            files=files,
            text_summary=meta.get("text_summary", ""),
            error=meta.get("error"),
        )

    def load_all_evidence(self) -> dict[str, list[EvidenceResult]]:
        """Load all evidence results from the workspace."""
        all_results: dict[str, list[EvidenceResult]] = {}
        if not self.evidence_dir.exists():
            return all_results

        for req_dir in sorted(self.evidence_dir.iterdir()):
            if not req_dir.is_dir():
                continue
            request_id = req_dir.name
            results = []
            for sys_dir in req_dir.iterdir():
                if not sys_dir.is_dir():
                    continue
                try:
                    system = System(sys_dir.name)
                except ValueError:
                    continue
                result = self.load_evidence(request_id, system)
                if result:
                    results.append(result)
            if results:
                all_results[request_id] = results

        return all_results

    def save_explainer(self, request_id: str, content: str):
        """Save an explainer document."""
        self.explainers_dir.mkdir(parents=True, exist_ok=True)
        (self.explainers_dir / f"{request_id}.md").write_text(content)

    def load_explainer(self, request_id: str) -> Optional[str]:
        """Load a previously generated explainer."""
        path = self.explainers_dir / f"{request_id}.md"
        if path.exists():
            return path.read_text()
        return None

    def cleanup(self):
        """Remove the workspace directory."""
        if self.workspace.exists():
            shutil.rmtree(self.workspace)
