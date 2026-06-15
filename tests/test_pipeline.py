"""Tests for the pipeline workspace — serialization and stage management."""
import shutil
from pathlib import Path

import pytest

from agent.pipeline import CollectionRun, Stage
from agent.models import EvidenceFile, EvidenceRequest, EvidenceResult, System


class TestCollectionRun:
    def setup_method(self):
        self.run = CollectionRun(
            run_id="test_20260615",
            engagement="Test Engagement",
            questionnaire_path="/tmp/test.csv",
        )

    def teardown_method(self):
        if self.run.workspace.exists():
            shutil.rmtree(self.run.workspace)

    def test_initial_stage(self):
        assert self.run.stage == Stage.INITIALIZED

    def test_save_and_load(self):
        self.run.requests = [
            EvidenceRequest(id="1", question="Test?", category="General", systems=[System.AWS]),
        ]
        self.run.stage = Stage.PARSED
        self.run.save()

        loaded = CollectionRun.load("test_20260615")
        assert loaded.engagement == "Test Engagement"
        assert loaded.stage == Stage.PARSED
        assert len(loaded.requests) == 1
        assert loaded.requests[0].id == "1"

    def test_save_evidence(self):
        result = EvidenceResult(
            request_id="1",
            system=System.AWS,
            files=[EvidenceFile(filename="test.json", content=b'{"key": "value"}', mime_type="application/json", description="Test file")],
            text_summary="Test summary",
        )
        self.run.save_evidence("1", result)

        loaded = self.run.load_evidence("1", System.AWS)
        assert loaded is not None
        assert len(loaded.files) == 1
        assert loaded.files[0].filename == "test.json"
        assert loaded.text_summary == "Test summary"

    def test_load_nonexistent_evidence(self):
        result = self.run.load_evidence("nonexistent", System.AWS)
        assert result is None
