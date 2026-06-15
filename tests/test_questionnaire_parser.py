"""Tests for questionnaire parsing — CSV, plain text, framework detection."""
import tempfile
from pathlib import Path

import pytest

from agent.questionnaire_parser import load_questionnaire, _heuristic_systems, parse_questionnaire
from agent.models import System


class TestLoadQuestionnaire:
    def test_csv_with_id_and_question(self, tmp_path):
        csv = tmp_path / "test.csv"
        csv.write_text("id,question\n1,Is MFA enabled?\n2,Are buckets encrypted?\n")
        df = load_questionnaire(str(csv))
        assert len(df) == 2
        assert df.iloc[0]["id"] == "1"
        assert "MFA" in df.iloc[0]["question"]

    def test_csv_with_category(self, tmp_path):
        csv = tmp_path / "test.csv"
        csv.write_text("id,category,question\nCC6.1,Access Control,Provide MFA evidence\n")
        df = load_questionnaire(str(csv))
        assert df.iloc[0]["id"] == "CC6.1"

    def test_plain_text_auto_numbered(self, tmp_path):
        txt = tmp_path / "test.txt"
        txt.write_text("Is MFA enabled?\nAre keys rotated?\n")
        df = load_questionnaire(str(txt))
        assert len(df) == 2
        assert df.iloc[0]["id"] == "1"
        assert df.iloc[1]["id"] == "2"

    def test_plain_text_with_numbers(self, tmp_path):
        txt = tmp_path / "test.txt"
        txt.write_text("1. Is MFA enabled?\n2. Are keys rotated?\n")
        df = load_questionnaire(str(txt))
        assert df.iloc[0]["id"] == "1"
        assert "MFA" in df.iloc[0]["question"]

    def test_comments_skipped(self, tmp_path):
        txt = tmp_path / "test.txt"
        txt.write_text("# This is a comment\nActual question here\n# Another comment\n")
        df = load_questionnaire(str(txt))
        assert len(df) == 1
        assert "Actual" in df.iloc[0]["question"]

    def test_empty_raises(self, tmp_path):
        txt = tmp_path / "test.txt"
        txt.write_text("# Only comments\n\n")
        with pytest.raises(ValueError, match="No questions"):
            load_questionnaire(str(txt))


class TestHeuristicSystems:
    def test_mfa_routes_to_okta(self):
        systems = _heuristic_systems("Is multi-factor authentication enforced?")
        assert System.OKTA in systems

    def test_encryption_routes_to_aws(self):
        systems = _heuristic_systems("Is encryption at rest enabled for all storage?")
        assert System.AWS in systems

    def test_github_keywords(self):
        systems = _heuristic_systems("Are branch protection rules enabled on all repositories?")
        assert System.GITHUB in systems

    def test_unknown_routes_to_manual(self):
        systems = _heuristic_systems("What color is the sky?")
        assert systems == [System.MANUAL]

    def test_multiple_systems_matched(self):
        systems = _heuristic_systems("Provide IAM users with MFA status from okta and aws")
        assert System.AWS in systems
        assert System.OKTA in systems


class TestParseQuestionnaire:
    def test_full_parse_no_claude(self, tmp_path):
        csv = tmp_path / "test.csv"
        csv.write_text("id,question\n1,Is MFA enforced for all users?\n2,Are S3 buckets encrypted?\n")
        requests = parse_questionnaire(str(csv), use_claude=False)
        assert len(requests) == 2
        assert requests[0].id == "1"
        assert System.OKTA in requests[0].systems
        assert System.AWS in requests[1].systems
