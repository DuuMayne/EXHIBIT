from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class System(str, Enum):
    AWS = "aws"
    ENV0 = "env0"
    GITHUB = "github"
    OKTA = "okta"
    GOOGLE_WORKSPACE = "google_workspace"
    JIRA = "jira"
    CONFLUENCE = "confluence"
    CROWDSTRIKE = "crowdstrike"
    CLOUDFLARE = "cloudflare"
    SNOWFLAKE = "snowflake"
    KANDJI = "kandji"
    SEMGREP = "semgrep"
    BROWSER = "browser"
    MANUAL = "manual"


@dataclass
class EvidenceRequest:
    id: str                          # e.g. "1.2", "Q-14"
    question: str                    # raw question text
    category: str                    # e.g. "Access Control", "Encryption"
    systems: list[System]            # which systems should be queried
    hints: list[str] = field(default_factory=list)  # sub-hints from LLM parsing
    notes: str = ""


@dataclass
class EvidenceFile:
    filename: str
    content: bytes
    mime_type: str
    description: str


@dataclass
class EvidenceResult:
    request_id: str
    system: System
    files: list[EvidenceFile] = field(default_factory=list)
    text_summary: str = ""
    error: Optional[str] = None
    drive_file_ids: list[str] = field(default_factory=list)
