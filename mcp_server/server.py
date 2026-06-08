from __future__ import annotations
"""
MCP server for EXHIBIT — Evidence eXtraction, Harvesting and Intelligence-Based Investigation Tool.

Runs inside Docker Desktop. Credentials are injected as container
environment variables (set in Docker Desktop UI or docker-compose.yml)
rather than via a project-level .env file.

Transport: SSE over HTTP (port 8765 by default).
Claude Code config: {"url": "http://localhost:8765/sse"}
"""
import contextlib
import json
import os
import sys
import tempfile
from io import StringIO
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

# Make the agent package importable from /app inside Docker
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.main import CREDENTIAL_CHECKS, check_credentials, dry_run, run
from agent.models import System

_FRAMEWORKS_DIR = Path("/app/frameworks")

mcp = FastMCP(
    "exhibit",
    instructions="""EXHIBIT — Evidence eXtraction, Harvesting and Intelligence-Based Investigation Tool.
Queries integrated systems (AWS, GitHub, CrowdStrike, Okta, etc.) and organises
all evidence into a structured Google Drive folder. Use dry_run first to verify routing,
then collect_evidence for the real run.""",
)


@contextlib.contextmanager
def _redirect_to_stderr():
    """Redirect stdout to stderr so agent print() calls don't corrupt MCP stdio."""
    old = sys.stdout
    sys.stdout = sys.stderr
    try:
        yield
    finally:
        sys.stdout = old


@contextlib.contextmanager
def _capture_stdout():
    """Capture stdout to a string buffer (for dry_run output)."""
    old = sys.stdout
    buf = StringIO()
    sys.stdout = buf
    try:
        yield buf
    finally:
        sys.stdout = old


@mcp.tool()
def list_frameworks() -> str:
    """List the available framework questionnaire templates."""
    if not _FRAMEWORKS_DIR.exists():
        return "frameworks/ directory not found — is the volume mounted?"
    files = sorted(_FRAMEWORKS_DIR.glob("*.csv"))
    if not files:
        return "No CSV templates found in frameworks/"
    lines = ["Available framework templates:", ""]
    for f in files:
        lines.append(f"  {f.name}")
    lines.append("")
    lines.append("Pass any of these paths to dry_run or collect_evidence.")
    return "\n".join(lines)


@mcp.tool()
def check_integration_status() -> str:
    """Check which integrations have credentials configured in this container."""
    lines = ["=== Integration Status ===", ""]
    for system, check_fn in CREDENTIAL_CHECKS.items():
        try:
            ok = bool(check_fn())
        except Exception:
            ok = False
        status = "OK" if ok else "MISSING — set env var in Docker Desktop"
        lines.append(f"  {system.value:<30} {status}")
    lines.append("")
    drive_path = os.getenv("GOOGLE_CREDENTIALS_PATH", "")
    drive_ok = Path(drive_path).exists() if drive_path else False
    lines.append(f"  {'google_drive (upload)':<30} {'OK' if drive_ok else 'MISSING — mount service account JSON'}")
    return "\n".join(lines)


@mcp.tool()
def upload_questionnaire(content: str, filename: str = "questionnaire.csv") -> str:
    """
    Save a questionnaire CSV (or pasted text) to a temp file inside the container.

    Returns the path to use with dry_run or collect_evidence.
    Accepts either valid CSV with id,question columns or plain text lines
    (each line becomes a numbered question).
    """
    tmp = Path(tempfile.mkdtemp(prefix="compliance_")) / filename
    if "," in content.splitlines()[0] if content.strip() else False:
        tmp.write_text(content, encoding="utf-8")
    else:
        # Plain-text lines → auto-number into CSV
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        rows = ["id,question"] + [f"{i},{json.dumps(l)}" for i, l in enumerate(lines, 1)]
        tmp.write_text("\n".join(rows), encoding="utf-8")
    return str(tmp)


@mcp.tool()
def dry_run_collection(questionnaire_path: str, engagement_name: str) -> str:
    """
    Parse a questionnaire and show the evidence collection plan.

    No API calls are made — safe to run before committing to a full collection.

    Args:
        questionnaire_path: Path to CSV/Excel, or use upload_questionnaire first.
                           Framework templates live at /app/frameworks/*.csv
        engagement_name: Human-readable label, e.g. "Baker Tilly Q2 2026"
    """
    with _capture_stdout() as buf:
        try:
            dry_run(questionnaire_path, engagement_name, use_claude=False)
        except Exception as e:
            return f"Error: {e}"
    return buf.getvalue()


@mcp.tool()
def collect_evidence(
    questionnaire_path: str,
    engagement_name: str,
    only_systems: Optional[str] = None,
    use_claude: bool = True,
) -> str:
    """
    Run the full evidence collection pipeline.

    Queries all relevant systems, uploads evidence files, and creates a
    structured Google Drive folder. Returns the Drive folder link when done.

    Args:
        questionnaire_path: Path to CSV/Excel questionnaire, or output of upload_questionnaire.
                           Built-in templates: /app/frameworks/soc2_type2.csv,
                           /app/frameworks/earnest_audit_2026.csv, etc.
        engagement_name: Label for the Drive folder, e.g. "Baker Tilly Q2 2026 SOC 2"
        only_systems: Comma-separated list to restrict collection, e.g. "aws,github,okta".
                     Leave blank to collect from all configured systems.
        use_claude: Whether to use Claude for question classification (default True).
                   Set False for faster offline routing.
    """
    only = None
    if only_systems:
        valid = {s.value: s for s in System}
        only = []
        for name in only_systems.split(","):
            name = name.strip()
            if name not in valid:
                return f"Unknown system '{name}'. Valid: {list(valid.keys())}"
            only.append(valid[name])

    with _redirect_to_stderr():
        try:
            drive_link = run(
                questionnaire_path,
                engagement_name,
                only_systems=only,
                use_claude=use_claude,
            )
        except Exception as e:
            return f"Collection failed: {e}"

    return f"Collection complete.\nDrive folder: {drive_link}"


if __name__ == "__main__":
    port = int(os.environ.get("MCP_PORT", "8765"))
    mcp.run(transport="sse", host="0.0.0.0", port=port)
