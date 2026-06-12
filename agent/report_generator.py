"""
Generate per-item explainer documents and the master summary.
Uses the configured LLM backend (or heuristic fallback) to write
plain-language explanations of collected evidence.
"""
import json
import os
from datetime import datetime

from .models import EvidenceRequest, EvidenceResult
from .llm import get_explainer_generator


def generate_explainer(request: EvidenceRequest, results: list[EvidenceResult]) -> str:
    """Generate an explainer document using the configured backend."""
    generator = get_explainer_generator()
    return generator.generate(request, results)


def generate_master_summary(
    engagement_name: str,
    requests: list[EvidenceRequest],
    all_results: dict[str, list[EvidenceResult]],
    drive_link: str,
) -> tuple[str, str]:
    """Returns (markdown_summary, json_index)."""

    total_files = sum(
        len(ef.files)
        for results in all_results.values()
        for ef in results
    )
    errors = {
        req_id: [r.error for r in results if r.error]
        for req_id, results in all_results.items()
    }

    lines = [
        f"# Compliance Evidence Collection — {engagement_name}",
        f"",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Drive Folder:** {drive_link}",
        f"**Total questions:** {len(requests)}",
        f"**Total evidence files:** {total_files}",
        f"",
        f"---",
        f"",
        f"## Evidence Index",
        f"",
        f"| ID | Category | Question (truncated) | Systems | Files | Status |",
        f"|----|----------|---------------------|---------|-------|--------|",
    ]

    index = []
    for req in requests:
        results = all_results.get(req.id, [])
        file_count = sum(len(r.files) for r in results)
        has_errors = bool(errors.get(req.id))
        status = "ERROR" if has_errors else ("OK" if file_count > 0 else "NO DATA")
        lines.append(
            f"| {req.id} | {req.category} | {req.question[:60]}... | "
            f"{', '.join(s.value for s in req.systems)} | {file_count} | {status} |"
        )
        index.append({
            "id": req.id,
            "category": req.category,
            "question": req.question,
            "systems": [s.value for s in req.systems],
            "files": file_count,
            "errors": errors.get(req.id, []),
        })

    if any(errors.values()):
        lines += ["", "## Items Needing Manual Review", ""]
        for req_id, errs in errors.items():
            if errs:
                req = next((r for r in requests if r.id == req_id), None)
                q = req.question[:80] if req else req_id
                lines.append(f"- **{req_id}**: {q}")
                for e in errs:
                    lines.append(f"  - Error: {e}")

    return "\n".join(lines), json.dumps(index, indent=2)
