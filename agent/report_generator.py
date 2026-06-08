"""
Generate per-item explainer documents and the master summary.
Uses Claude to write a plain-language explanation of what each evidence file shows
and how it answers the audit question.
"""
import json
import os
from datetime import datetime

import anthropic

from .models import EvidenceRequest, EvidenceResult

EXPLAINER_PROMPT = """You are a compliance analyst writing evidence explainers for auditors.

Audit question (ID {id}):
"{question}"

Category: {category}
Systems queried: {systems}

Evidence files collected:
{files_list}

Text summaries from collectors:
{summaries}

Write a concise explainer (3-6 sentences) that:
1. States what the question is asking for
2. Describes what evidence was collected and from which systems
3. Highlights any key findings (e.g. "14 of 42 IAM users lack MFA", "all S3 buckets have encryption at rest enabled")
4. Notes any gaps or items requiring manual review

Be specific and factual. Use the actual numbers from the summaries. Do not make up information not in the evidence."""


def generate_explainer(request: EvidenceRequest, results: list[EvidenceResult]) -> str:
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    files_list = "\n".join(
        f"  - [{r.system.value}] {ef.filename}: {ef.description}"
        for r in results
        for ef in r.files
    ) or "  (no files collected)"

    summaries = "\n".join(
        f"[{r.system.value}] {r.text_summary}" for r in results if r.text_summary
    ) or "(no summaries available)"

    errors = [r.error for r in results if r.error]

    message = client.messages.create(
        model="claude-opus-4-8",
        max_tokens=1024,
        messages=[{
            "role": "user",
            "content": EXPLAINER_PROMPT.format(
                id=request.id,
                question=request.question,
                category=request.category,
                systems=", ".join(s.value for s in request.systems),
                files_list=files_list,
                summaries=summaries,
            ),
        }],
    )
    explanation = message.content[0].text

    # Build full explainer markdown
    lines = [
        f"# Evidence Explainer — Q{request.id}",
        f"",
        f"**Audit Question:** {request.question}",
        f"**Category:** {request.category}",
        f"**Systems:** {', '.join(s.value for s in request.systems)}",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"",
        f"---",
        f"",
        f"## Summary",
        f"",
        explanation,
        f"",
        f"---",
        f"",
        f"## Evidence Files",
        f"",
    ]
    for r in results:
        for ef in r.files:
            lines.append(f"- **{ef.filename}** ({r.system.value}): {ef.description}")
    if not any(r.files for r in results):
        lines.append("_No files collected._")

    if errors:
        lines += ["", "## Collection Errors", ""]
        for e in errors:
            lines.append(f"- {e}")

    if request.hints:
        lines += ["", "## Collection Hints Used", ""]
        for h in request.hints:
            lines.append(f"- {h}")

    return "\n".join(lines)


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
