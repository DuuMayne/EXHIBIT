"""
LLM abstraction layer for EXHIBIT.

Defines protocols for classification and explainer generation, with
pluggable implementations. The active implementation is selected at
runtime based on configuration (EXHIBIT_LLM_BACKEND env var).

Backends:
  - "claude" (default): Uses Anthropic Claude API
  - "heuristic": Keyword matching + framework maps only, no API calls
  - Future: "ollama", "openai", etc.

Usage:
    from agent.llm import get_classifier, get_explainer_generator

    classifier = get_classifier()         # returns appropriate backend
    results = classifier.classify(rows)

    explainer = get_explainer_generator()
    text = explainer.generate(request, results)
"""
from __future__ import annotations

import json
import os
import re
from abc import ABC, abstractmethod
from typing import Protocol

from .models import EvidenceRequest, EvidenceResult, System


# ---------------------------------------------------------------------------
# Protocols (interfaces)
# ---------------------------------------------------------------------------

class Classifier(ABC):
    """Classifies questionnaire items → systems, categories, and hints."""

    @abstractmethod
    def classify(self, rows: list[dict]) -> list[dict]:
        """
        Classify a batch of questionnaire items.

        Args:
            rows: List of dicts with "id" and "question" keys.

        Returns:
            List of dicts with keys: "id", "category", "systems" (list[str]), "hints" (list[str]).
            Returns empty list on failure (caller falls back to heuristics).
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable backend name for logging."""
        ...


class ExplainerGenerator(ABC):
    """Generates plain-language explainer documents for collected evidence."""

    @abstractmethod
    def generate(self, request: EvidenceRequest, results: list[EvidenceResult]) -> str:
        """
        Generate an explainer markdown document.

        Args:
            request: The original evidence request.
            results: Collected evidence results for this request.

        Returns:
            Markdown string with the explainer content.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...


# ---------------------------------------------------------------------------
# Claude implementation
# ---------------------------------------------------------------------------

CLASSIFICATION_PROMPT = """You are a compliance evidence analyst. Given a list of audit questions or evidence requests, classify each one.

System reference:
- "aws": IAM, CloudTrail, S3, RDS, ACM, CloudWatch, Config — any AWS infrastructure or database access
- "env0": infrastructure-as-code deployments, Terraform/OpenTofu runs, environment inventory (prod/staging separation), IaC team permissions, deployment approvals, configuration drift — use for ANY infrastructure change or deploy-to-production question
- "github": application code changes (PRs, commits), branch protections, SAST/secret scanning, repo membership, staging branches — use alongside env0 for change management questions
- "okta": access reviews, user accounts, MFA, privileged access, provisioning/deprovisioning, inactivity policy
- "jira": tickets, populations/samples of changes, incidents, access modification logs, restoration evidence
- "confluence": policies, procedures, runbooks — anything asking for written documentation
- "google_workspace": Gmail, Drive, admin console, 2SV, audit logs
- "crowdstrike": EDR/antimalware coverage, prevention policies, endpoint detections, vulnerability spotlight, host groups; also serves as the SIEM — use for centralized logging, security monitoring, threat detection, and XDR questions
- "cloudflare": CDN/edge, WAF rules, TLS/SSL config, DDoS protection, Cloudflare Access/Zero Trust, web filtering
- "snowflake": data warehouse user accounts, role grants, login history, query audit, password and network policies
- "kandji": MDM device inventory, FileVault/encryption compliance, blueprints, patch management, automated enrollment
- "semgrep": SAST findings by severity/repo, projects scanned, scan policies, pipeline coverage
- "lacework": cloud security posture (CSPM), compliance assessments, cloud alerts/violations, host and container vulnerability findings; use for cloud misconfiguration or cloud benchmark questions
- "browser": internal applications without usable APIs, 1Password, ArgoCD, New Relic, Zendesk, HackerOne, Pritunl VPN, Retool, or any other app requiring interactive browser access
- "manual": items requiring human narrative response or physical evidence with no automatable source

For each item return a JSON object with:
- "id": the item ID/number from the input
- "category": the compliance category (e.g. "Access Control", "Change Management", "Logging & Monitoring", "Business Continuity", "IT Operations", "Network Security", "Vulnerability Management")
- "systems": array of systems to query from the list above — include ALL relevant systems for the question
- "hints": array of 3-5 specific artifacts to collect (e.g. "GitHub PR list filtered to 01/01/2026-present with author, approver, merge date", "Okta users report showing last login and MFA status", "Jira tickets labeled restoration-test from Q1 2026")

Return a JSON array, one object per item. Be precise in hints — they are instructions to automated collectors.

Questions to classify:
{questions}"""

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


class ClaudeClassifier(Classifier):
    """Classification via Anthropic Claude API."""

    def __init__(self, model: str | None = None):
        import anthropic
        self._client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self._model = model or os.environ.get("EXHIBIT_CLAUDE_MODEL", "claude-sonnet-4-20250514")

    @property
    def name(self) -> str:
        return f"claude ({self._model})"

    def classify(self, rows: list[dict]) -> list[dict]:
        questions_text = "\n".join(f"{r['id']}. {r['question']}" for r in rows)

        message = self._client.messages.create(
            model=self._model,
            max_tokens=8192,
            messages=[{
                "role": "user",
                "content": CLASSIFICATION_PROMPT.format(questions=questions_text),
            }],
        )

        raw = message.content[0].text
        json_match = re.search(r"\[.*\]", raw, re.DOTALL)
        if not json_match:
            raise ValueError(f"Could not parse classification response:\n{raw[:500]}")
        return json.loads(json_match.group())


class ClaudeExplainerGenerator(ExplainerGenerator):
    """Explainer generation via Anthropic Claude API."""

    def __init__(self, model: str | None = None):
        import anthropic
        self._client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self._model = model or os.environ.get("EXHIBIT_CLAUDE_MODEL", "claude-sonnet-4-20250514")

    @property
    def name(self) -> str:
        return f"claude ({self._model})"

    def generate(self, request: EvidenceRequest, results: list[EvidenceResult]) -> str:
        from datetime import datetime

        files_list = "\n".join(
            f"  - [{r.system.value}] {ef.filename}: {ef.description}"
            for r in results for ef in r.files
        ) or "  (no files collected)"

        summaries = "\n".join(
            f"[{r.system.value}] {r.text_summary}" for r in results if r.text_summary
        ) or "(no summaries available)"

        message = self._client.messages.create(
            model=self._model,
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
        return self._format_explainer(request, results, explanation)

    def _format_explainer(
        self, request: EvidenceRequest, results: list[EvidenceResult], explanation: str
    ) -> str:
        from datetime import datetime, timezone
        lines = [
            f"# Evidence Explainer — Q{request.id}",
            f"",
            f"**Audit Question:** {request.question}",
            f"**Category:** {request.category}",
            f"**Systems:** {', '.join(s.value for s in request.systems)}",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
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

        errors = [r.error for r in results if r.error]
        if errors:
            lines += ["", "## Collection Errors", ""]
            for e in errors:
                lines.append(f"- {e}")

        if request.hints:
            lines += ["", "## Collection Hints Used", ""]
            for h in request.hints:
                lines.append(f"- {h}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Heuristic implementation (no API calls)
# ---------------------------------------------------------------------------

class HeuristicClassifier(Classifier):
    """Classification using keyword matching only. No external API calls."""

    @property
    def name(self) -> str:
        return "heuristic"

    def classify(self, rows: list[dict]) -> list[dict]:
        # Return empty — caller will fall through to keyword/framework heuristics
        return []


class HeuristicExplainerGenerator(ExplainerGenerator):
    """Generates a basic explainer from file metadata without LLM calls."""

    @property
    def name(self) -> str:
        return "heuristic"

    def generate(self, request: EvidenceRequest, results: list[EvidenceResult]) -> str:
        from datetime import datetime, timezone

        lines = [
            f"# Evidence Explainer — Q{request.id}",
            f"",
            f"**Audit Question:** {request.question}",
            f"**Category:** {request.category}",
            f"**Systems:** {', '.join(s.value for s in request.systems)}",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"",
            f"---",
            f"",
            f"## Summary",
            f"",
        ]

        # Build a basic summary from text_summary fields
        summaries = [r.text_summary for r in results if r.text_summary]
        if summaries:
            lines.append("Evidence was collected from the following systems:")
            lines.append("")
            for r in results:
                if r.text_summary:
                    lines.append(f"- **{r.system.value}**: {r.text_summary.strip()[:200]}")
        else:
            file_count = sum(len(r.files) for r in results)
            systems_used = set(r.system.value for r in results if r.files)
            lines.append(
                f"Collected {file_count} evidence file(s) from: {', '.join(sorted(systems_used)) or 'none'}."
            )

        lines += ["", "---", "", "## Evidence Files", ""]
        for r in results:
            for ef in r.files:
                lines.append(f"- **{ef.filename}** ({r.system.value}): {ef.description}")
        if not any(r.files for r in results):
            lines.append("_No files collected._")

        errors = [r.error for r in results if r.error]
        if errors:
            lines += ["", "## Collection Errors", ""]
            for e in errors:
                lines.append(f"- {e}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------

def get_classifier(backend: str | None = None) -> Classifier:
    """Get the configured classifier backend.

    Args:
        backend: Override backend selection. If None, uses EXHIBIT_LLM_BACKEND env var
                 (default: "claude" if ANTHROPIC_API_KEY is set, else "heuristic").
    """
    if backend is None:
        backend = os.environ.get("EXHIBIT_LLM_BACKEND", "").lower()
        if not backend:
            backend = "claude" if os.environ.get("ANTHROPIC_API_KEY") else "heuristic"

    if backend == "claude":
        return ClaudeClassifier()
    elif backend == "heuristic":
        return HeuristicClassifier()
    else:
        raise ValueError(f"Unknown LLM backend: '{backend}'. Valid: claude, heuristic")


def get_explainer_generator(backend: str | None = None) -> ExplainerGenerator:
    """Get the configured explainer generator backend.

    Args:
        backend: Override backend selection. If None, uses EXHIBIT_LLM_BACKEND env var
                 (default: "claude" if ANTHROPIC_API_KEY is set, else "heuristic").
    """
    if backend is None:
        backend = os.environ.get("EXHIBIT_LLM_BACKEND", "").lower()
        if not backend:
            backend = "claude" if os.environ.get("ANTHROPIC_API_KEY") else "heuristic"

    if backend == "claude":
        return ClaudeExplainerGenerator()
    elif backend == "heuristic":
        return HeuristicExplainerGenerator()
    else:
        raise ValueError(f"Unknown LLM backend: '{backend}'. Valid: claude, heuristic")
