"""
Coverage gap reporting for the CHECKS ↔ EXHIBIT integration.

After a collection run, generates a report showing:
  - Which evidence requests were handled by CHECKS (deterministic, cheap)
  - Which had to fall back to EXHIBIT collectors (gap — needs a new evaluator)
  - For each gap: the question, systems, what EXHIBIT did, and a suggested check definition

This report is your roadmap for expanding the CHECKS library. Every gap
is a potential new evaluator that would make future runs cheaper and faster.

Output:
  - Printed summary at end of run
  - JSON report saved to workspace (machine-readable for tracking over time)
  - Markdown report saved to workspace (human-readable)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import EvidenceRequest, System


@dataclass
class CoverageEntry:
    """A single evidence request's coverage status."""
    request_id: str
    question: str
    category: str
    systems: list[str]
    tier: str  # "check", "collector", "skipped"
    check_keys_used: list[str] = field(default_factory=list)
    collector_systems_used: list[str] = field(default_factory=list)
    evidence_method: str = ""  # What EXHIBIT actually did
    suggested_check: Optional[dict] = None  # Proposed evaluator definition


@dataclass
class CoverageReport:
    """Full coverage report for a collection run."""
    run_id: str
    engagement: str
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    entries: list[CoverageEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def covered_by_checks(self) -> list[CoverageEntry]:
        return [e for e in self.entries if e.tier == "check"]

    @property
    def gaps(self) -> list[CoverageEntry]:
        return [e for e in self.entries if e.tier == "collector"]

    @property
    def skipped(self) -> list[CoverageEntry]:
        return [e for e in self.entries if e.tier == "skipped"]

    @property
    def coverage_rate(self) -> float:
        actionable = [e for e in self.entries if e.tier != "skipped"]
        if not actionable:
            return 0.0
        return len(self.covered_by_checks) / len(actionable)

    def add_check_hit(self, req: EvidenceRequest, check_keys: list[str]):
        """Record that CHECKS handled this request."""
        self.entries.append(CoverageEntry(
            request_id=req.id,
            question=req.question,
            category=req.category,
            systems=[s.value for s in req.systems],
            tier="check",
            check_keys_used=check_keys,
            evidence_method=f"Deterministic check(s): {', '.join(check_keys)}",
        ))

    def add_collector_fallback(
        self,
        req: EvidenceRequest,
        systems_used: list[str],
        method_description: str = "",
    ):
        """Record that EXHIBIT's collectors handled this (gap in CHECKS)."""
        suggested = _suggest_check(req)
        self.entries.append(CoverageEntry(
            request_id=req.id,
            question=req.question,
            category=req.category,
            systems=[s.value for s in req.systems],
            tier="collector",
            collector_systems_used=systems_used,
            evidence_method=method_description or f"EXHIBIT collectors: {', '.join(systems_used)}",
            suggested_check=suggested,
        ))

    def add_skip(self, req: EvidenceRequest, reason: str):
        """Record a skipped request (manual, no credentials, etc.)."""
        self.entries.append(CoverageEntry(
            request_id=req.id,
            question=req.question,
            category=req.category,
            systems=[s.value for s in req.systems],
            tier="skipped",
            evidence_method=f"Skipped: {reason}",
        ))

    def print_summary(self):
        """Print a human-readable summary to stdout."""
        total = self.total
        checks_count = len(self.covered_by_checks)
        gaps_count = len(self.gaps)
        skipped_count = len(self.skipped)
        rate = self.coverage_rate

        print(f"\n{'='*60}")
        print(f"  CHECKS Coverage Report")
        print(f"{'='*60}")
        print(f"  Total requests:      {total}")
        print(f"  Handled by CHECKS:   {checks_count} ({rate:.0%} coverage)")
        print(f"  Fell back to EXHIBIT:{gaps_count} (gaps — needs new evaluators)")
        print(f"  Skipped:             {skipped_count}")

        if self.gaps:
            print(f"\n  --- Coverage Gaps (evaluator opportunities) ---\n")
            for entry in self.gaps[:15]:
                print(f"  Q{entry.request_id}: {entry.question[:70]}")
                print(f"    Systems: {entry.systems}")
                print(f"    EXHIBIT did: {entry.evidence_method}")
                if entry.suggested_check:
                    print(f"    Suggested check: {entry.suggested_check.get('evaluator', '?')} via {entry.suggested_check.get('connector', '?')}")
                print()

            if len(self.gaps) > 15:
                print(f"  ... and {len(self.gaps) - 15} more gaps (see full report)")

        print(f"{'='*60}\n")

    def save_json(self, path: Path):
        """Save machine-readable report for tracking over time."""
        data = {
            "run_id": self.run_id,
            "engagement": self.engagement,
            "generated_at": self.generated_at,
            "summary": {
                "total": self.total,
                "covered_by_checks": len(self.covered_by_checks),
                "gaps": len(self.gaps),
                "skipped": len(self.skipped),
                "coverage_rate": round(self.coverage_rate, 4),
            },
            "gaps": [
                {
                    "request_id": e.request_id,
                    "question": e.question,
                    "category": e.category,
                    "systems": e.systems,
                    "evidence_method": e.evidence_method,
                    "suggested_check": e.suggested_check,
                }
                for e in self.gaps
            ],
            "covered": [
                {
                    "request_id": e.request_id,
                    "check_keys": e.check_keys_used,
                }
                for e in self.covered_by_checks
            ],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2))

    def save_markdown(self, path: Path):
        """Save human-readable markdown report."""
        rate = self.coverage_rate
        lines = [
            f"# CHECKS Coverage Report",
            f"",
            f"**Engagement:** {self.engagement}",
            f"**Run ID:** {self.run_id}",
            f"**Generated:** {self.generated_at[:19]}",
            f"**Coverage:** {rate:.0%} ({len(self.covered_by_checks)}/{self.total - len(self.skipped)} requests handled by deterministic checks)",
            f"",
            f"---",
            f"",
        ]

        if self.covered_by_checks:
            lines += [
                f"## Covered by CHECKS ({len(self.covered_by_checks)} items)",
                f"",
                f"| ID | Category | Check(s) Used |",
                f"|---|---|---|",
            ]
            for e in self.covered_by_checks:
                lines.append(f"| {e.request_id} | {e.category} | {', '.join(e.check_keys_used)} |")
            lines.append("")

        if self.gaps:
            lines += [
                f"## Gaps — Needs New Evaluators ({len(self.gaps)} items)",
                f"",
                f"These requests fell back to EXHIBIT's collectors. Each is an opportunity to write a deterministic check that would make future runs cheaper.",
                f"",
            ]
            for e in self.gaps:
                lines.append(f"### Q{e.request_id}: {e.question[:80]}")
                lines.append(f"")
                lines.append(f"- **Category:** {e.category}")
                lines.append(f"- **Systems:** {', '.join(e.systems)}")
                lines.append(f"- **What EXHIBIT did:** {e.evidence_method}")
                if e.suggested_check:
                    lines.append(f"- **Suggested check definition:**")
                    lines.append(f"  ```yaml")
                    lines.append(f"  {e.suggested_check.get('key', 'new_check')}:")
                    lines.append(f"    connector: {e.suggested_check.get('connector', '?')}")
                    lines.append(f"    evaluator: {e.suggested_check.get('evaluator', '? (needs implementation)')}")
                    lines.append(f"    config: {json.dumps(e.suggested_check.get('config', {}))}")
                    lines.append(f"  ```")
                lines.append(f"")

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines))


def _suggest_check(req: EvidenceRequest) -> dict:
    """Heuristically suggest a check definition for a coverage gap."""
    q_lower = req.question.lower()
    systems = [s.value for s in req.systems if s not in (System.MANUAL, System.BROWSER)]
    connector = systems[0] if systems else "unknown"

    # Try to guess an evaluator type from the question
    evaluator = "unknown"
    if any(kw in q_lower for kw in ["mfa", "multi-factor", "2fa"]):
        evaluator = "mfa_enforced"
    elif any(kw in q_lower for kw in ["branch protection", "code review", "pull request"]):
        evaluator = "branch_protection"
    elif any(kw in q_lower for kw in ["encrypt", "encryption"]):
        evaluator = "encryption_at_rest"
    elif any(kw in q_lower for kw in ["access key", "key rotation", "rotate"]):
        evaluator = "access_key_rotation"
    elif any(kw in q_lower for kw in ["cloudtrail", "audit log", "logging"]):
        evaluator = "cloudtrail_enabled"
    elif any(kw in q_lower for kw in ["vulnerability", "scanning", "patch"]):
        evaluator = "vulnerability_scanning"
    elif any(kw in q_lower for kw in ["endpoint", "edr", "antimalware"]):
        evaluator = "endpoint_protection"
    elif any(kw in q_lower for kw in ["password policy", "password strength"]):
        evaluator = "password_policy"
    elif any(kw in q_lower for kw in ["inactive", "dormant", "stale user"]):
        evaluator = "no_inactive_users"
    elif any(kw in q_lower for kw in ["secret scanning", "secrets"]):
        evaluator = "secret_scanning"

    # Generate a key from the question
    key = f"check_{req.id.replace('.', '_')}_{connector}"

    return {
        "key": key,
        "connector": connector,
        "evaluator": evaluator,
        "config": {},
        "source_question": req.question[:200],
    }
