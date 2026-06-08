from __future__ import annotations
"""
Semgrep evidence collector via REST API (semgrep.dev/api/v1).

Auth: Bearer API token, scoped to a deployment (org slug).

Covers:
- Findings (open count by severity, grouped by repository)
- Projects (repos being scanned, last scan date)
- Policies (active scan policies and rule sets)
- Scans (recent 30-day scan history showing coverage)
"""
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import requests

from ..models import EvidenceFile, EvidenceRequest, EvidenceResult, System


def _json_bytes(data) -> bytes:
    return json.dumps(data, indent=2, default=str).encode()


class SemgrepCollector:
    BASE = "https://semgrep.dev/api/v1"

    def __init__(self):
        token = os.environ["SEMGREP_API_TOKEN"]
        self.org_slug = os.environ["SEMGREP_ORG_SLUG"]
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        })

    def _get(self, path: str, params: dict = None) -> dict:
        r = self.session.get(f"{self.BASE}{path}", params=params)
        r.raise_for_status()
        return r.json()

    def _get_paginated(self, path: str, list_key: str, params: dict = None) -> list:
        """Page through Semgrep list endpoints using page/page_size."""
        results = []
        page = 0
        page_size = (params or {}).get("page_size", 100)
        while True:
            p = dict(params or {})
            p.update({"page": page, "page_size": page_size})
            data = self._get(path, p)
            batch = data.get(list_key, []) or []
            results.extend(batch)
            if len(batch) < page_size:
                break
            page += 1
        return results

    def collect(self, request: EvidenceRequest) -> EvidenceResult:
        result = EvidenceResult(request_id=request.id, system=System.SEMGREP)
        hints_lower = " ".join(request.hints + [request.question]).lower()

        try:
            if any(k in hints_lower for k in ["finding", "vulnerability", "vuln", "sast", "issue", "severity", "code scan"]):
                self._collect_findings(result)

            if any(k in hints_lower for k in ["project", "repo", "repository", "coverage", "scanned"]):
                self._collect_projects(result)

            if any(k in hints_lower for k in ["policy", "rule", "ruleset", "rule set", "configuration"]):
                self._collect_policies(result)

            if any(k in hints_lower for k in ["scan", "scan history", "frequency", "last scan", "coverage"]):
                self._collect_scans(result)

            if not result.files:
                self._collect_summary(result)

        except Exception as e:
            result.error = str(e)

        return result

    def _collect_findings(self, result: EvidenceResult):
        findings = self._get_paginated(
            f"/deployments/{self.org_slug}/findings",
            "findings",
            {"status": "open"},
        )

        severity_dist = Counter()
        by_repo = defaultdict(lambda: Counter())
        for f in findings:
            sev = str(f.get("severity", "unknown")).lower()
            severity_dist[sev] += 1
            repo = (f.get("repository") or {}).get("name") if isinstance(f.get("repository"), dict) else f.get("repository") or "unknown"
            by_repo[repo][sev] += 1

        payload = {
            "total_open_findings": len(findings),
            "severity_distribution": dict(severity_dist),
            "by_repository": {repo: dict(counts) for repo, counts in by_repo.items()},
        }

        result.files.append(EvidenceFile(
            filename="semgrep_findings.json",
            content=_json_bytes(payload),
            mime_type="application/json",
            description=f"Semgrep open findings ({len(findings)}) by severity and repository",
        ))
        result.text_summary += (
            f"Semgrep: {len(findings)} open findings "
            f"(critical={severity_dist.get('critical', 0)}, high={severity_dist.get('high', 0)}) "
            f"across {len(by_repo)} repositories.\n"
        )

    def _collect_projects(self, result: EvidenceResult):
        projects = self._get_paginated(f"/deployments/{self.org_slug}/projects", "projects")
        summary = [{
            "id": p.get("id"),
            "name": p.get("name"),
            "url": p.get("url"),
            "default_branch": p.get("default_branch"),
            "latest_scan_at": p.get("latest_scan_at") or p.get("last_scan_at"),
            "tags": p.get("tags"),
        } for p in projects]

        result.files.append(EvidenceFile(
            filename="semgrep_projects.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description=f"Semgrep scanned projects/repositories ({len(summary)})",
        ))
        result.text_summary += f"Semgrep: {len(summary)} repositories under scan coverage.\n"

    def _collect_policies(self, result: EvidenceResult):
        try:
            data = self._get(f"/deployments/{self.org_slug}/policies")
            policies = data.get("policies", data) if isinstance(data, dict) else data
        except Exception as e:
            result.text_summary += f"Semgrep policies unavailable: {e}\n"
            policies = []

        result.files.append(EvidenceFile(
            filename="semgrep_policies.json",
            content=_json_bytes(policies),
            mime_type="application/json",
            description=f"Semgrep active scan policies and rule sets",
        ))
        n = len(policies) if isinstance(policies, list) else "configured"
        result.text_summary += f"Semgrep: {n} scan policies / rule sets active.\n"

    def _collect_scans(self, result: EvidenceResult):
        since = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        scans = self._get_paginated(
            f"/deployments/{self.org_slug}/scans",
            "scans",
            {"since": since},
        )

        recent = [s for s in scans if (s.get("started_at") or s.get("start_time") or "") >= since] or scans
        repos_scanned = {(s.get("repository") or {}).get("name") if isinstance(s.get("repository"), dict) else s.get("repository") for s in recent}

        summary = [{
            "id": s.get("id"),
            "repository": (s.get("repository") or {}).get("name") if isinstance(s.get("repository"), dict) else s.get("repository"),
            "status": s.get("status"),
            "started_at": s.get("started_at") or s.get("start_time"),
            "completed_at": s.get("completed_at") or s.get("end_time"),
            "findings_count": s.get("findings_count"),
        } for s in recent]

        result.files.append(EvidenceFile(
            filename="semgrep_scans_30d.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description=f"Semgrep scan history last 30 days ({len(summary)} scans)",
        ))
        result.text_summary += (
            f"Semgrep: {len(summary)} scans in last 30 days across "
            f"{len([r for r in repos_scanned if r])} repositories.\n"
        )

    def _collect_summary(self, result: EvidenceResult):
        projects = self._get_paginated(f"/deployments/{self.org_slug}/projects", "projects")
        summary = {
            "org_slug": self.org_slug,
            "project_count": len(projects),
            "projects": [{"id": p.get("id"), "name": p.get("name")} for p in projects],
        }
        result.files.append(EvidenceFile(
            filename="semgrep_summary.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description="Semgrep deployment summary",
        ))
        result.text_summary += f"Semgrep: {len(projects)} projects in deployment '{self.org_slug}'.\n"
