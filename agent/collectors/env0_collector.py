from __future__ import annotations
"""
env0 evidence collector via REST API.

Covers:
- Deployment run history (who deployed what, when, approval status)
- Environment inventory (prod, staging, per-service)
- Team membership and permissions (who can deploy to prod)
- Audit log (access changes, variable changes, environment creates/destroys)
- Drift detection results
- Variable and secret usage (names only, not values)
"""
import json
import os
from datetime import datetime, timezone

import requests

from ..models import EvidenceFile, EvidenceRequest, EvidenceResult, System


def _json_bytes(data) -> bytes:
    return json.dumps(data, indent=2, default=str).encode()


class Env0Collector:
    BASE = "https://api.env0.com"

    def __init__(self):
        api_key = os.environ["ENV0_API_KEY"]
        self.session = requests.Session()
        self.session.auth = (api_key, "")  # env0 uses API key as HTTP Basic username
        self.session.headers.update({"Accept": "application/json"})
        self.org_id = os.environ.get("ENV0_ORG_ID") or self._get_org_id()

    def _get_org_id(self) -> str:
        r = self.session.get(f"{self.BASE}/organizations")
        r.raise_for_status()
        orgs = r.json()
        if not orgs:
            raise ValueError("No env0 organizations found for this API key")
        if len(orgs) > 1:
            print(f"  [env0] Multiple orgs found, using first: {orgs[0]['name']}. Set ENV0_ORG_ID to override.")
        return orgs[0]["id"]

    def _get(self, path: str, params: dict = None) -> list | dict:
        r = self.session.get(f"{self.BASE}{path}", params=params)
        r.raise_for_status()
        return r.json()

    def collect(self, request: EvidenceRequest) -> EvidenceResult:
        result = EvidenceResult(request_id=request.id, system=System.ENV0)
        hints_lower = " ".join(request.hints + [request.question]).lower()

        try:
            if any(k in hints_lower for k in [
                "deploy", "deployment", "code change", "infrastructure change",
                "iac", "terraform", "run history", "production deploy",
            ]):
                self._collect_deployment_runs(result)

            if any(k in hints_lower for k in [
                "environment", "staging", "production environment", "env",
                "database", "rds", "snowflake", "change",
            ]):
                self._collect_environments(result)

            if any(k in hints_lower for k in [
                "access", "team", "permission", "who can deploy", "role",
                "least privilege", "segregation", "separation of duties",
            ]):
                self._collect_teams_and_permissions(result)

            if any(k in hints_lower for k in [
                "audit", "audit log", "access change", "modification",
                "user change", "variable change",
            ]):
                self._collect_audit_log(result)

            if any(k in hints_lower for k in [
                "drift", "configuration drift", "unauthorized change",
            ]):
                self._collect_drift_results(result)

            if not result.files:
                self._collect_org_summary(result)

        except Exception as e:
            result.error = str(e)

        return result

    def _collect_deployment_runs(self, result: EvidenceResult):
        # Get all projects first
        projects = self._get("/projects", {"organizationId": self.org_id})
        if isinstance(projects, dict):
            projects = projects.get("projects", [])

        all_runs = []
        for project in projects:
            try:
                deployments = self._get("/deployments", {
                    "projectId": project["id"],
                    "limit": 100,
                })
                if isinstance(deployments, dict):
                    deployments = deployments.get("deployments", [])
                for d in deployments:
                    all_runs.append({
                        "id": d.get("id"),
                        "projectName": project.get("name"),
                        "environmentName": d.get("environmentName") or d.get("environment", {}).get("name"),
                        "status": d.get("status"),
                        "type": d.get("type"),          # deploy, destroy, plan
                        "triggeredBy": d.get("triggeredBy") or d.get("user", {}).get("name"),
                        "startedAt": d.get("startedAt"),
                        "finishedAt": d.get("finishedAt"),
                        "blueprintName": d.get("blueprintName"),  # template/module name
                        "requiresApproval": d.get("requiresApproval"),
                        "approvedBy": d.get("approvedBy"),
                        "gitBranch": d.get("blueprintRevision") or d.get("gitBranch"),
                        "prLink": d.get("prLink"),
                    })
            except Exception:
                pass

        result.files.append(EvidenceFile(
            filename="env0_deployment_runs.json",
            content=_json_bytes(all_runs),
            mime_type="application/json",
            description=f"env0 deployment run history ({len(all_runs)} runs across {len(projects)} projects)",
        ))

        prod_runs = [r for r in all_runs if _is_prod(r.get("environmentName", ""))]
        approved = [r for r in prod_runs if r.get("approvedBy")]
        result.text_summary += (
            f"env0: {len(all_runs)} total runs, {len(prod_runs)} to production, "
            f"{len(approved)} with recorded approvals.\n"
        )

    def _collect_environments(self, result: EvidenceResult):
        projects = self._get("/projects", {"organizationId": self.org_id})
        if isinstance(projects, dict):
            projects = projects.get("projects", [])

        environments = []
        for project in projects:
            try:
                envs = self._get("/environments", {"projectId": project["id"]})
                if isinstance(envs, dict):
                    envs = envs.get("environments", [])
                for e in envs:
                    environments.append({
                        "id": e.get("id"),
                        "name": e.get("name"),
                        "projectName": project.get("name"),
                        "status": e.get("status"),
                        "isRemoteBackend": e.get("isRemoteBackend"),
                        "terraformVersion": e.get("terraformVersion"),
                        "blueprintName": e.get("latestDeploymentLog", {}).get("blueprintName"),
                        "latestDeployAt": e.get("latestDeploymentLog", {}).get("startedAt"),
                        "latestDeployedBy": e.get("latestDeploymentLog", {}).get("triggeredBy"),
                        "driftStatus": e.get("driftStatus"),
                        "isProd": _is_prod(e.get("name", "")),
                    })
            except Exception:
                pass

        result.files.append(EvidenceFile(
            filename="env0_environments.json",
            content=_json_bytes(environments),
            mime_type="application/json",
            description=f"env0 environment inventory ({len(environments)} environments)",
        ))

        prod_envs = [e for e in environments if e.get("isProd")]
        staging_envs = [e for e in environments if _is_staging(e.get("name", ""))]
        result.text_summary += (
            f"env0: {len(environments)} environments total, "
            f"{len(prod_envs)} production, {len(staging_envs)} staging.\n"
        )

    def _collect_teams_and_permissions(self, result: EvidenceResult):
        teams = self._get("/teams", {"organizationId": self.org_id})
        if isinstance(teams, dict):
            teams = teams.get("teams", [])

        team_details = []
        for team in teams:
            try:
                members = self._get(f"/teams/{team['id']}/members")
                if isinstance(members, dict):
                    members = members.get("users", [])
                team_details.append({
                    "teamName": team.get("name"),
                    "teamId": team.get("id"),
                    "members": [{
                        "name": m.get("name"),
                        "email": m.get("email"),
                        "role": m.get("role"),
                    } for m in members],
                })
            except Exception:
                team_details.append({"teamName": team.get("name"), "teamId": team.get("id")})

        # Also get project-level role assignments
        projects = self._get("/projects", {"organizationId": self.org_id})
        if isinstance(projects, dict):
            projects = projects.get("projects", [])

        project_roles = []
        for project in projects:
            try:
                roles = self._get(f"/projects/{project['id']}/roles")
                if isinstance(roles, dict):
                    roles = roles.get("roles", [])
                for r in roles:
                    project_roles.append({
                        "project": project.get("name"),
                        "team": r.get("teamName") or r.get("team", {}).get("name"),
                        "role": r.get("role"),
                    })
            except Exception:
                pass

        result.files.append(EvidenceFile(
            filename="env0_teams_and_members.json",
            content=_json_bytes(team_details),
            mime_type="application/json",
            description=f"env0 teams and membership ({len(team_details)} teams)",
        ))
        result.files.append(EvidenceFile(
            filename="env0_project_role_assignments.json",
            content=_json_bytes(project_roles),
            mime_type="application/json",
            description=f"env0 project-level role assignments ({len(project_roles)} assignments)",
        ))
        result.text_summary += f"env0: {len(team_details)} teams, {len(project_roles)} project role assignments.\n"

    def _collect_audit_log(self, result: EvidenceResult):
        try:
            logs = self._get("/audit-logs", {
                "organizationId": self.org_id,
                "limit": 500,
            })
            if isinstance(logs, dict):
                logs = logs.get("auditLogs", logs.get("logs", []))

            result.files.append(EvidenceFile(
                filename="env0_audit_log.json",
                content=_json_bytes(logs),
                mime_type="application/json",
                description=f"env0 audit log ({len(logs)} entries)",
            ))
        except Exception as e:
            result.text_summary += f"env0 audit log unavailable: {e}\n"

    def _collect_drift_results(self, result: EvidenceResult):
        projects = self._get("/projects", {"organizationId": self.org_id})
        if isinstance(projects, dict):
            projects = projects.get("projects", [])

        drifted = []
        for project in projects:
            try:
                envs = self._get("/environments", {"projectId": project["id"]})
                if isinstance(envs, dict):
                    envs = envs.get("environments", [])
                for e in envs:
                    if e.get("driftStatus") and e["driftStatus"] != "OK":
                        drifted.append({
                            "project": project.get("name"),
                            "environment": e.get("name"),
                            "driftStatus": e.get("driftStatus"),
                            "lastChecked": e.get("driftDetectionRequest", {}).get("lastRunAt"),
                        })
            except Exception:
                pass

        result.files.append(EvidenceFile(
            filename="env0_drift_detection.json",
            content=_json_bytes(drifted),
            mime_type="application/json",
            description=f"env0 drift detection results ({len(drifted)} environments with drift)",
        ))
        result.text_summary += f"env0: {len(drifted)} environments with detected drift.\n"

    def _collect_org_summary(self, result: EvidenceResult):
        orgs = self._get("/organizations")
        projects = self._get("/projects", {"organizationId": self.org_id})
        if isinstance(projects, dict):
            projects = projects.get("projects", [])

        summary = {
            "organization": next((o for o in orgs if o["id"] == self.org_id), {}),
            "projectCount": len(projects),
            "projects": [{"id": p["id"], "name": p["name"]} for p in projects],
        }
        result.files.append(EvidenceFile(
            filename="env0_org_summary.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description="env0 organization and project summary",
        ))


def _is_prod(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in ["prod", "production", "prd"]) and not _is_staging(name)


def _is_staging(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in ["staging", "stage", "stg", "uat", "preprod", "pre-prod"])
