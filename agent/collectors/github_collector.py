"""
GitHub evidence collector using PyGithub.
Covers: branch protections, org members, secret scanning, SAST, dependency review.
"""
import json
import os

from github import Github, GithubException

from ..models import EvidenceFile, EvidenceRequest, EvidenceResult, System


def _json_bytes(data) -> bytes:
    return json.dumps(data, indent=2, default=str).encode()


class GitHubCollector:
    def __init__(self):
        token = os.environ["GITHUB_TOKEN"]
        self.org_name = os.environ["GITHUB_ORG"]
        self.gh = Github(token)
        self.org = self.gh.get_organization(self.org_name)

    def collect(self, request: EvidenceRequest) -> EvidenceResult:
        result = EvidenceResult(request_id=request.id, system=System.GITHUB)
        hints_lower = " ".join(request.hints + [request.question]).lower()

        try:
            if any(k in hints_lower for k in ["branch protection", "main branch", "protected", "merge"]):
                self._collect_branch_protections(result)

            if any(k in hints_lower for k in ["member", "access", "permission", "team", "role", "admin"]):
                self._collect_org_members(result)

            if any(k in hints_lower for k in ["secret scanning", "secret", "credential", "leak"]):
                self._collect_secret_scanning(result)

            if any(k in hints_lower for k in ["dependency", "sbom", "vulnerable", "cve", "dependabot"]):
                self._collect_dependabot(result)

            if any(k in hints_lower for k in ["sast", "code scanning", "static analysis", "codeql", "semgrep"]):
                self._collect_code_scanning(result)

            if not result.files:
                self._collect_org_summary(result)

        except GithubException as e:
            result.error = f"GitHub API error: {e.status} {e.data}"
        except Exception as e:
            result.error = str(e)

        return result

    def _collect_branch_protections(self, result: EvidenceResult):
        repos_data = []
        for repo in self.org.get_repos(type="all"):
            if repo.archived:
                continue
            try:
                branch = repo.get_branch(repo.default_branch)
                protection = branch.get_protection() if branch.protected else None
                repos_data.append({
                    "repo": repo.full_name,
                    "default_branch": repo.default_branch,
                    "protected": branch.protected,
                    "protection": {
                        "required_reviews": protection.required_pull_request_reviews.required_approving_review_count if protection and protection.required_pull_request_reviews else None,
                        "dismiss_stale_reviews": protection.required_pull_request_reviews.dismiss_stale_reviews if protection and protection.required_pull_request_reviews else None,
                        "require_code_owner_reviews": protection.required_pull_request_reviews.require_code_owner_reviews if protection and protection.required_pull_request_reviews else None,
                        "require_status_checks": bool(protection.required_status_checks) if protection else None,
                        "enforce_admins": protection.enforce_admins.enabled if protection else None,
                    } if protection else None,
                })
            except Exception:
                repos_data.append({"repo": repo.full_name, "default_branch": repo.default_branch, "protected": False, "error": "Could not read protection"})

        result.files.append(EvidenceFile(
            filename="github_branch_protections.json",
            content=_json_bytes(repos_data),
            mime_type="application/json",
            description=f"Branch protection rules for {len(repos_data)} repos",
        ))
        unprotected = [r["repo"] for r in repos_data if not r.get("protected")]
        result.text_summary += f"GitHub: {len(repos_data)} repos, {len(unprotected)} unprotected default branches.\n"

    def _collect_org_members(self, result: EvidenceResult):
        members = []
        for m in self.org.get_members():
            membership = self.org.get_membership(m)
            members.append({
                "login": m.login,
                "name": m.name,
                "email": m.email,
                "role": membership.role,
                "state": membership.state,
                "two_factor_enabled": m.two_factor_authentication,
            })

        result.files.append(EvidenceFile(
            filename="github_org_members.json",
            content=_json_bytes(members),
            mime_type="application/json",
            description=f"GitHub org members ({len(members)} members)",
        ))

        no_2fa = [m["login"] for m in members if not m.get("two_factor_enabled")]
        result.text_summary += f"GitHub members: {len(members)}, {len(no_2fa)} without 2FA.\n"

    def _collect_secret_scanning(self, result: EvidenceResult):
        alerts_summary = []
        for repo in self.org.get_repos(type="all"):
            if repo.archived:
                continue
            try:
                alerts = list(repo.get_secret_scanning_alerts())
                if alerts:
                    alerts_summary.append({
                        "repo": repo.full_name,
                        "open_alerts": len([a for a in alerts if a.state == "open"]),
                        "resolved_alerts": len([a for a in alerts if a.state == "resolved"]),
                        "secret_types": list({a.secret_type for a in alerts}),
                    })
            except GithubException:
                pass  # Not enabled for this repo

        result.files.append(EvidenceFile(
            filename="github_secret_scanning_alerts.json",
            content=_json_bytes(alerts_summary),
            mime_type="application/json",
            description="Secret scanning alert summary by repo",
        ))

    def _collect_dependabot(self, result: EvidenceResult):
        summary = []
        for repo in self.org.get_repos(type="all"):
            if repo.archived:
                continue
            try:
                alerts = list(repo.get_dependabot_alerts())
                critical = [a for a in alerts if a.security_advisory.severity == "critical"]
                high = [a for a in alerts if a.security_advisory.severity == "high"]
                if alerts:
                    summary.append({
                        "repo": repo.full_name,
                        "total": len(alerts),
                        "critical": len(critical),
                        "high": len(high),
                    })
            except GithubException:
                pass

        result.files.append(EvidenceFile(
            filename="github_dependabot_alerts.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description="Dependabot vulnerability alert summary by repo",
        ))

    def _collect_code_scanning(self, result: EvidenceResult):
        summary = []
        for repo in self.org.get_repos(type="all"):
            if repo.archived:
                continue
            try:
                alerts = list(repo.get_code_scanning_alerts())
                if alerts:
                    summary.append({
                        "repo": repo.full_name,
                        "open_alerts": len([a for a in alerts if a.state == "open"]),
                        "tools": list({a.tool.name for a in alerts}),
                    })
            except GithubException:
                pass

        result.files.append(EvidenceFile(
            filename="github_code_scanning_alerts.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description="Code scanning (SAST) alert summary by repo",
        ))

    def _collect_org_summary(self, result: EvidenceResult):
        data = {
            "org": self.org_name,
            "total_repos": self.org.total_private_repos + self.org.public_repos,
            "private_repos": self.org.total_private_repos,
            "public_repos": self.org.public_repos,
            "members_can_create_repos": self.org.members_can_create_repositories,
            "two_factor_requirement": self.org.two_factor_requirement_enabled,
        }
        result.files.append(EvidenceFile(
            filename="github_org_summary.json",
            content=_json_bytes(data),
            mime_type="application/json",
            description="GitHub organization summary",
        ))
