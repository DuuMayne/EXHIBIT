"""
Jira + Confluence evidence collector via Atlassian REST API.
Covers: project list, issue counts, audit log, Confluence policies.
"""
import json
import os
from base64 import b64encode

import requests

from ..models import EvidenceFile, EvidenceRequest, EvidenceResult, System


def _json_bytes(data) -> bytes:
    return json.dumps(data, indent=2, default=str).encode()


class JiraCollector:
    def __init__(self):
        domain = os.environ["ATLASSIAN_DOMAIN"].rstrip("/")
        email = os.environ["ATLASSIAN_EMAIL"]
        token = os.environ["ATLASSIAN_API_TOKEN"]
        creds = b64encode(f"{email}:{token}".encode()).decode()
        self.base_jira = f"https://{domain}/rest/api/3"
        self.base_conf = f"https://{domain}/wiki/rest/api"
        self.headers = {
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
        }

    def _get(self, url: str, params: dict = None) -> dict | list:
        r = requests.get(url, headers=self.headers, params=params)
        r.raise_for_status()
        return r.json()

    def collect(self, request: EvidenceRequest) -> EvidenceResult:
        system = System.JIRA if request.system == System.JIRA else System.CONFLUENCE
        result = EvidenceResult(request_id=request.id, system=system)
        hints_lower = " ".join(request.hints + [request.question]).lower()

        try:
            if any(k in hints_lower for k in ["vulnerability", "vuln", "patch", "remediation", "cve", "risk"]):
                self._collect_vulnerability_issues(result)

            if any(k in hints_lower for k in ["incident", "incident response", "postmortem"]):
                self._collect_incident_issues(result)

            if any(k in hints_lower for k in ["policy", "procedure", "documentation", "runbook", "handbook"]):
                self._collect_confluence_policies(result)

            if any(k in hints_lower for k in ["change", "change management", "change request"]):
                self._collect_change_management(result)

            if any(k in hints_lower for k in ["user", "access", "permission", "jira user"]):
                self._collect_jira_users(result)

            if not result.files:
                self._collect_projects_summary(result)

        except Exception as e:
            result.error = str(e)

        return result

    def _collect_vulnerability_issues(self, result: EvidenceResult):
        jql = 'labels = "security" OR labels = "vulnerability" OR labels = "cve" ORDER BY created DESC'
        data = self._get(f"{self.base_jira}/search", {
            "jql": jql,
            "maxResults": 100,
            "fields": "summary,status,priority,assignee,created,resolutiondate,labels",
        })
        issues = [{
            "key": i["key"],
            "summary": i["fields"]["summary"],
            "status": i["fields"]["status"]["name"],
            "priority": i["fields"]["priority"]["name"] if i["fields"].get("priority") else None,
            "assignee": i["fields"]["assignee"]["displayName"] if i["fields"].get("assignee") else None,
            "created": i["fields"]["created"],
            "resolved": i["fields"].get("resolutiondate"),
        } for i in data.get("issues", [])]

        result.files.append(EvidenceFile(
            filename="jira_vulnerability_issues.json",
            content=_json_bytes(issues),
            mime_type="application/json",
            description=f"Jira security/vulnerability issues ({len(issues)} issues)",
        ))
        open_issues = [i for i in issues if i["status"] not in ("Done", "Resolved", "Closed")]
        result.text_summary += f"Jira: {len(open_issues)} open vulnerability issues.\n"

    def _collect_incident_issues(self, result: EvidenceResult):
        jql = 'labels = "incident" OR issueType = "Incident" ORDER BY created DESC'
        data = self._get(f"{self.base_jira}/search", {
            "jql": jql,
            "maxResults": 100,
            "fields": "summary,status,priority,assignee,created,resolutiondate",
        })
        issues = [{
            "key": i["key"],
            "summary": i["fields"]["summary"],
            "status": i["fields"]["status"]["name"],
            "priority": i["fields"]["priority"]["name"] if i["fields"].get("priority") else None,
            "created": i["fields"]["created"],
            "resolved": i["fields"].get("resolutiondate"),
        } for i in data.get("issues", [])]

        result.files.append(EvidenceFile(
            filename="jira_incident_issues.json",
            content=_json_bytes(issues),
            mime_type="application/json",
            description=f"Jira incident issues ({len(issues)} issues)",
        ))

    def _collect_confluence_policies(self, result: EvidenceResult):
        # Search for pages tagged with policy-related labels
        data = self._get(f"{self.base_conf}/search", {
            "cql": 'label = "policy" OR label = "security-policy" OR title ~ "Policy" ORDER BY lastmodified DESC',
            "limit": 50,
            "expand": "version,space",
        })
        pages = [{
            "id": p["id"],
            "title": p["title"],
            "space": p.get("space", {}).get("key"),
            "url": p.get("_links", {}).get("webui"),
            "lastModified": p.get("version", {}).get("when"),
            "version": p.get("version", {}).get("number"),
        } for p in data.get("results", [])]

        result.files.append(EvidenceFile(
            filename="confluence_policy_pages.json",
            content=_json_bytes(pages),
            mime_type="application/json",
            description=f"Confluence policy documentation ({len(pages)} pages)",
        ))
        result.text_summary += f"Confluence: {len(pages)} policy pages found.\n"

    def _collect_change_management(self, result: EvidenceResult):
        jql = 'labels = "change-request" OR issueType = "Change" ORDER BY created DESC'
        data = self._get(f"{self.base_jira}/search", {
            "jql": jql,
            "maxResults": 50,
            "fields": "summary,status,assignee,created,resolutiondate",
        })
        issues = [{
            "key": i["key"],
            "summary": i["fields"]["summary"],
            "status": i["fields"]["status"]["name"],
            "created": i["fields"]["created"],
        } for i in data.get("issues", [])]

        result.files.append(EvidenceFile(
            filename="jira_change_management.json",
            content=_json_bytes(issues),
            mime_type="application/json",
            description=f"Jira change management records ({len(issues)} items)",
        ))

    def _collect_jira_users(self, result: EvidenceResult):
        data = self._get(f"{self.base_jira}/users/search", {"maxResults": 200})
        users = [{
            "accountId": u.get("accountId"),
            "displayName": u.get("displayName"),
            "emailAddress": u.get("emailAddress"),
            "active": u.get("active"),
            "accountType": u.get("accountType"),
        } for u in data]

        result.files.append(EvidenceFile(
            filename="jira_users.json",
            content=_json_bytes(users),
            mime_type="application/json",
            description=f"Jira users ({len(users)} accounts)",
        ))

    def _collect_projects_summary(self, result: EvidenceResult):
        projects = self._get(f"{self.base_jira}/project/search", {"maxResults": 100})
        data = [{
            "key": p["key"],
            "name": p["name"],
            "type": p.get("projectTypeKey"),
            "lead": p.get("lead", {}).get("displayName"),
        } for p in projects.get("values", [])]

        result.files.append(EvidenceFile(
            filename="jira_projects.json",
            content=_json_bytes(data),
            mime_type="application/json",
            description=f"Jira projects ({len(data)} projects)",
        ))
