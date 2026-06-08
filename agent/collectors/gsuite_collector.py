"""
Google Workspace evidence collector using Admin SDK.
Covers: users, 2SV, OAuth apps, audit logs, domain settings.
"""
import json
import os

from google.oauth2 import service_account
from googleapiclient.discovery import build

from ..models import EvidenceFile, EvidenceRequest, EvidenceResult, System

SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
]


def _json_bytes(data) -> bytes:
    return json.dumps(data, indent=2, default=str).encode()


class GSuiteCollector:
    def __init__(self):
        creds_path = os.environ["GOOGLE_CREDENTIALS_PATH"]
        delegate_email = os.environ["GOOGLE_DRIVE_OWNER_EMAIL"]

        creds = service_account.Credentials.from_service_account_file(
            creds_path,
            scopes=SCOPES,
            subject=delegate_email,  # domain-wide delegation
        )
        self.admin = build("admin", "directory_v1", credentials=creds)
        self.reports = build("admin", "reports_v1", credentials=creds)

    def collect(self, request: EvidenceRequest) -> EvidenceResult:
        result = EvidenceResult(request_id=request.id, system=System.GOOGLE_WORKSPACE)
        hints_lower = " ".join(request.hints + [request.question]).lower()

        try:
            if any(k in hints_lower for k in ["2sv", "2-step", "mfa", "authentication", "user"]):
                self._collect_users_2sv(result)

            if any(k in hints_lower for k in ["oauth", "third-party app", "connected app", "token"]):
                self._collect_oauth_tokens(result)

            if any(k in hints_lower for k in ["audit log", "login audit", "admin activity", "login"]):
                self._collect_login_audit(result)

            if any(k in hints_lower for k in ["group", "team", "distribution list"]):
                self._collect_groups(result)

            if not result.files:
                self._collect_domain_summary(result)

        except Exception as e:
            result.error = str(e)

        return result

    def _collect_users_2sv(self, result: EvidenceResult):
        users = []
        request_obj = self.admin.users().list(customer="my_customer", maxResults=500)
        while request_obj:
            response = request_obj.execute()
            for u in response.get("users", []):
                users.append({
                    "email": u.get("primaryEmail"),
                    "name": u.get("name", {}).get("fullName"),
                    "isAdmin": u.get("isAdmin"),
                    "isSuspended": u.get("suspended"),
                    "isEnrolledIn2Sv": u.get("isEnrolledIn2Sv"),
                    "isEnforcedIn2Sv": u.get("isEnforcedIn2Sv"),
                    "lastLoginTime": u.get("lastLoginTime"),
                    "creationTime": u.get("creationTime"),
                })
            request_obj = self.admin.users().list_next(request_obj, response)

        result.files.append(EvidenceFile(
            filename="gsuite_users_2sv.json",
            content=_json_bytes(users),
            mime_type="application/json",
            description=f"Google Workspace users with 2SV status ({len(users)} users)",
        ))
        no_2sv = [u["email"] for u in users if not u.get("isEnrolledIn2Sv")]
        result.text_summary += f"Google Workspace: {len(users)} users, {len(no_2sv)} without 2SV.\n"

    def _collect_oauth_tokens(self, result: EvidenceResult):
        tokens = []
        request_obj = self.admin.tokens().list(userKey="all") if hasattr(self.admin, "tokens") else None
        # tokens().list requires user-level enumeration
        users_resp = self.admin.users().list(customer="my_customer", maxResults=200).execute()
        for u in users_resp.get("users", []):
            try:
                resp = self.admin.tokens().list(userKey=u["primaryEmail"]).execute()
                for token in resp.get("items", []):
                    tokens.append({
                        "user": u["primaryEmail"],
                        "clientId": token.get("clientId"),
                        "displayText": token.get("displayText"),
                        "scopes": token.get("scopes", []),
                    })
            except Exception:
                pass

        result.files.append(EvidenceFile(
            filename="gsuite_oauth_tokens.json",
            content=_json_bytes(tokens),
            mime_type="application/json",
            description=f"Google Workspace third-party OAuth tokens ({len(tokens)} tokens)",
        ))

    def _collect_login_audit(self, result: EvidenceResult):
        activities = []
        request_obj = self.reports.activities().list(
            userKey="all",
            applicationName="login",
            maxResults=1000,
        )
        response = request_obj.execute()
        for item in response.get("items", []):
            activities.append({
                "time": item.get("id", {}).get("time"),
                "email": item.get("actor", {}).get("email"),
                "ipAddress": item.get("ipAddress"),
                "events": [{
                    "name": e.get("name"),
                    "parameters": {p["name"]: p.get("value") for p in e.get("parameters", [])},
                } for e in item.get("events", [])],
            })

        result.files.append(EvidenceFile(
            filename="gsuite_login_audit_recent.json",
            content=_json_bytes(activities),
            mime_type="application/json",
            description=f"Google Workspace login audit log (last {len(activities)} events)",
        ))

    def _collect_groups(self, result: EvidenceResult):
        groups = []
        request_obj = self.admin.groups().list(customer="my_customer", maxResults=200)
        while request_obj:
            response = request_obj.execute()
            for g in response.get("groups", []):
                groups.append({
                    "email": g.get("email"),
                    "name": g.get("name"),
                    "memberCount": g.get("directMembersCount"),
                    "description": g.get("description"),
                })
            request_obj = self.admin.groups().list_next(request_obj, response)

        result.files.append(EvidenceFile(
            filename="gsuite_groups.json",
            content=_json_bytes(groups),
            mime_type="application/json",
            description=f"Google Workspace groups ({len(groups)} groups)",
        ))

    def _collect_domain_summary(self, result: EvidenceResult):
        domains = self.admin.domains().list(customer="my_customer").execute()
        result.files.append(EvidenceFile(
            filename="gsuite_domains.json",
            content=_json_bytes(domains.get("domains", [])),
            mime_type="application/json",
            description="Google Workspace domain configuration",
        ))
