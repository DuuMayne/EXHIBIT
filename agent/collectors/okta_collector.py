from __future__ import annotations
"""
Okta evidence collector via REST API.
Covers: MFA policies, password policies, users, groups, apps.
"""
import json
import os

import requests

from ..models import EvidenceFile, EvidenceRequest, EvidenceResult, System


def _json_bytes(data) -> bytes:
    return json.dumps(data, indent=2, default=str).encode()


class OktaCollector:
    def __init__(self):
        self.domain = os.environ["OKTA_DOMAIN"].rstrip("/")
        self.base = f"https://{self.domain}/api/v1"
        self.headers = {
            "Authorization": f"SSWS {os.environ['OKTA_API_TOKEN']}",
            "Accept": "application/json",
        }

    def _get(self, path: str, params: dict = None) -> list | dict:
        url = f"{self.base}{path}"
        results = []
        while url:
            r = requests.get(url, headers=self.headers, params=params)
            r.raise_for_status()
            data = r.json()
            if isinstance(data, list):
                results.extend(data)
            else:
                return data
            # Follow Okta pagination
            url = None
            link = r.headers.get("Link", "")
            for part in link.split(","):
                if 'rel="next"' in part:
                    url = part.split(";")[0].strip().strip("<>")
                    params = None
                    break
        return results

    def collect(self, request: EvidenceRequest) -> EvidenceResult:
        result = EvidenceResult(request_id=request.id, system=System.OKTA)
        hints_lower = " ".join(request.hints + [request.question]).lower()

        try:
            if any(k in hints_lower for k in ["mfa", "multi-factor", "authenticator", "policy"]):
                self._collect_mfa_policies(result)

            if any(k in hints_lower for k in ["password", "lockout", "complexity"]):
                self._collect_password_policies(result)

            if any(k in hints_lower for k in ["user", "active user", "account", "deprovisioning"]):
                self._collect_users(result)

            if any(k in hints_lower for k in ["group", "team", "assignment"]):
                self._collect_groups(result)

            if any(k in hints_lower for k in ["app", "application", "sso", "saml", "oauth", "scim"]):
                self._collect_apps(result)

            if any(k in hints_lower for k in ["session", "timeout", "idle"]):
                self._collect_session_policies(result)

            if not result.files:
                self._collect_org_summary(result)

        except Exception as e:
            result.error = str(e)

        return result

    def _collect_mfa_policies(self, result: EvidenceResult):
        policies = self._get("/policies", {"type": "MFA_ENROLL"})
        result.files.append(EvidenceFile(
            filename="okta_mfa_enrollment_policies.json",
            content=_json_bytes(policies),
            mime_type="application/json",
            description=f"Okta MFA enrollment policies ({len(policies)} policies)",
        ))
        result.text_summary += f"Okta: {len(policies)} MFA enrollment policies.\n"

    def _collect_password_policies(self, result: EvidenceResult):
        policies = self._get("/policies", {"type": "PASSWORD"})
        result.files.append(EvidenceFile(
            filename="okta_password_policies.json",
            content=_json_bytes(policies),
            mime_type="application/json",
            description=f"Okta password policies ({len(policies)} policies)",
        ))

    def _collect_users(self, result: EvidenceResult):
        users = self._get("/users", {"limit": 200})
        summary = [{
            "id": u["id"],
            "login": u["profile"].get("login"),
            "email": u["profile"].get("email"),
            "firstName": u["profile"].get("firstName"),
            "lastName": u["profile"].get("lastName"),
            "status": u["status"],
            "created": u["created"],
            "lastLogin": u.get("lastLogin"),
            "passwordChanged": u.get("passwordChanged"),
        } for u in users]

        result.files.append(EvidenceFile(
            filename="okta_users.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description=f"Okta users ({len(summary)} users)",
        ))
        active = [u for u in summary if u["status"] == "ACTIVE"]
        result.text_summary += f"Okta: {len(active)} active users of {len(summary)} total.\n"

    def _collect_groups(self, result: EvidenceResult):
        groups = self._get("/groups")
        summary = [{
            "id": g["id"],
            "name": g["profile"].get("name"),
            "description": g["profile"].get("description"),
            "type": g["type"],
            "memberCount": g.get("objectClass"),
        } for g in groups]

        result.files.append(EvidenceFile(
            filename="okta_groups.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description=f"Okta groups ({len(summary)} groups)",
        ))

    def _collect_apps(self, result: EvidenceResult):
        apps = self._get("/apps")
        summary = [{
            "id": a["id"],
            "label": a["label"],
            "status": a["status"],
            "signOnMode": a["signOnMode"],
            "created": a["created"],
        } for a in apps]

        result.files.append(EvidenceFile(
            filename="okta_applications.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description=f"Okta applications ({len(summary)} apps)",
        ))

    def _collect_session_policies(self, result: EvidenceResult):
        policies = self._get("/policies", {"type": "OKTA_SIGN_ON"})
        result.files.append(EvidenceFile(
            filename="okta_signon_policies.json",
            content=_json_bytes(policies),
            mime_type="application/json",
            description=f"Okta sign-on (session) policies ({len(policies)} policies)",
        ))

    def _collect_org_summary(self, result: EvidenceResult):
        org = self._get("/org")
        result.files.append(EvidenceFile(
            filename="okta_org_settings.json",
            content=_json_bytes(org),
            mime_type="application/json",
            description="Okta organization settings",
        ))
