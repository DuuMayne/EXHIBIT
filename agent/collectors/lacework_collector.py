from __future__ import annotations
"""
Lacework evidence collector via Lacework REST API v2.

Auth: API key + secret → exchange for short-lived access token.

Env vars:
  LACEWORK_ACCOUNT    - Tenant name (e.g. "earnest" → earnest.lacework.net)
  LACEWORK_API_KEY    - Key ID from API credentials JSON
  LACEWORK_API_SECRET - Key secret from API credentials JSON

Covers:
- Compliance assessments / cloud security posture (AWS, GCP, Azure)
- Active alerts and policy violations
- Host vulnerability summary
- Container vulnerability summary
- User activity (who accessed Lacework)
"""
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from ..models import EvidenceFile, EvidenceRequest, EvidenceResult, System


def _json_bytes(data) -> bytes:
    return json.dumps(data, indent=2, default=str).encode()


class LaceworkCollector:
    BASE = "https://{account}.lacework.net/api/v2"

    def __init__(self):
        account = os.environ["LACEWORK_ACCOUNT"].strip()
        self.base = self.BASE.format(account=account)
        key_id = os.environ["LACEWORK_API_KEY"]
        key_secret = os.environ["LACEWORK_API_SECRET"]
        self._token = self._get_token(key_id, key_secret)

    def _get_token(self, key_id: str, key_secret: str) -> str:
        url = f"{self.base}/access/tokens"
        body = json.dumps({"keyId": key_id, "expiryTime": 3600}).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={
                "Content-Type": "application/json",
                "X-LW-UAKS": key_secret,
            }
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        return data["token"]

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self.base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self._token}"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())

    def _post(self, path: str, body: dict) -> dict:
        url = f"{self.base}{path}"
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())

    def _time_range(self, days: int = 90) -> dict:
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=days)
        return {
            "timeFilter": {
                "startTime": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "endTime": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        }

    def collect(self, request: EvidenceRequest) -> EvidenceResult:
        result = EvidenceResult(request_id=request.id, system=System.LACEWORK)
        hints_lower = " ".join(request.hints + [request.question]).lower()

        try:
            if any(k in hints_lower for k in ["compliance", "posture", "benchmark", "cis", "cloud security"]):
                self._collect_compliance(result)

            if any(k in hints_lower for k in ["alert", "detection", "violation", "policy", "anomal"]):
                self._collect_alerts(result)

            if any(k in hints_lower for k in ["vulnerability", "vuln", "cve", "patch", "host"]):
                self._collect_host_vulns(result)

            if any(k in hints_lower for k in ["container", "docker", "image", "k8s", "kubernetes"]):
                self._collect_container_vulns(result)

            if not result.files:
                self._collect_summary(result)

        except Exception as e:
            result.error = str(e)

        return result

    def _collect_compliance(self, result: EvidenceResult):
        # Latest compliance evaluation reports (AWS is primary for Earnest)
        try:
            data = self._get("/Configs/ComplianceEvaluations", {"primaryQueryId": "AWS_CIS_S3"})
            evals = data.get("data", [])
        except Exception:
            evals = []

        # Also try to get summary across all cloud accounts
        try:
            summary_data = self._get("/Configs/ComplianceEvaluations")
            evals = summary_data.get("data", evals)
        except Exception:
            pass

        result.files.append(EvidenceFile(
            filename="lacework_compliance_evaluations.json",
            content=_json_bytes(evals),
            mime_type="application/json",
            description=f"Lacework compliance assessments ({len(evals)} evaluations)",
        ))

        # Compute pass/fail summary
        passed = sum(1 for e in evals if e.get("status") == "COMPLIANT")
        result.text_summary += (
            f"Lacework: {len(evals)} compliance evaluations "
            f"({passed} compliant, {len(evals) - passed} non-compliant).\n"
        )

    def _collect_alerts(self, result: EvidenceResult):
        body = {**self._time_range(90), "filters": [{"expression": "severity <= 3"}]}
        try:
            data = self._post("/Alerts/search", body)
            alerts = data.get("data", [])
        except Exception as e:
            alerts = [{"error": str(e)}]

        # Summarize by severity
        sev_counts: dict[int, int] = {}
        for a in alerts:
            sev = a.get("severity", 0)
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        result.files.append(EvidenceFile(
            filename="lacework_alerts_90d.json",
            content=_json_bytes(alerts),
            mime_type="application/json",
            description=f"Lacework alerts last 90 days ({len(alerts)} alerts, severity ≤3)",
        ))
        sev_str = ", ".join(f"sev{k}={v}" for k, v in sorted(sev_counts.items()))
        result.text_summary += f"Lacework: {len(alerts)} alerts last 90 days ({sev_str}).\n"

    def _collect_host_vulns(self, result: EvidenceResult):
        body = {
            **self._time_range(30),
            "filters": [{"field": "severity", "expression": "in", "values": ["Critical", "High"]}],
            "returns": ["mid", "hostname", "cveId", "severity", "status", "fixInfo"],
        }
        try:
            data = self._post("/Vulnerabilities/Hosts/search", body)
            vulns = data.get("data", [])
        except Exception as e:
            vulns = [{"error": str(e)}]

        critical = sum(1 for v in vulns if v.get("severity") == "Critical")
        high = sum(1 for v in vulns if v.get("severity") == "High")

        result.files.append(EvidenceFile(
            filename="lacework_host_vulns_30d.json",
            content=_json_bytes(vulns),
            mime_type="application/json",
            description=f"Lacework host vulnerabilities last 30 days ({len(vulns)} critical/high)",
        ))
        result.text_summary += (
            f"Lacework: {len(vulns)} host vulns (crit/high only) — "
            f"{critical} critical, {high} high.\n"
        )

    def _collect_container_vulns(self, result: EvidenceResult):
        body = {
            **self._time_range(30),
            "filters": [{"field": "severity", "expression": "in", "values": ["Critical", "High"]}],
            "returns": ["imageId", "repository", "tag", "cveId", "severity", "status"],
        }
        try:
            data = self._post("/Vulnerabilities/Containers/search", body)
            vulns = data.get("data", [])
        except Exception as e:
            vulns = [{"error": str(e)}]

        result.files.append(EvidenceFile(
            filename="lacework_container_vulns_30d.json",
            content=_json_bytes(vulns),
            mime_type="application/json",
            description=f"Lacework container vulnerabilities last 30 days ({len(vulns)} critical/high)",
        ))
        result.text_summary += f"Lacework: {len(vulns)} container vulns (crit/high) last 30 days.\n"

    def _collect_summary(self, result: EvidenceResult):
        try:
            profile = self._get("/UserProfile")
            account_info = profile.get("data", [{}])[0] if profile.get("data") else {}
        except Exception as e:
            account_info = {"error": str(e)}

        result.files.append(EvidenceFile(
            filename="lacework_account_summary.json",
            content=_json_bytes(account_info),
            mime_type="application/json",
            description="Lacework account profile and configuration",
        ))
        result.text_summary += "Lacework: account profile collected.\n"
