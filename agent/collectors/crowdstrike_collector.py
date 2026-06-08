from __future__ import annotations
"""
CrowdStrike Falcon evidence collector via REST API.

Auth: OAuth2 client_credentials grant -> bearer token.

Covers:
- Device/sensor coverage (total devices, OS breakdown, sensor version distribution)
- Prevention policies (enabled/disabled state, platforms covered)
- Detections (open detections in last 90 days, severity distribution)
- Spotlight vulnerabilities (CVE findings on endpoints, severity, remediation status)
- Host groups (names and counts)
"""
import json
import os
from collections import Counter
from datetime import datetime, timedelta, timezone

import requests

from ..models import EvidenceFile, EvidenceRequest, EvidenceResult, System


def _json_bytes(data) -> bytes:
    return json.dumps(data, indent=2, default=str).encode()


class CrowdStrikeCollector:
    def __init__(self):
        self.client_id = os.environ["CROWDSTRIKE_CLIENT_ID"]
        self.client_secret = os.environ["CROWDSTRIKE_CLIENT_SECRET"]
        self.base = os.environ.get("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com").rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})
        self._authenticate()

    def _authenticate(self):
        r = self.session.post(
            f"{self.base}/oauth2/token",
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        r.raise_for_status()
        token = r.json()["access_token"]
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def _get(self, path: str, params: dict = None) -> dict:
        r = self.session.get(f"{self.base}{path}", params=params)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, payload: dict) -> dict:
        r = self.session.post(f"{self.base}{path}", json=payload)
        r.raise_for_status()
        return r.json()

    def _query_all_ids(self, query_path: str, params: dict = None) -> list:
        """Page through a /queries/ endpoint collecting all resource ids."""
        ids = []
        offset = 0
        limit = (params or {}).get("limit", 500)
        while True:
            p = dict(params or {})
            p.update({"limit": limit, "offset": offset})
            data = self._get(query_path, p)
            resources = data.get("resources", []) or []
            ids.extend(resources)
            pagination = data.get("meta", {}).get("pagination", {})
            total = pagination.get("total", len(ids))
            offset += len(resources)
            if not resources or offset >= total:
                break
        return ids

    def collect(self, request: EvidenceRequest) -> EvidenceResult:
        result = EvidenceResult(request_id=request.id, system=System.CROWDSTRIKE)
        hints_lower = " ".join(request.hints + [request.question]).lower()

        try:
            if any(k in hints_lower for k in ["device", "endpoint", "sensor", "coverage", "agent", "host count", "asset"]):
                self._collect_device_coverage(result)

            if any(k in hints_lower for k in ["prevention", "policy", "policies", "antivirus", "edr", "protection"]):
                self._collect_prevention_policies(result)

            if any(k in hints_lower for k in ["detection", "alert", "incident", "threat", "malware"]):
                self._collect_detections(result)

            if any(k in hints_lower for k in ["vuln", "vulnerability", "patch", "cve", "spotlight", "remediation"]):
                self._collect_spotlight_vulns(result)

            if any(k in hints_lower for k in ["host group", "group", "grouping", "tag"]):
                self._collect_host_groups(result)

            if not result.files:
                self._collect_summary(result)

        except Exception as e:
            result.error = str(e)

        return result

    def _collect_device_coverage(self, result: EvidenceResult):
        device_ids = self._query_all_ids("/devices/queries/devices/v1", {"limit": 5000})

        devices = []
        for i in range(0, len(device_ids), 100):
            chunk = device_ids[i:i + 100]
            data = self._get("/devices/entities/devices/v2", {"ids": chunk})
            devices.extend(data.get("resources", []) or [])

        os_breakdown = Counter()
        sensor_versions = Counter()
        for d in devices:
            os_breakdown[d.get("platform_name") or d.get("os_version") or "unknown"] += 1
            sensor_versions[d.get("agent_version", "unknown")] += 1

        coverage = {
            "total_devices": len(devices),
            "os_breakdown": dict(os_breakdown),
            "sensor_version_distribution": dict(sensor_versions),
            "devices": [{
                "device_id": d.get("device_id"),
                "hostname": d.get("hostname"),
                "platform_name": d.get("platform_name"),
                "os_version": d.get("os_version"),
                "agent_version": d.get("agent_version"),
                "last_seen": d.get("last_seen"),
                "status": d.get("status"),
            } for d in devices],
        }

        result.files.append(EvidenceFile(
            filename="crowdstrike_device_coverage.json",
            content=_json_bytes(coverage),
            mime_type="application/json",
            description=f"CrowdStrike device/sensor coverage ({len(devices)} devices)",
        ))
        result.text_summary += (
            f"CrowdStrike: {len(devices)} devices under sensor management across "
            f"{len(os_breakdown)} OS families.\n"
        )

    def _collect_prevention_policies(self, result: EvidenceResult):
        offset = 0
        policies = []
        while True:
            data = self._get("/policy/combined/prevention/v1", {"limit": 100, "offset": offset})
            resources = data.get("resources", []) or []
            policies.extend(resources)
            pagination = data.get("meta", {}).get("pagination", {})
            total = pagination.get("total", len(policies))
            offset += len(resources)
            if not resources or offset >= total:
                break

        summary = [{
            "id": p.get("id"),
            "name": p.get("name"),
            "enabled": p.get("enabled"),
            "platform_name": p.get("platform_name"),
            "description": p.get("description"),
            "groups": [g.get("name") for g in p.get("groups", []) or []],
        } for p in policies]

        platforms = sorted({p.get("platform_name") for p in policies if p.get("platform_name")})
        enabled_count = sum(1 for p in policies if p.get("enabled"))

        result.files.append(EvidenceFile(
            filename="crowdstrike_prevention_policies.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description=f"CrowdStrike prevention policies ({len(policies)} policies)",
        ))
        result.text_summary += (
            f"CrowdStrike: {len(policies)} prevention policies ({enabled_count} enabled) "
            f"covering platforms: {', '.join(platforms) or 'none'}.\n"
        )

    def _collect_detections(self, result: EvidenceResult):
        since = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
        fql = f"created_timestamp:>'{since}'+status:'new'"
        detection_ids = self._query_all_ids(
            "/detections/queries/detections/v1",
            {"filter": fql, "limit": 1000},
        )

        detections = []
        for i in range(0, len(detection_ids), 100):
            chunk = detection_ids[i:i + 100]
            data = self._post("/detections/entities/summaries/v1", {"ids": chunk})
            detections.extend(data.get("resources", []) or [])

        severity_dist = Counter()
        for d in detections:
            sev = (d.get("max_severity_displayname") or d.get("severity") or "unknown")
            severity_dist[str(sev).lower()] += 1

        payload = {
            "window": "last 90 days",
            "total_open_detections": len(detections),
            "severity_distribution": dict(severity_dist),
            "detections": [{
                "detection_id": d.get("detection_id"),
                "created_timestamp": d.get("created_timestamp"),
                "status": d.get("status"),
                "max_severity": d.get("max_severity_displayname"),
                "hostname": d.get("device", {}).get("hostname"),
            } for d in detections],
        }

        result.files.append(EvidenceFile(
            filename="crowdstrike_detections_90d.json",
            content=_json_bytes(payload),
            mime_type="application/json",
            description=f"CrowdStrike open detections last 90 days ({len(detections)})",
        ))
        result.text_summary += (
            f"CrowdStrike: {len(detections)} open detections in last 90 days "
            f"(critical={severity_dist.get('critical', 0)}, high={severity_dist.get('high', 0)}).\n"
        )

    def _collect_spotlight_vulns(self, result: EvidenceResult):
        vuln_ids = self._query_all_ids(
            "/spotlight/queries/vulnerabilities/v1",
            {"filter": "status:'open'", "limit": 400},
        )

        vulns = []
        for i in range(0, len(vuln_ids), 100):
            chunk = vuln_ids[i:i + 100]
            data = self._get("/spotlight/entities/vulnerabilities/v2", {"ids": chunk})
            vulns.extend(data.get("resources", []) or [])

        severity_dist = Counter()
        remediation_status = Counter()
        for v in vulns:
            cve = v.get("cve", {}) or {}
            severity_dist[str(cve.get("severity", "unknown")).lower()] += 1
            remediation_status[v.get("status", "unknown")] += 1

        payload = {
            "total_open_findings": len(vulns),
            "severity_breakdown": dict(severity_dist),
            "remediation_status": dict(remediation_status),
            "findings": [{
                "id": v.get("id"),
                "cve_id": (v.get("cve") or {}).get("id"),
                "severity": (v.get("cve") or {}).get("severity"),
                "status": v.get("status"),
                "hostname": (v.get("host_info") or {}).get("hostname"),
                "created_timestamp": v.get("created_timestamp"),
            } for v in vulns],
        }

        result.files.append(EvidenceFile(
            filename="crowdstrike_spotlight_vulnerabilities.json",
            content=_json_bytes(payload),
            mime_type="application/json",
            description=f"CrowdStrike Spotlight vulnerabilities ({len(vulns)} open findings)",
        ))
        result.text_summary += (
            f"CrowdStrike Spotlight: {len(vulns)} open vulnerability findings "
            f"(critical={severity_dist.get('critical', 0)}, high={severity_dist.get('high', 0)}).\n"
        )

    def _collect_host_groups(self, result: EvidenceResult):
        offset = 0
        groups = []
        while True:
            data = self._get("/devices/combined/host-groups/v1", {"limit": 100, "offset": offset})
            resources = data.get("resources", []) or []
            groups.extend(resources)
            pagination = data.get("meta", {}).get("pagination", {})
            total = pagination.get("total", len(groups))
            offset += len(resources)
            if not resources or offset >= total:
                break

        summary = [{
            "id": g.get("id"),
            "name": g.get("name"),
            "group_type": g.get("group_type"),
            "description": g.get("description"),
            "member_count": g.get("member_count"),
        } for g in groups]

        result.files.append(EvidenceFile(
            filename="crowdstrike_host_groups.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description=f"CrowdStrike host groups ({len(groups)} groups)",
        ))
        result.text_summary += f"CrowdStrike: {len(groups)} host groups configured.\n"

    def _collect_summary(self, result: EvidenceResult):
        device_count = len(self._query_all_ids("/devices/queries/devices/v1", {"limit": 5000}))
        group_count = len(self._query_all_ids("/devices/queries/host-groups/v1", {"limit": 500}))
        summary = {
            "base_url": self.base,
            "total_devices": device_count,
            "host_group_count": group_count,
        }
        result.files.append(EvidenceFile(
            filename="crowdstrike_summary.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description="CrowdStrike Falcon tenant summary",
        ))
        result.text_summary += f"CrowdStrike: {device_count} managed devices, {group_count} host groups.\n"
