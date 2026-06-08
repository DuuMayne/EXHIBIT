from __future__ import annotations
"""
Kandji MDM evidence collector via REST API.

Auth: Bearer API token. Base URL is tenant-specific.

Covers:
- Devices (total count, OS breakdown, enrollment + supervised status)
- Device compliance for Macs (FileVault, Gatekeeper, SIP, OS version distribution)
- Blueprints (security configuration profiles applied)
- Automated Device Enrollment integrations (MDM enrollment method)
- Library items (automated software update / patch management)
"""
import json
import os
from collections import Counter

import requests

from ..models import EvidenceFile, EvidenceRequest, EvidenceResult, System


def _json_bytes(data) -> bytes:
    return json.dumps(data, indent=2, default=str).encode()


class KandjiCollector:
    def __init__(self):
        token = os.environ["KANDJI_API_TOKEN"]
        subdomain = os.environ["KANDJI_SUBDOMAIN"]
        self.base = f"https://{subdomain}.api.kandji.io/api"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        })

    def _get(self, path: str, params: dict = None) -> dict | list:
        r = self.session.get(f"{self.base}{path}", params=params)
        r.raise_for_status()
        return r.json()

    def _get_paginated(self, path: str, params: dict = None) -> list:
        """Page through Kandji list endpoints using limit/offset."""
        results = []
        offset = 0
        limit = (params or {}).get("limit", 300)
        while True:
            p = dict(params or {})
            p.update({"limit": limit, "offset": offset})
            data = self._get(path, p)
            if isinstance(data, dict):
                batch = data.get("results", data.get("data", []))
            else:
                batch = data
            batch = batch or []
            results.extend(batch)
            if len(batch) < limit:
                break
            offset += limit
        return results

    def collect(self, request: EvidenceRequest) -> EvidenceResult:
        result = EvidenceResult(request_id=request.id, system=System.KANDJI)
        hints_lower = " ".join(request.hints + [request.question]).lower()

        try:
            if any(k in hints_lower for k in ["device", "endpoint", "laptop", "mac", "inventory", "asset", "enrollment"]):
                self._collect_devices(result)

            if any(k in hints_lower for k in ["compliance", "filevault", "encryption", "gatekeeper", "sip", "hardening", "disk encryption"]):
                self._collect_device_compliance(result)

            if any(k in hints_lower for k in ["blueprint", "configuration profile", "baseline", "security configuration", "policy"]):
                self._collect_blueprints(result)

            if any(k in hints_lower for k in ["mdm", "ade", "automated device enrollment", "dep", "enrollment method"]):
                self._collect_automated_device_enrollment(result)

            if any(k in hints_lower for k in ["patch", "update", "software update", "library", "version management"]):
                self._collect_library_items(result)

            if not result.files:
                self._collect_summary(result)

        except Exception as e:
            result.error = str(e)

        return result

    def _collect_devices(self, result: EvidenceResult):
        devices = self._get_paginated("/v1/devices")
        os_breakdown = Counter()
        enrolled = 0
        supervised = 0
        for d in devices:
            os_breakdown[d.get("platform") or d.get("os") or "unknown"] += 1
            if d.get("is_mdm") or d.get("mdm_enabled") or d.get("enrolled"):
                enrolled += 1
            if d.get("is_supervised") or d.get("supervised"):
                supervised += 1

        payload = {
            "total_devices": len(devices),
            "os_breakdown": dict(os_breakdown),
            "enrolled_count": enrolled,
            "supervised_count": supervised,
            "devices": [{
                "device_id": d.get("device_id"),
                "device_name": d.get("device_name"),
                "platform": d.get("platform"),
                "os_version": d.get("os_version"),
                "model": d.get("model"),
                "last_check_in": d.get("last_check_in"),
                "enrolled": d.get("is_mdm") or d.get("mdm_enabled") or d.get("enrolled"),
                "supervised": d.get("is_supervised") or d.get("supervised"),
            } for d in devices],
        }

        result.files.append(EvidenceFile(
            filename="kandji_devices.json",
            content=_json_bytes(payload),
            mime_type="application/json",
            description=f"Kandji managed devices ({len(devices)} devices)",
        ))
        result.text_summary += (
            f"Kandji: {len(devices)} devices, {enrolled} MDM-enrolled, {supervised} supervised.\n"
        )

    def _collect_device_compliance(self, result: EvidenceResult):
        macs = self._get_paginated("/v1/devices", {"platform": "Mac"})

        os_versions = Counter()
        filevault_on = 0
        compliance = []
        for d in macs:
            device_id = d.get("device_id")
            os_versions[d.get("os_version", "unknown")] += 1
            details = {
                "device_id": device_id,
                "device_name": d.get("device_name"),
                "os_version": d.get("os_version"),
                "filevault_enabled": None,
                "gatekeeper": None,
                "sip_enabled": None,
            }
            try:
                params = self._get(f"/v1/devices/{device_id}/details")
                sec = params.get("security_information", params) if isinstance(params, dict) else {}
                fv = sec.get("filevault", {})
                details["filevault_enabled"] = fv.get("filevault_enabled") if isinstance(fv, dict) else fv
                details["gatekeeper"] = sec.get("gatekeeper", {}).get("gatekeeper_status") if isinstance(sec.get("gatekeeper"), dict) else sec.get("gatekeeper")
                details["sip_enabled"] = sec.get("system_integrity_protection", {}).get("status") if isinstance(sec.get("system_integrity_protection"), dict) else sec.get("sip")
            except Exception:
                pass
            if details["filevault_enabled"]:
                filevault_on += 1
            compliance.append(details)

        payload = {
            "total_macs": len(macs),
            "filevault_enabled_count": filevault_on,
            "os_version_distribution": dict(os_versions),
            "devices": compliance,
        }

        result.files.append(EvidenceFile(
            filename="kandji_mac_compliance.json",
            content=_json_bytes(payload),
            mime_type="application/json",
            description=f"Kandji Mac compliance posture ({len(macs)} Macs)",
        ))
        result.text_summary += (
            f"Kandji: {len(macs)} Macs, {filevault_on} with FileVault enabled.\n"
        )

    def _collect_blueprints(self, result: EvidenceResult):
        blueprints = self._get_paginated("/v1/blueprints")
        summary = [{
            "id": b.get("id"),
            "name": b.get("name"),
            "type": b.get("type"),
            "device_count": b.get("computers_count") or b.get("device_count"),
            "enrollment_code_enabled": b.get("enrollment_code_enabled"),
        } for b in blueprints]

        result.files.append(EvidenceFile(
            filename="kandji_blueprints.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description=f"Kandji blueprints / security configuration profiles ({len(summary)})",
        ))
        result.text_summary += f"Kandji: {len(summary)} blueprints applied.\n"

    def _collect_automated_device_enrollment(self, result: EvidenceResult):
        try:
            integrations = self._get("/v1/ade/integrations")
            if isinstance(integrations, dict):
                integrations = integrations.get("results", integrations.get("data", []))
        except Exception as e:
            result.text_summary += f"Kandji ADE integrations unavailable: {e}\n"
            integrations = []

        summary = [{
            "id": i.get("id"),
            "server_name": i.get("server_name") or i.get("name"),
            "status": i.get("status"),
            "device_count": i.get("device_count"),
            "last_sync": i.get("last_device_sync") or i.get("last_sync"),
        } for i in (integrations or [])]

        result.files.append(EvidenceFile(
            filename="kandji_ade_integrations.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description=f"Kandji Automated Device Enrollment integrations ({len(summary)})",
        ))
        method = "ADE/DEP" if summary else "manual"
        result.text_summary += f"Kandji: {len(summary)} ADE integrations (enrollment method: {method}).\n"

    def _collect_library_items(self, result: EvidenceResult):
        items = self._get_paginated("/v1/library/library-items")
        patch_items = [
            i for i in items
            if any(k in str(i.get("type", "")).lower() for k in ["update", "patch", "auto app", "managed os", "installer"])
        ]
        summary = [{
            "id": i.get("id"),
            "name": i.get("name"),
            "type": i.get("type"),
            "active": i.get("active"),
        } for i in items]

        result.files.append(EvidenceFile(
            filename="kandji_library_items.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description=f"Kandji library items ({len(summary)} total, {len(patch_items)} patch/update related)",
        ))
        result.text_summary += (
            f"Kandji: {len(summary)} library items, {len(patch_items)} for software update/patch management.\n"
        )

    def _collect_summary(self, result: EvidenceResult):
        devices = self._get_paginated("/v1/devices")
        blueprints = self._get_paginated("/v1/blueprints")
        summary = {
            "device_count": len(devices),
            "blueprint_count": len(blueprints),
        }
        result.files.append(EvidenceFile(
            filename="kandji_summary.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description="Kandji tenant summary",
        ))
        result.text_summary += f"Kandji: {len(devices)} devices, {len(blueprints)} blueprints.\n"
