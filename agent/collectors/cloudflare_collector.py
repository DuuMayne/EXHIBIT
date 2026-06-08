from __future__ import annotations
"""
Cloudflare evidence collector via REST API (client/v4).

Auth: Bearer API token.

Covers:
- Zones (status, SSL mode, always-HTTPS setting)
- WAF / firewall rules per zone (count and enabled status)
- SSL/TLS settings per zone (SSL mode, minimum TLS version)
- Cloudflare Access apps (zero-trust app count)
- DDoS / security level per zone
"""
import json
import os

import requests

from ..models import EvidenceFile, EvidenceRequest, EvidenceResult, System


def _json_bytes(data) -> bytes:
    return json.dumps(data, indent=2, default=str).encode()


class CloudflareCollector:
    BASE = "https://api.cloudflare.com/client/v4"

    def __init__(self):
        token = os.environ["CLOUDFLARE_API_TOKEN"]
        self.account_id = os.environ["CLOUDFLARE_ACCOUNT_ID"]
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def _get(self, path: str, params: dict = None) -> dict:
        r = self.session.get(f"{self.BASE}{path}", params=params)
        r.raise_for_status()
        return r.json()

    def _get_paginated(self, path: str, params: dict = None) -> list:
        """Page through a list endpoint using Cloudflare result_info pagination."""
        results = []
        page = 1
        per_page = (params or {}).get("per_page", 50)
        while True:
            p = dict(params or {})
            p.update({"page": page, "per_page": per_page})
            data = self._get(path, p)
            results.extend(data.get("result", []) or [])
            info = data.get("result_info") or {}
            total_pages = info.get("total_pages")
            if not total_pages or page >= total_pages:
                break
            page += 1
        return results

    def _zones(self) -> list:
        return self._get_paginated("/zones")

    def collect(self, request: EvidenceRequest) -> EvidenceResult:
        result = EvidenceResult(request_id=request.id, system=System.CLOUDFLARE)
        hints_lower = " ".join(request.hints + [request.question]).lower()

        try:
            if any(k in hints_lower for k in ["zone", "domain", "dns", "site", "https", "always https"]):
                self._collect_zones(result)

            if any(k in hints_lower for k in ["waf", "firewall", "rule", "web application firewall"]):
                self._collect_waf_rules(result)

            if any(k in hints_lower for k in ["ssl", "tls", "encryption in transit", "certificate", "min tls"]):
                self._collect_ssl_tls(result)

            if any(k in hints_lower for k in ["access", "zero trust", "zero-trust", "ztna", "application access"]):
                self._collect_access_policies(result)

            if any(k in hints_lower for k in ["ddos", "security level", "rate limit", "protection", "mitigation"]):
                self._collect_ddos_settings(result)

            if not result.files:
                self._collect_summary(result)

        except Exception as e:
            result.error = str(e)

        return result

    def _collect_zones(self, result: EvidenceResult):
        zones = self._zones()
        summary = []
        for z in zones:
            zone_id = z["id"]
            ssl_mode = None
            always_https = None
            try:
                ssl_mode = self._get(f"/zones/{zone_id}/settings/ssl").get("result", {}).get("value")
            except Exception:
                pass
            try:
                always_https = self._get(f"/zones/{zone_id}/settings/always_use_https").get("result", {}).get("value")
            except Exception:
                pass
            summary.append({
                "id": zone_id,
                "name": z.get("name"),
                "status": z.get("status"),
                "paused": z.get("paused"),
                "ssl_mode": ssl_mode,
                "always_use_https": always_https,
            })

        result.files.append(EvidenceFile(
            filename="cloudflare_zones.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description=f"Cloudflare zones ({len(summary)} zones)",
        ))
        active = sum(1 for z in summary if z.get("status") == "active")
        result.text_summary += f"Cloudflare: {len(summary)} zones ({active} active).\n"

    def _collect_waf_rules(self, result: EvidenceResult):
        zones = self._zones()
        per_zone = []
        for z in zones:
            zone_id = z["id"]
            try:
                rules = self._get_paginated(f"/zones/{zone_id}/firewall/rules")
            except Exception:
                rules = []
            enabled = sum(1 for r in rules if not r.get("paused"))
            per_zone.append({
                "zone": z.get("name"),
                "zone_id": zone_id,
                "rule_count": len(rules),
                "enabled_count": enabled,
                "rules": [{
                    "id": r.get("id"),
                    "description": r.get("description"),
                    "action": (r.get("action") if isinstance(r.get("action"), str) else None),
                    "paused": r.get("paused"),
                } for r in rules],
            })

        result.files.append(EvidenceFile(
            filename="cloudflare_waf_firewall_rules.json",
            content=_json_bytes(per_zone),
            mime_type="application/json",
            description=f"Cloudflare WAF/firewall rules across {len(per_zone)} zones",
        ))
        total_rules = sum(z["rule_count"] for z in per_zone)
        result.text_summary += f"Cloudflare: {total_rules} firewall rules across {len(per_zone)} zones.\n"

    def _collect_ssl_tls(self, result: EvidenceResult):
        zones = self._zones()
        per_zone = []
        for z in zones:
            zone_id = z["id"]
            ssl_mode = None
            min_tls = None
            try:
                ssl_mode = self._get(f"/zones/{zone_id}/settings/ssl").get("result", {}).get("value")
            except Exception:
                pass
            try:
                min_tls = self._get(f"/zones/{zone_id}/settings/min_tls_version").get("result", {}).get("value")
            except Exception:
                pass
            per_zone.append({
                "zone": z.get("name"),
                "zone_id": zone_id,
                "ssl_mode": ssl_mode,
                "min_tls_version": min_tls,
            })

        result.files.append(EvidenceFile(
            filename="cloudflare_ssl_tls_settings.json",
            content=_json_bytes(per_zone),
            mime_type="application/json",
            description=f"Cloudflare SSL/TLS settings across {len(per_zone)} zones",
        ))
        weak = [z["zone"] for z in per_zone if z.get("min_tls_version") in (None, "1.0", "1.1")]
        result.text_summary += (
            f"Cloudflare: SSL/TLS settings for {len(per_zone)} zones, "
            f"{len(weak)} with min TLS below 1.2.\n"
        )

    def _collect_access_policies(self, result: EvidenceResult):
        try:
            apps = self._get_paginated(f"/accounts/{self.account_id}/access/apps")
        except Exception as e:
            result.text_summary += f"Cloudflare Access unavailable: {e}\n"
            apps = []

        summary = [{
            "id": a.get("id"),
            "name": a.get("name"),
            "domain": a.get("domain"),
            "type": a.get("type"),
            "session_duration": a.get("session_duration"),
        } for a in apps]

        result.files.append(EvidenceFile(
            filename="cloudflare_access_apps.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description=f"Cloudflare Access (zero-trust) apps ({len(summary)})",
        ))
        result.text_summary += f"Cloudflare Access: {len(summary)} zero-trust applications.\n"

    def _collect_ddos_settings(self, result: EvidenceResult):
        zones = self._zones()
        per_zone = []
        for z in zones:
            zone_id = z["id"]
            level = None
            try:
                level = self._get(f"/zones/{zone_id}/settings/security_level").get("result", {}).get("value")
            except Exception:
                pass
            per_zone.append({
                "zone": z.get("name"),
                "zone_id": zone_id,
                "security_level": level,
            })

        result.files.append(EvidenceFile(
            filename="cloudflare_security_levels.json",
            content=_json_bytes(per_zone),
            mime_type="application/json",
            description=f"Cloudflare security level (DDoS) per zone ({len(per_zone)} zones)",
        ))
        result.text_summary += f"Cloudflare: security level captured for {len(per_zone)} zones.\n"

    def _collect_summary(self, result: EvidenceResult):
        zones = self._zones()
        summary = {
            "account_id": self.account_id,
            "zone_count": len(zones),
            "zones": [{"id": z["id"], "name": z.get("name"), "status": z.get("status")} for z in zones],
        }
        result.files.append(EvidenceFile(
            filename="cloudflare_summary.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description="Cloudflare account and zone summary",
        ))
        result.text_summary += f"Cloudflare: {len(zones)} zones in account.\n"
