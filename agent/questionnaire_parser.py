"""
Parse a CSV/Excel questionnaire into EvidenceRequest objects.
Uses a configurable LLM backend (or heuristics) to classify items and map to systems.
Framework mappings loaded from YAML files in frameworks/mappings/.
"""
from __future__ import annotations
import json
import os
import re
from pathlib import Path

import pandas as pd

from .models import EvidenceRequest, System
from .llm import get_classifier
from .framework_loader import get_framework_registry

SYSTEM_KEYWORDS = {
    System.AWS: [
        "aws", "iam", "s3", "cloudtrail", "cloudwatch", "config", "kms",
        "acm", "certificate", "ec2", "vpc", "security group", "guardduty",
        "macie", "inspector", "waf", "lambda", "rds", "encryption at rest",
        "encryption in transit", "mfa for root", "access key rotation",
        "cloud infrastructure", "cloud hosting", "backup", "disaster recovery",
        "code changes", "database", "read-only access", "db access",
    ],
    System.ENV0: [
        "env0", "infrastructure as code", "iac", "terraform", "tofu", "opentofu",
        "infrastructure change", "deploy", "deployment", "environment",
        "staging environment", "production environment", "database change",
        "rds change", "snowflake change", "drift", "configuration drift",
        "who can deploy", "deploy to production", "build to production",
    ],
    System.GITHUB: [
        "github", "repository", "branch protection", "code review", "pr",
        "pull request", "sast", "secret scanning", "dependency", "sbom",
        "source code", "version control", "commit signing", "sdlc",
        "secure development", "application security", "code scanning",
        "code changes",
    ],
    System.OKTA: [
        "okta", "sso", "saml", "mfa", "multi-factor", "authentication policy",
        "password policy", "identity provider", "idp", "session timeout",
        "user provisioning", "deprovisioning", "scim", "privileged access",
        "access removal", "remote access", "least privilege", "access review",
        "terminated employee", "offboarding",
    ],
    System.GOOGLE_WORKSPACE: [
        "google workspace", "gsuite", "gmail", "drive", "admin console",
        "2sv", "2-step verification", "oauth apps", "data loss prevention",
        "dlp", "login audit", "device management",
    ],
    System.JIRA: [
        "jira", "ticket", "vulnerability management", "patch", "remediation",
        "sla", "incident", "change management", "risk register",
        "penetration test", "pentest", "vuln", "cve", "findings",
        "change request", "change ticket", "tabletop", "post-incident",
        "root cause", "population of", "access modification",
        "access changes", "restoration test", "scheduled jobs", "job scheduling",
        "transfer sample", "sample evidence",
    ],
    System.CONFLUENCE: [
        "confluence", "policy", "procedure", "runbook", "documentation",
        "handbook", "wiki", "infosec policy", "policy and procedures",
        "job scheduling process", "inactivity", "disabling of accounts",
        "acceptable use", "information classification", "supplier", "vendor",
        "business continuity", "disaster recovery plan", "incident response plan",
        "retention", "legal", "regulatory", "training",
    ],
    System.CROWDSTRIKE: [
        "crowdstrike", "edr", "endpoint detection", "endpoint protection",
        "antimalware", "anti-malware", "malware protection", "malware",
        "endpoint coverage", "prevention policy", "detection", "falcon",
        "vulnerability spotlight", "host group", "sensor",
        "siem", "log management", "centralized log", "security event",
        "threat detection", "security monitoring", "security alert",
        "incident detection", "threat intelligence", "xdr",
    ],
    System.CLOUDFLARE: [
        "cloudflare", "cdn", "waf", "web application firewall", "ddos",
        "edge", "tls", "ssl", "zone", "firewall rule", "zero trust",
        "web filtering", "gateway", "network security", "network connection",
        "unauthorized network", "cloudflare access",
    ],
    System.SNOWFLAKE: [
        "snowflake", "data warehouse", "warehouse", "snowflake user",
        "snowflake role", "snowflake grant", "snowflake audit", "snowflake login",
        "snowflake password policy", "snowflake network policy",
    ],
    System.KANDJI: [
        "kandji", "mdm", "mobile device management", "device management",
        "endpoint management", "macos", "workstation", "os patching",
        "filevault", "full disk encryption", "gatekeeper", "blueprint",
        "automated device enrollment", "ade", "device compliance",
        "screen lock", "patch management",
    ],
    System.SEMGREP: [
        "semgrep", "sast", "static analysis", "secure coding", "code scanning",
        "application security", "sdlc security", "security testing",
        "security gate", "pipeline security", "code vulnerability",
    ],
    System.LACEWORK: [
        "lacework", "cloud security posture", "cspm", "cloud posture",
        "cloud compliance assessment", "cloud misconfiguration", "cloud benchmark",
        "cis benchmark", "cloud security monitoring", "cloud threat detection",
        "container vulnerability", "host vulnerability", "cloud alert",
    ],
    System.BROWSER: [
        "mmax", "school success disbursement", "cashi", "certification approval",
        "school hub", "spoke", "nest",
        "1password", "argocd", "gitops", "new relic", "uptime", "apm",
        "zendesk", "ticketing system", "bug bounty", "hackerone",
        "pritunl", "vpn access log", "retool",
        "staging environment", "test environment",
        "unauthorized network connection", "network alert",
    ],
}


def load_questionnaire(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    if path.suffix in (".xlsx", ".xls"):
        df = pd.read_excel(path)
    elif path.suffix == ".csv":
        df = pd.read_csv(path)
    else:
        raise ValueError(f"Unsupported format: {path.suffix}")

    # Normalize column names
    df.columns = [c.strip().lower() for c in df.columns]

    # Find the question/description column — exact match first, then substring
    q_col = (
        "question" if "question" in df.columns
        else next(
            (c for c in df.columns if any(k == c for k in ["request", "description", "item", "text"])),
            next(
                (c for c in df.columns if any(k in c for k in ["question", "request", "description"])),
                df.columns[-1],
            ),
        )
    )
    id_col = next(
        (c for c in df.columns if c == "id"),
        next(
            (c for c in df.columns if any(k in c for k in ["no", "num", "#", "ref"])),
            None,
        ),
    )

    result = pd.DataFrame()
    result["question"] = df[q_col].dropna().astype(str)
    if id_col:
        result["id"] = df[id_col].astype(str)
    else:
        result["id"] = [str(i + 1) for i in range(len(result))]
    return result


def _heuristic_systems(question: str) -> list[System]:
    q = question.lower()
    matched = []
    for system, keywords in SYSTEM_KEYWORDS.items():
        if any(kw in q for kw in keywords):
            matched.append(system)
    return matched or [System.MANUAL]


def classify_with_llm(rows: list[dict]) -> list[dict]:
    """Classify using the configured LLM backend."""
    classifier = get_classifier()
    print(f"  [parser] Using classifier: {classifier.name}")
    return classifier.classify(rows)


def parse_questionnaire(path: str | Path, use_claude: bool = True) -> list[EvidenceRequest]:
    df = load_questionnaire(path)
    rows = df.to_dict("records")

    # Detect framework from item IDs using the registry
    registry = get_framework_registry()
    item_ids = [str(r.get("id", "")) for r in rows[:10]]
    framework = registry.detect(item_ids)
    if framework:
        mapping = registry.get(framework)
        print(f"  [parser] Detected framework: {mapping.name} — using YAML mapping")

    # Pull category column if present (framework CSVs include it)
    has_category = "category" in df.columns

    if use_claude:
        try:
            classifications = classify_with_llm(rows)
            cls_map = {str(c["id"]): c for c in classifications}
        except Exception as e:
            print(f"[warn] LLM classification failed ({e}), falling back to heuristics")
            cls_map = {}
    else:
        cls_map = {}

    requests = []
    for row in rows:
        item_id = str(row["id"])
        question = row["question"]
        cls = cls_map.get(item_id, {})

        # System resolution priority: LLM → framework YAML lookup → keyword heuristics
        raw_systems = cls.get("systems", [])
        systems = [s for s in (System(v) for v in raw_systems if v in System._value2member_map_) if s]
        if not systems and framework:
            systems = registry.lookup(framework, item_id)
        if not systems:
            systems = _heuristic_systems(question)

        # Category: from CSV column > LLM > framework YAML > fallback
        if has_category and row.get("category"):
            category = str(row["category"])
        elif cls.get("category"):
            category = cls["category"]
        elif framework:
            category = registry.category(framework, item_id) or "General"
        else:
            category = "General"

        requests.append(EvidenceRequest(
            id=item_id,
            question=question,
            category=category,
            systems=systems,
            hints=cls.get("hints", []),
        ))

    return requests
