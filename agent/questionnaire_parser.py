"""
Parse a CSV/Excel questionnaire into EvidenceRequest objects.
Uses Claude to classify each item and map it to systems.
"""
from __future__ import annotations
import json
import os
import re
from pathlib import Path

import anthropic
import pandas as pd

from .models import EvidenceRequest, System

# SOC 2 CC criteria → systems map (used when framework=soc2 is detected)
SOC2_CRITERIA_SYSTEMS: dict[str, list[str]] = {
    "CC1": ["confluence", "jira"],
    "CC2": ["confluence", "jira"],
    "CC3": ["confluence", "jira"],
    "CC4": ["confluence", "jira"],
    "CC5": ["confluence", "github", "env0", "jira"],
    "CC6.1": ["okta", "aws", "github"],
    "CC6.2": ["okta", "jira"],
    "CC6.3": ["okta", "aws", "jira"],
    "CC6.4": ["browser"],           # physical access — browser to facility portal or subservice letter
    "CC6.5": ["okta", "aws", "google_workspace", "github"],
    "CC6.6": ["okta", "aws"],
    "CC6.7": ["aws", "github"],
    "CC6.8": ["browser", "jira"],   # EDR console (CrowdStrike/Jamf) + ticket evidence
    "CC7.1": ["crowdstrike", "lacework", "github", "jira", "aws"],
    "CC7.2": ["crowdstrike", "lacework", "aws", "jira"],
    "CC7.3": ["jira"],
    "CC7.4": ["jira", "confluence"],
    "CC7.5": ["jira", "confluence"],
    "CC8.1": ["github", "env0", "jira"],
    "CC9.1": ["confluence", "jira"],
    "CC9.2": ["confluence", "jira"],
    "A1": ["aws", "jira", "confluence"],
    "C1": ["aws", "confluence"],
    "PI1": ["github", "jira"],
}

# ISO 27001:2022 Annex A → systems map
ISO27001_CRITERIA_SYSTEMS: dict[str, list[str]] = {
    "5.1": ["confluence"], "5.2": ["confluence"], "5.3": ["okta", "github", "confluence"],
    "5.4": ["confluence"], "5.7": ["confluence", "jira"], "5.9": ["confluence"],
    "5.10": ["confluence"], "5.12": ["confluence"], "5.14": ["confluence"],
    "5.15": ["okta", "aws", "github", "confluence"], "5.16": ["okta", "confluence"],
    "5.17": ["okta", "aws", "confluence"], "5.18": ["okta", "aws", "github"],
    "5.19": ["confluence", "jira"], "5.20": ["confluence"], "5.22": ["confluence", "jira"],
    "5.23": ["aws", "confluence"], "5.24": ["confluence", "jira"],
    "5.26": ["jira", "confluence"], "5.27": ["jira", "confluence"],
    "5.29": ["jira", "confluence"], "5.31": ["confluence"],
    "5.33": ["confluence"], "5.35": ["confluence", "jira"], "5.36": ["confluence"],
    "6.1": ["confluence"], "6.3": ["confluence"], "6.6": ["confluence"],
    "6.7": ["confluence", "okta"], "6.8": ["jira", "confluence"],
    "7.1": ["browser", "confluence"], "7.2": ["browser", "confluence"],
    "7.7": ["kandji", "confluence"], "7.14": ["kandji", "confluence"],
    "8.1": ["kandji", "crowdstrike", "aws"],
    "8.2": ["okta", "aws", "github"],
    "8.4": ["github"], "8.5": ["okta", "aws", "google_workspace", "github"],
    "8.7": ["crowdstrike", "kandji"],
    "8.8": ["crowdstrike", "github", "semgrep", "jira"],
    "8.9": ["aws", "kandji", "confluence"],
    "8.12": ["google_workspace", "confluence"],
    "8.13": ["aws", "confluence"],
    "8.15": ["crowdstrike", "aws", "okta", "github"],
    "8.16": ["lacework", "crowdstrike", "aws", "jira"],
    "8.20": ["cloudflare", "aws", "confluence"],
    "8.22": ["cloudflare", "aws"],
    "8.23": ["cloudflare", "confluence"],
    "8.24": ["aws", "cloudflare", "confluence"],
    "8.25": ["github", "semgrep", "confluence"],
    "8.28": ["github", "semgrep"],
    "8.29": ["semgrep", "jira", "confluence"],
    "8.31": ["env0", "github"],
    "8.32": ["github", "env0", "jira"],
    "8.34": ["jira", "confluence"],
}

# NIST CSF 2.0 subcategory → systems map
NIST_CSF2_SYSTEMS: dict[str, list[str]] = {
    "GV.OC": ["confluence"], "GV.RM": ["confluence", "jira"],
    "GV.RR": ["confluence"], "GV.PO": ["confluence"],
    "GV.OV": ["confluence", "jira"], "GV.SC": ["confluence", "jira"],
    "ID.AM": ["aws", "kandji", "github", "confluence"],
    "ID.RA": ["crowdstrike", "semgrep", "jira", "confluence"],
    "ID.IM": ["jira", "confluence"],
    "PR.AA": ["okta", "aws", "github"],
    "PR.AT": ["confluence"],
    "PR.DS": ["aws", "cloudflare", "snowflake", "confluence"],
    "PR.PS": ["kandji", "aws", "github", "semgrep", "confluence"],
    "PR.IR": ["cloudflare", "aws", "confluence"],
    "DE.CM": ["lacework", "crowdstrike", "cloudflare", "aws", "okta"],
    "DE.AE": ["lacework", "crowdstrike", "aws", "jira"],
    "RS.MA": ["jira", "confluence"],
    "RS.AN": ["jira", "confluence"],
    "RS.CO": ["jira", "confluence"],
    "RS.MI": ["jira", "crowdstrike"],
    "RC.RP": ["jira", "confluence"],
    "RC.CO": ["confluence"],
}

# NYDFS 500.x section → systems map
NYDFS_SECTION_SYSTEMS: dict[str, list[str]] = {
    "500.2": ["confluence"],
    "500.3": ["confluence"],
    "500.4": ["confluence"],
    "500.5": ["jira", "confluence"],
    "500.6": ["aws", "okta", "github"],
    "500.7": ["okta", "aws"],
    "500.8": ["github", "env0", "confluence"],
    "500.9": ["confluence", "jira"],
    "500.10": ["confluence"],
    "500.11": ["confluence", "jira"],
    "500.12": ["okta", "aws", "google_workspace"],
    "500.13": ["aws", "confluence"],
    "500.14": ["crowdstrike", "confluence", "okta", "aws"],
    "500.15": ["aws"],
    "500.16": ["jira", "confluence"],
    "500.17": ["confluence"],
    "500.23": ["confluence"],
}

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
        # CrowdStrike as SIEM / centralized security monitoring
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
    # Browser-required: systems without usable APIs or needing interactive session
    System.BROWSER: [
        # In-house Earnest apps (VPN + Playwright or AWS CLI)
        "mmax", "school success disbursement", "cashi", "certification approval",
        "school hub", "spoke", "nest",
        # Other systems routed to browser
        "1password", "argocd", "gitops", "new relic", "uptime", "apm",
        "zendesk", "ticketing system", "bug bounty", "hackerone",
        "pritunl", "vpn access log", "retool",
        # Network/environment
        "staging environment", "test environment",
        "unauthorized network connection", "network alert",
    ],
}

CLASSIFICATION_PROMPT = """You are a compliance evidence analyst. Given a list of audit questions or evidence requests, classify each one.

System reference:
- "aws": IAM, CloudTrail, S3, RDS, ACM, CloudWatch, Config — any AWS infrastructure or database access
- "env0": infrastructure-as-code deployments, Terraform/OpenTofu runs, environment inventory (prod/staging separation), IaC team permissions, deployment approvals, configuration drift — use for ANY infrastructure change or deploy-to-production question
- "github": application code changes (PRs, commits), branch protections, SAST/secret scanning, repo membership, staging branches — use alongside env0 for change management questions
- "okta": access reviews, user accounts, MFA, privileged access, provisioning/deprovisioning, inactivity policy
- "jira": tickets, populations/samples of changes, incidents, access modification logs, restoration evidence
- "confluence": policies, procedures, runbooks — anything asking for written documentation
- "google_workspace": Gmail, Drive, admin console, 2SV, audit logs
- "crowdstrike": EDR/antimalware coverage, prevention policies, endpoint detections, vulnerability spotlight, host groups; also serves as the SIEM — use for centralized logging, security monitoring, threat detection, and XDR questions
- "cloudflare": CDN/edge, WAF rules, TLS/SSL config, DDoS protection, Cloudflare Access/Zero Trust, web filtering
- "snowflake": data warehouse user accounts, role grants, login history, query audit, password and network policies
- "kandji": MDM device inventory, FileVault/encryption compliance, blueprints, patch management, automated enrollment
- "semgrep": SAST findings by severity/repo, projects scanned, scan policies, pipeline coverage
- "lacework": cloud security posture (CSPM), compliance assessments, cloud alerts/violations, host and container vulnerability findings; use for cloud misconfiguration or cloud benchmark questions
- "browser": MMAX (school success disbursement), CASHI (school hub interface), School Hub/Spoke, 1Password, ArgoCD, New Relic, Zendesk, HackerOne, Pritunl VPN, Retool, or any other internal app without a usable API
- "manual": items requiring human narrative response or physical evidence with no automatable source

For each item return a JSON object with:
- "id": the item ID/number from the input
- "category": the compliance category (e.g. "Access Control", "Change Management", "Logging & Monitoring", "Business Continuity", "IT Operations", "Network Security", "Vulnerability Management")
- "systems": array of systems to query from the list above — include ALL relevant systems for the question
- "hints": array of 3-5 specific artifacts to collect (e.g. "GitHub PR list filtered to 01/01/2026-present with author, approver, merge date", "Okta users report showing last login and MFA status", "Jira tickets labeled restoration-test from Q1 2026")

Return a JSON array, one object per item. Be precise in hints — they are instructions to automated collectors.

Questions to classify:
{questions}"""


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


def classify_with_claude(rows: list[dict]) -> list[dict]:
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    system_names = [s.value for s in System if s != System.MANUAL]

    questions_text = "\n".join(
        f"{r['id']}. {r['question']}" for r in rows
    )

    message = client.messages.create(
        model="claude-opus-4-8",
        max_tokens=8192,
        messages=[{
            "role": "user",
            "content": CLASSIFICATION_PROMPT.format(
                systems=", ".join(system_names),
                questions=questions_text,
            ),
        }],
    )

    raw = message.content[0].text
    # Extract JSON from response (handle markdown code fences)
    json_match = re.search(r"\[.*\]", raw, re.DOTALL)
    if not json_match:
        raise ValueError(f"Could not parse Claude classification response:\n{raw[:500]}")
    return json.loads(json_match.group())


def _detect_framework(rows: list[dict]) -> str | None:
    """Detect if this is a known framework questionnaire from ID patterns."""
    ids = [str(r.get("id", "")).upper() for r in rows[:5]]
    if any(re.match(r"CC\d|A1\.|C1\.|PI1\.", i) for i in ids):
        return "soc2"
    if any(re.match(r"500\.", i) for i in ids):
        return "nydfs"
    if any(re.match(r"^\d+\.\d+$", i) and float(i) >= 5.0 and float(i) < 9.0 for i in ids if re.match(r"^\d+\.\d+$", i)):
        return "iso27001"
    if any(re.match(r"(GV|ID|PR|DE|RS|RC)\.", i) for i in ids):
        return "nist_csf2"
    return None


def _framework_systems(item_id: str, framework: str) -> list[System]:
    """Look up systems for a known framework criteria code."""
    raw = []

    if framework == "soc2":
        for prefix in [item_id, item_id.split(".")[0], item_id[:3]]:
            if prefix in SOC2_CRITERIA_SYSTEMS:
                raw = SOC2_CRITERIA_SYSTEMS[prefix]
                break

    elif framework == "nydfs":
        section = item_id if item_id.startswith("500.") else f"500.{item_id}"
        for key in [section, re.sub(r"[a-z]$", "", section)]:
            if key in NYDFS_SECTION_SYSTEMS:
                raw = NYDFS_SECTION_SYSTEMS[key]
                break

    elif framework == "iso27001":
        # Try exact match, then major.minor without patch, then major
        parts = item_id.split(".")
        candidates = [item_id]
        if len(parts) >= 2:
            candidates.append(f"{parts[0]}.{parts[1]}")
        candidates.append(parts[0])
        for key in candidates:
            if key in ISO27001_CRITERIA_SYSTEMS:
                raw = ISO27001_CRITERIA_SYSTEMS[key]
                break

    elif framework == "nist_csf2":
        # GV.OC-1 → try "GV.OC-1", then "GV.OC", then "GV"
        candidates = [item_id]
        if "-" in item_id:
            candidates.append(item_id.rsplit("-", 1)[0])
        if "." in item_id:
            candidates.append(item_id.split(".")[0])
        for key in candidates:
            if key in NIST_CSF2_SYSTEMS:
                raw = NIST_CSF2_SYSTEMS[key]
                break

    systems = []
    for s in raw:
        try:
            systems.append(System(s))
        except ValueError:
            pass
    return systems or [System.MANUAL]


def parse_questionnaire(path: str | Path, use_claude: bool = True) -> list[EvidenceRequest]:
    df = load_questionnaire(path)
    rows = df.to_dict("records")

    # Detect known frameworks (SOC 2, NYDFS) from ID patterns
    framework = _detect_framework(rows)
    if framework:
        print(f"  [parser] Detected framework: {framework.upper()} — using pre-built system mapping")

    # Pull category column if present (framework CSVs include it)
    has_category = "category" in df.columns

    if use_claude:
        try:
            classifications = classify_with_claude(rows)
            cls_map = {str(c["id"]): c for c in classifications}
        except Exception as e:
            print(f"[warn] Claude classification failed ({e}), falling back to heuristics")
            cls_map = {}
    else:
        cls_map = {}

    requests = []
    for row in rows:
        item_id = str(row["id"])
        question = row["question"]
        cls = cls_map.get(item_id, {})

        # System resolution priority: Claude → framework lookup → keyword heuristics
        raw_systems = cls.get("systems", [])
        systems = [s for s in (System(v) for v in raw_systems if v in System._value2member_map_) if s]
        if not systems and framework:
            systems = _framework_systems(item_id, framework)
        if not systems:
            systems = _heuristic_systems(question)

        # Category: from CSV column > Claude > item ID prefix
        if has_category and row.get("category"):
            category = str(row["category"])
        else:
            category = cls.get("category") or _infer_category(item_id, framework)

        requests.append(EvidenceRequest(
            id=item_id,
            question=question,
            category=category,
            systems=systems,
            hints=cls.get("hints", []),
        ))

    return requests


def _infer_category(item_id: str, framework: str | None) -> str:
    if framework == "soc2":
        prefix = item_id.upper().split(".")[0]
        return {
            "CC1": "Control Environment", "CC2": "Communication & Information",
            "CC3": "Risk Assessment", "CC4": "Monitoring Activities",
            "CC5": "Control Activities", "CC6": "Logical Access",
            "CC7": "System Operations", "CC8": "Change Management",
            "CC9": "Risk Mitigation", "A1": "Availability",
            "C1": "Confidentiality", "PI1": "Processing Integrity",
        }.get(prefix, "General")
    if framework == "nydfs":
        return "NYDFS 23 NYCRR 500"
    if framework == "iso27001":
        major = item_id.split(".")[0]
        return {
            "5": "Organizational Controls", "6": "People Controls",
            "7": "Physical Controls", "8": "Technological Controls",
        }.get(major, "ISO 27001")
    if framework == "nist_csf2":
        fn = item_id.split(".")[0]
        return {
            "GV": "Govern", "ID": "Identify", "PR": "Protect",
            "DE": "Detect", "RS": "Respond", "RC": "Recover",
        }.get(fn, "NIST CSF 2.0")
    return "General"
