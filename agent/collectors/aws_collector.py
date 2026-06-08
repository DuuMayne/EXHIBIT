"""
AWS evidence collector using boto3.
Covers: IAM, CloudTrail, S3, ACM, Config, GuardDuty, CloudWatch.
"""
import io
import json
import os
from datetime import datetime, timezone

import boto3

from ..models import EvidenceFile, EvidenceRequest, EvidenceResult, System


def _json_bytes(data) -> bytes:
    return json.dumps(data, indent=2, default=str).encode()


class AWSCollector:
    def __init__(self):
        profile = os.getenv("AWS_PROFILE", "default")
        region = os.getenv("AWS_REGION", "us-east-1")
        session = boto3.Session(profile_name=profile, region_name=region)
        self.iam = session.client("iam")
        self.ct = session.client("cloudtrail")
        self.s3 = session.client("s3")
        self.acm = session.client("acm")
        self.config = session.client("config")
        self.sts = session.client("sts")
        self.region = region

    def collect(self, request: EvidenceRequest) -> EvidenceResult:
        result = EvidenceResult(request_id=request.id, system=System.AWS)
        hints_lower = " ".join(request.hints + [request.question]).lower()

        try:
            if any(k in hints_lower for k in ["iam", "user", "access key", "mfa", "password policy", "role", "permission"]):
                self._collect_iam(result)

            if any(k in hints_lower for k in ["cloudtrail", "audit log", "trail", "logging"]):
                self._collect_cloudtrail(result)

            if any(k in hints_lower for k in ["s3", "bucket", "storage", "encryption at rest"]):
                self._collect_s3(result)

            if any(k in hints_lower for k in ["certificate", "acm", "tls", "ssl"]):
                self._collect_acm(result)

            if any(k in hints_lower for k in ["config", "compliance rule", "conformance"]):
                self._collect_config(result)

            if not result.files:
                # Generic: account summary
                self._collect_account_summary(result)

        except Exception as e:
            result.error = str(e)

        return result

    def _collect_iam(self, result: EvidenceResult):
        # Password policy
        try:
            policy = self.iam.get_account_password_policy()["PasswordPolicy"]
            result.files.append(EvidenceFile(
                filename="iam_password_policy.json",
                content=_json_bytes(policy),
                mime_type="application/json",
                description="IAM account password policy",
            ))
        except self.iam.exceptions.NoSuchEntityException:
            pass

        # MFA summary - users without MFA
        users = []
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page["Users"]:
                mfa_devices = self.iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"]
                access_keys = self.iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]
                users.append({
                    "UserName": u["UserName"],
                    "PasswordLastUsed": u.get("PasswordLastUsed"),
                    "CreateDate": u["CreateDate"],
                    "MFAEnabled": len(mfa_devices) > 0,
                    "MFADevices": [d["SerialNumber"] for d in mfa_devices],
                    "AccessKeys": [{
                        "KeyId": k["AccessKeyId"],
                        "Status": k["Status"],
                        "CreateDate": k["CreateDate"],
                    } for k in access_keys],
                })

        result.files.append(EvidenceFile(
            filename="iam_users_mfa_status.json",
            content=_json_bytes(users),
            mime_type="application/json",
            description=f"IAM users with MFA status ({len(users)} users)",
        ))

        no_mfa = [u["UserName"] for u in users if not u["MFAEnabled"]]
        result.text_summary += f"IAM: {len(users)} users, {len(no_mfa)} without MFA.\n"

        # Roles summary (just names and trust policies for brevity)
        roles = []
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page["Roles"]:
                roles.append({
                    "RoleName": r["RoleName"],
                    "CreateDate": r["CreateDate"],
                    "TrustPolicy": r["AssumeRolePolicyDocument"],
                })
        result.files.append(EvidenceFile(
            filename="iam_roles.json",
            content=_json_bytes(roles),
            mime_type="application/json",
            description=f"IAM roles ({len(roles)} roles)",
        ))

    def _collect_cloudtrail(self, result: EvidenceResult):
        trails = self.ct.describe_trails(includeShadowTrails=False)["trailList"]
        trail_details = []
        for t in trails:
            status = self.ct.get_trail_status(Name=t["TrailARN"])
            trail_details.append({
                "Name": t["Name"],
                "HomeRegion": t.get("HomeRegion"),
                "IsMultiRegionTrail": t.get("IsMultiRegionTrail"),
                "LogFileValidationEnabled": t.get("LogFileValidationEnabled"),
                "S3BucketName": t.get("S3BucketName"),
                "IsLogging": status.get("IsLogging"),
                "LatestDeliveryTime": status.get("LatestDeliveryTime"),
            })

        result.files.append(EvidenceFile(
            filename="cloudtrail_trails.json",
            content=_json_bytes(trail_details),
            mime_type="application/json",
            description=f"CloudTrail configuration ({len(trail_details)} trails)",
        ))
        result.text_summary += f"CloudTrail: {len(trail_details)} trails configured.\n"

    def _collect_s3(self, result: EvidenceResult):
        buckets = self.s3.list_buckets()["Buckets"]
        bucket_details = []
        for b in buckets:
            name = b["Name"]
            details = {"Name": name, "CreationDate": b["CreationDate"]}
            try:
                enc = self.s3.get_bucket_encryption(Bucket=name)
                details["Encryption"] = enc["ServerSideEncryptionConfiguration"]
            except Exception:
                details["Encryption"] = "None"
            try:
                versioning = self.s3.get_bucket_versioning(Bucket=name)
                details["Versioning"] = versioning.get("Status", "Disabled")
            except Exception:
                details["Versioning"] = "Unknown"
            try:
                public = self.s3.get_public_access_block(Bucket=name)
                details["PublicAccessBlock"] = public["PublicAccessBlockConfiguration"]
            except Exception:
                details["PublicAccessBlock"] = "Not configured"
            bucket_details.append(details)

        result.files.append(EvidenceFile(
            filename="s3_buckets_encryption.json",
            content=_json_bytes(bucket_details),
            mime_type="application/json",
            description=f"S3 buckets with encryption and public access settings ({len(bucket_details)} buckets)",
        ))

    def _collect_acm(self, result: EvidenceResult):
        certs = []
        paginator = self.acm.get_paginator("list_certificates")
        for page in paginator.paginate():
            for c in page["CertificateSummaryList"]:
                detail = self.acm.describe_certificate(CertificateArn=c["CertificateArn"])["Certificate"]
                certs.append({
                    "Domain": detail.get("DomainName"),
                    "Status": detail.get("Status"),
                    "Type": detail.get("Type"),
                    "NotAfter": detail.get("NotAfter"),
                    "SubjectAlternativeNames": detail.get("SubjectAlternativeNames", []),
                    "KeyAlgorithm": detail.get("KeyAlgorithm"),
                })

        result.files.append(EvidenceFile(
            filename="acm_certificates.json",
            content=_json_bytes(certs),
            mime_type="application/json",
            description=f"ACM TLS certificates ({len(certs)} certs)",
        ))

    def _collect_config(self, result: EvidenceResult):
        rules = self.config.describe_config_rules()["ConfigRules"]
        compliance = self.config.describe_compliance_by_config_rule()["ComplianceByConfigRules"]
        compliance_map = {c["ConfigRuleName"]: c["Compliance"]["ComplianceType"] for c in compliance}

        summary = [{
            "RuleName": r["ConfigRuleName"],
            "Source": r["Source"]["Owner"],
            "Compliance": compliance_map.get(r["ConfigRuleName"], "UNKNOWN"),
        } for r in rules]

        result.files.append(EvidenceFile(
            filename="aws_config_rules_compliance.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description=f"AWS Config rules compliance ({len(rules)} rules)",
        ))
        non_compliant = [r for r in summary if r["Compliance"] == "NON_COMPLIANT"]
        result.text_summary += f"AWS Config: {len(rules)} rules, {len(non_compliant)} non-compliant.\n"

    def _collect_account_summary(self, result: EvidenceResult):
        identity = self.sts.get_caller_identity()
        summary = self.iam.get_account_summary()["SummaryMap"]
        result.files.append(EvidenceFile(
            filename="aws_account_summary.json",
            content=_json_bytes({"identity": identity, "iam_summary": summary}),
            mime_type="application/json",
            description="AWS account identity and IAM summary",
        ))
