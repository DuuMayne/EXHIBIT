from __future__ import annotations
"""
Snowflake evidence collector via snowflake-connector-python.

Auth: account + user + password, with role/warehouse context.

Covers:
- Users (last login, disabled status, password/RSA key presence, must_change_password)
- Roles and grants for privileged roles (SYSADMIN, SECURITYADMIN, ACCOUNTADMIN)
- Login history (last 90 days, success/failure)
- Query history (last 30 days, sample)
- Password policies
- Network policies (IP allowlisting)
"""
import json
import os

from ..models import EvidenceFile, EvidenceRequest, EvidenceResult, System


def _json_bytes(data) -> bytes:
    return json.dumps(data, indent=2, default=str).encode()


class SnowflakeCollector:
    PRIVILEGED_ROLES = ["SYSADMIN", "SECURITYADMIN", "ACCOUNTADMIN"]

    def __init__(self):
        try:
            import snowflake.connector as _sf
            self._sf = _sf
        except ImportError:
            raise ImportError(
                "snowflake-connector-python is required for Snowflake evidence collection. "
                "Run: pip install snowflake-connector-python"
            )
        self.account = os.environ["SNOWFLAKE_ACCOUNT"]
        self.user = os.environ["SNOWFLAKE_USER"]
        self.password = os.environ["SNOWFLAKE_PASSWORD"]
        self.warehouse = os.environ.get("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH")
        self.role = os.environ.get("SNOWFLAKE_ROLE", "SECURITYADMIN")
        self.conn = self._sf.connect(
            account=self.account,
            user=self.user,
            password=self.password,
            warehouse=self.warehouse,
            role=self.role,
        )

    def _query(self, sql: str) -> list[dict]:
        cur = self.conn.cursor()
        try:
            cur.execute(sql)
            columns = [c[0] for c in cur.description]
            return [dict(zip(columns, row)) for row in cur.fetchall()]
        finally:
            cur.close()

    def collect(self, request: EvidenceRequest) -> EvidenceResult:
        result = EvidenceResult(request_id=request.id, system=System.SNOWFLAKE)
        hints_lower = " ".join(request.hints + [request.question]).lower()

        try:
            if any(k in hints_lower for k in ["user", "account", "disabled", "last login", "mfa", "password"]):
                self._collect_users(result)

            if any(k in hints_lower for k in ["role", "grant", "privilege", "admin", "least privilege", "permission"]):
                self._collect_roles_and_grants(result)

            if any(k in hints_lower for k in ["login", "audit", "authentication", "failed login", "access log"]):
                self._collect_login_history(result)

            if any(k in hints_lower for k in ["audit", "query", "activity", "data access", "query history"]):
                self._collect_query_history(result)

            if any(k in hints_lower for k in ["password policy", "password", "complexity", "rotation"]):
                self._collect_password_policy(result)

            if any(k in hints_lower for k in ["network", "ip", "allowlist", "whitelist", "network policy", "firewall"]):
                self._collect_network_policy(result)

            if not result.files:
                self._collect_summary(result)

        except Exception as e:
            result.error = str(e)
        finally:
            try:
                self.conn.close()
            except Exception:
                pass

        return result

    def _collect_users(self, result: EvidenceResult):
        rows = self._query("SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.USERS")
        users = [{
            "name": r.get("NAME"),
            "login_name": r.get("LOGIN_NAME"),
            "disabled": r.get("DISABLED"),
            "last_success_login": r.get("LAST_SUCCESS_LOGIN"),
            "has_password": r.get("HAS_PASSWORD"),
            "has_rsa_public_key": r.get("HAS_RSA_PUBLIC_KEY"),
            "must_change_password": r.get("MUST_CHANGE_PASSWORD"),
            "default_role": r.get("DEFAULT_ROLE"),
            "created_on": r.get("CREATED_ON"),
            "deleted_on": r.get("DELETED_ON"),
        } for r in rows]

        active = [u for u in users if not u.get("deleted_on")]
        disabled = [u for u in active if u.get("disabled")]

        result.files.append(EvidenceFile(
            filename="snowflake_users.json",
            content=_json_bytes(users),
            mime_type="application/json",
            description=f"Snowflake users ({len(users)} total, {len(active)} active)",
        ))
        result.text_summary += (
            f"Snowflake: {len(active)} active users, {len(disabled)} disabled.\n"
        )

    def _collect_roles_and_grants(self, result: EvidenceResult):
        roles = self._query("SHOW ROLES")
        role_names = [r.get("name") for r in roles if r.get("name")]

        privileged_grants = {}
        for role in self.PRIVILEGED_ROLES:
            try:
                grants = self._query(f'SHOW GRANTS OF ROLE {role}')
                privileged_grants[role] = [{
                    "grantee_name": g.get("grantee_name"),
                    "granted_to": g.get("granted_to"),
                    "granted_by": g.get("granted_by"),
                } for g in grants]
            except Exception as e:
                privileged_grants[role] = {"error": str(e)}

        result.files.append(EvidenceFile(
            filename="snowflake_roles.json",
            content=_json_bytes(roles),
            mime_type="application/json",
            description=f"Snowflake roles ({len(role_names)} roles)",
        ))
        result.files.append(EvidenceFile(
            filename="snowflake_privileged_role_grants.json",
            content=_json_bytes(privileged_grants),
            mime_type="application/json",
            description="Snowflake grants of privileged roles (SYSADMIN, SECURITYADMIN, ACCOUNTADMIN)",
        ))

        acct_admins = privileged_grants.get("ACCOUNTADMIN")
        n_acct = len(acct_admins) if isinstance(acct_admins, list) else "unknown"
        result.text_summary += (
            f"Snowflake: {len(role_names)} roles; {n_acct} grantees of ACCOUNTADMIN.\n"
        )

    def _collect_login_history(self, result: EvidenceResult):
        rows = self._query(
            "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY "
            "WHERE EVENT_TIMESTAMP > DATEADD(day, -90, CURRENT_TIMESTAMP())"
        )
        success = sum(1 for r in rows if r.get("IS_SUCCESS") == "YES")
        failure = len(rows) - success

        result.files.append(EvidenceFile(
            filename="snowflake_login_history_90d.json",
            content=_json_bytes(rows),
            mime_type="application/json",
            description=f"Snowflake login history last 90 days ({len(rows)} events)",
        ))
        result.text_summary += (
            f"Snowflake: {len(rows)} login events in last 90 days "
            f"({success} success, {failure} failed).\n"
        )

    def _collect_query_history(self, result: EvidenceResult):
        rows = self._query(
            "SELECT USER_NAME, QUERY_TYPE, START_TIME, DATABASE_NAME "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY "
            "WHERE START_TIME > DATEADD(day, -30, CURRENT_TIMESTAMP()) "
            "LIMIT 1000"
        )

        result.files.append(EvidenceFile(
            filename="snowflake_query_history_30d.json",
            content=_json_bytes(rows),
            mime_type="application/json",
            description=f"Snowflake query history last 30 days (sample of {len(rows)} queries)",
        ))
        result.text_summary += f"Snowflake: {len(rows)} queries sampled from last 30 days.\n"

    def _collect_password_policy(self, result: EvidenceResult):
        try:
            policies = self._query("SHOW PASSWORD POLICIES")
        except Exception as e:
            result.text_summary += f"Snowflake password policies unavailable: {e}\n"
            policies = []

        result.files.append(EvidenceFile(
            filename="snowflake_password_policies.json",
            content=_json_bytes(policies),
            mime_type="application/json",
            description=f"Snowflake password policies ({len(policies)})",
        ))
        result.text_summary += f"Snowflake: {len(policies)} password policies configured.\n"

    def _collect_network_policy(self, result: EvidenceResult):
        try:
            policies = self._query("SHOW NETWORK POLICIES")
        except Exception as e:
            result.text_summary += f"Snowflake network policies unavailable: {e}\n"
            policies = []

        result.files.append(EvidenceFile(
            filename="snowflake_network_policies.json",
            content=_json_bytes(policies),
            mime_type="application/json",
            description=f"Snowflake network policies / IP allowlisting ({len(policies)})",
        ))
        result.text_summary += f"Snowflake: {len(policies)} network policies (IP allowlisting) configured.\n"

    def _collect_summary(self, result: EvidenceResult):
        users = self._query("SELECT COUNT(*) AS C FROM SNOWFLAKE.ACCOUNT_USAGE.USERS WHERE DELETED_ON IS NULL")
        roles = self._query("SHOW ROLES")
        summary = {
            "account": self.account,
            "role_context": self.role,
            "warehouse": self.warehouse,
            "active_user_count": users[0].get("C") if users else None,
            "role_count": len(roles),
        }
        result.files.append(EvidenceFile(
            filename="snowflake_summary.json",
            content=_json_bytes(summary),
            mime_type="application/json",
            description="Snowflake account summary",
        ))
        result.text_summary += "Snowflake: account summary collected.\n"
