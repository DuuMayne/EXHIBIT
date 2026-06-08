# Compliance Evidence Agent

Automates compliance evidence collection from AWS, GitHub, Okta, Google Workspace, and Jira/Confluence. Organizes output into a Google Drive folder tree mapped to the questionnaire structure, with AI-generated explainer docs per item.

## Setup

### 1. Install dependencies

```bash
cd ~/Projects/compliance-agent
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

### 2. Configure credentials

```bash
cp .env.example .env
# Edit .env with your values
```

**Required:**
- `ANTHROPIC_API_KEY` — for questionnaire classification and explainer generation
- `GOOGLE_CREDENTIALS_PATH` — service account JSON (see below)
- `GOOGLE_DRIVE_OWNER_EMAIL` — your email; Drive folders will be shared with you

**Per-system (add the ones you use):**
- `GITHUB_TOKEN` + `GITHUB_ORG`
- `AWS_PROFILE` + `AWS_REGION`
- `OKTA_DOMAIN` + `OKTA_API_TOKEN`
- `ATLASSIAN_DOMAIN` + `ATLASSIAN_EMAIL` + `ATLASSIAN_API_TOKEN`
- `CHROME_USER_DATA_DIR` + `CHROME_PROFILE` (for browser-based evidence)

### 3. Google Drive service account setup

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a project (or use existing)
3. Enable APIs: **Google Drive API**, **Admin SDK API**
4. Create a service account: IAM & Admin → Service Accounts → Create
5. Download the JSON key → save path to `GOOGLE_CREDENTIALS_PATH`
6. **Share your Drive folder** with the service account email (or use domain-wide delegation for Admin SDK access)

For Google Workspace Admin SDK (user 2SV status, audit logs):
- Enable domain-wide delegation on the service account
- In Google Admin: Security → API Controls → Domain-wide delegation → Add client ID with scopes:
  - `https://www.googleapis.com/auth/admin.directory.user.readonly`
  - `https://www.googleapis.com/auth/admin.reports.audit.readonly`
  - `https://www.googleapis.com/auth/admin.directory.group.readonly`

### 4. Okta API token

Admin Console → Security → API → Tokens → Create Token (requires Read-Only Admin or Super Admin)

### 5. Atlassian API token

[Account Settings](https://id.atlassian.com/manage-profile/security/api-tokens) → Create API token

## Usage

### Via Claude skill (recommended)

```
/compliance-evidence sample_questionnaire.csv "Acme SOC2 Q2 2026"
```

### Direct CLI

```bash
source .venv/bin/activate
python -m agent.main sample_questionnaire.csv "Acme SOC2 Q2 2026"
```

### Output

The agent prints progress as it runs and returns a Google Drive link at the end. The folder structure looks like:

```
Acme SOC2 Q2 2026/
  00_Index/
    master_summary.md       ← review this first
    evidence_index.json
  01_Access_Control/
    Q1_1_IAM_Users.../
      00_explainer.md       ← tells auditor what was collected and why
      iam_users_mfa_status.json
      iam_password_policy.json
    Q1_2_Password_Policy.../
      ...
  02_Encryption/
    ...
```

## Adding a new system

1. Create `agent/collectors/my_system_collector.py` with a class `MySystemCollector` that has a `collect(request) -> EvidenceResult` method
2. Add `System.MY_SYSTEM = "my_system"` to `agent/models.py`
3. Add keywords to `SYSTEM_KEYWORDS` in `questionnaire_parser.py`
4. Add the collector to `COLLECTOR_MAP` in `agent/main.py`

## Browser-based evidence (Playwright)

For UI-only dashboards, the agent launches Chrome reusing your existing profile sessions. If it hits a login wall it pauses and waits for you to authenticate manually.

Make sure Chrome is closed before running browser-based collections — Playwright needs exclusive access to the profile directory.
