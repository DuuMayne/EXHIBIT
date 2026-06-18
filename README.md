# EXHIBIT — Evidence eXtraction, Harvesting and Intelligence-Based Investigation Tool

Automatically collects evidence for security audits and compliance questionnaires. Instead of manually logging into a dozen systems and exporting screenshots, you give EXHIBIT a list of audit questions and it queries your systems via API, organizes everything into a Google Drive folder, and writes a plain-English explanation for each item so reviewers know exactly what they're looking at.

**Systems it can query:** AWS, GitHub, env0, Okta, Google Workspace, Jira, Confluence, CrowdStrike, Cloudflare, Snowflake, Kandji, Semgrep, Lacework, and browser-based tools via Chrome automation.

**Supported audit frameworks (pre-built templates included):**
- SOC 2 Type II
- ISO 27001:2022
- NIST CSF 2.0
- NYDFS 23 NYCRR 500
- CSA CAIQ v4
- SIG Lite (Shared Assessments)
- Custom questionnaires (CSV, Excel, or plain text)

---

## Part of the PANOPTICON Suite

EXHIBIT is one piece of a three-part system for GRC engineers:

| Tool | What it does | Repo |
|------|-------------|------|
| **[CHECKS](https://github.com/DuuMayne/CHECKS)** | Shared check library — deterministic pass/fail logic + connectors | The primitive |
| **[OCULUS](https://github.com/DuuMayne/OCULUS)** | Runs checks continuously, stores results, alerts on drift | The monitor |
| **EXHIBIT** (this) | Packages evidence for auditors — maps frameworks, generates explainers | The audit response |

**How they connect:** When an auditor asks a question, EXHIBIT uses a decision engine to find the cheapest answer:

1. **Check** (free) — If CHECKS has a deterministic check for this control, use the result. No API call needed.
2. **Retrieval** (cheap) — If the answer is a known artifact with known parameters, fetch it directly.
3. **Agent** (expensive) — Only fire up LLM reasoning for genuinely ambiguous questions.

After every run, EXHIBIT generates a **coverage report** showing which questions were answered by checks vs. which fell back to collectors. Each gap is a suggested new evaluator you can add to the CHECKS library — shrinking future costs with every iteration.

Each tool works independently. You don't need all three. But together they form a feedback loop that gets cheaper over time.

---

## Table of Contents

1. [What you need before starting](#1-what-you-need-before-starting)
2. [Setup: Docker (recommended)](#2-setup-docker-recommended)
3. [Setup: Local Python (alternative)](#3-setup-local-python-alternative)
4. [Getting your API credentials](#4-getting-your-api-credentials)
5. [Running your first evidence collection](#5-running-your-first-evidence-collection)
6. [Understanding the output](#6-understanding-the-output)
7. [Using a custom questionnaire](#7-using-a-custom-questionnaire)
8. [Troubleshooting](#8-troubleshooting)
9. [For developers: extending the agent](#9-for-developers-extending-the-agent)

---

## 1. What you need before starting

**Required for any setup:**
- A computer running macOS, Windows, or Linux
- API credentials for at least one of the integrated systems (you only need to set up the systems you actually use)

**Optional but recommended:**
- An [Anthropic API key](https://console.anthropic.com) (improves question classification + generates explainer docs). Without it, EXHIBIT uses keyword-based routing and template explainers — still functional, just less nuanced.
- A Google Cloud service account with Drive API access (explained in [section 4](#google-drive-service-account)). Only needed for the `upload` stage — you can collect evidence locally without it.

**For the Docker setup (recommended):**
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running

**For the local Python setup:**
- Python 3.9 or later (`python3 --version` to check)

---

## 2. Setup: Docker (recommended)

Docker packages everything the agent needs into a self-contained container. You don't need to install Python, manage dependencies, or keep a `.env` file with your credentials in the project folder. Credentials live inside Docker Desktop.

### Step 1 — Install Docker Desktop

Download and install from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/). Once installed, open it and make sure the whale icon appears in your menu bar (macOS) or system tray (Windows) — that means Docker is running.

### Step 2 — Clone or download this project

If you have Git installed:
```bash
git clone https://github.com/DuuMayne/EXHIBIT.git
cd EXHIBIT
```

If not, download the ZIP from GitHub and unzip it. Then open a terminal and navigate to the folder:
```bash
cd ~/Downloads/EXHIBIT
```

### Step 3 — Build and start the agent container

Run this once from inside the `EXHIBIT` folder:
```bash
docker compose up -d --build
```

What this does:
- **`--build`** — builds the Docker image (installs Python packages, Playwright, etc.)
- **`-d`** — runs in the background (you can close the terminal)

This takes 3–5 minutes the first time. Subsequent starts are under 10 seconds.

To confirm it's running:
```bash
docker compose ps
```
You should see `exhibit-mcp` with status `Up`.

### Step 4 — Add your credentials in Docker Desktop

Open Docker Desktop → click **Containers** in the left sidebar → click **exhibit-mcp** → click the **Inspect** tab → scroll to **Environment Variables**.

Add each credential as a key/value pair. You only need to fill in the systems you use. See [section 4](#4-getting-your-api-credentials) for how to get each one.

The variables to set:

| Variable | What it's for |
|---|---|
| `ANTHROPIC_API_KEY` | AI question classification + explainer writing |
| `GOOGLE_CREDENTIALS_PATH` | Path to your Google service account JSON (see note below) |
| `GOOGLE_DRIVE_OWNER_EMAIL` | Your email — Drive folders will be shared with you |
| `GITHUB_TOKEN` | GitHub API access |
| `GITHUB_ORG` | Your GitHub organization name (e.g. `acme-corp`) |
| `AWS_REGION` | Usually `us-east-1` |
| `AWS_PROFILE` | Name of your AWS CLI profile (usually `default`) |
| `OKTA_DOMAIN` | Your Okta tenant (e.g. `acme-corp.okta.com`) |
| `OKTA_API_TOKEN` | Okta API token |
| `ATLASSIAN_DOMAIN` | Your Atlassian domain (e.g. `acme-corp.atlassian.net`) |
| `ATLASSIAN_EMAIL` | Your Atlassian account email |
| `ATLASSIAN_API_TOKEN` | Atlassian API token |
| `CROWDSTRIKE_CLIENT_ID` | CrowdStrike API client ID |
| `CROWDSTRIKE_CLIENT_SECRET` | CrowdStrike API client secret |
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID |
| `SNOWFLAKE_ACCOUNT` | Snowflake account identifier |
| `SNOWFLAKE_USER` | Snowflake username |
| `SNOWFLAKE_PASSWORD` | Snowflake password |
| `KANDJI_API_TOKEN` | Kandji API token |
| `KANDJI_SUBDOMAIN` | Your Kandji subdomain (e.g. `acme-corp`) |
| `SEMGREP_API_TOKEN` | Semgrep API token |
| `SEMGREP_ORG_SLUG` | Your Semgrep org slug |
| `LACEWORK_ACCOUNT` | Lacework account name (e.g. `acme-corp`) |
| `LACEWORK_API_KEY` | Lacework API key ID |
| `LACEWORK_API_SECRET` | Lacework API secret |
| `ENV0_API_KEY` | env0 API key |
| `ENV0_ORG_ID` | env0 organization ID (auto-detected if blank) |

> **Google service account JSON:** The JSON file from Google Cloud needs to be accessible inside the container. The easiest way is to mount it. In `docker-compose.yml`, uncomment this line under `volumes:` and update the path to where you saved the file:
> ```yaml
> - ~/.config/exhibit/google_sa.json:/run/secrets/google_sa.json:ro
> ```
> Then set `GOOGLE_CREDENTIALS_PATH` to `/run/secrets/google_sa.json`.

After adding credentials, restart the container to apply them:
```bash
docker compose restart
```

### Step 5 — Connect Claude Code

If you're using [Claude Code](https://claude.ai/code), the agent appears automatically as an MCP server because this project includes a `.claude.json` config file pointing to `http://localhost:8765`. Open (or restart) Claude Code from the `EXHIBIT` directory and you'll see the agent's tools available.

To verify the connection is working, ask Claude:
> "Check integration status for EXHIBIT"

It will call the `check_integration_status` tool and show you which credentials are configured.

---

## 3. Setup: Local Python (alternative)

Use this if you prefer not to use Docker or want to modify the agent code directly.

### Step 1 — Create a Python virtual environment

A virtual environment keeps this project's dependencies separate from your system Python. Run these commands from inside the `EXHIBIT` folder:

```bash
python3 -m venv .venv
```

Activate it (you'll need to do this every time you open a new terminal):
```bash
# macOS / Linux:
source .venv/bin/activate

# Windows:
.venv\Scripts\activate
```

When activated, your terminal prompt will show `(.venv)` at the start.

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
playwright install chromium
```

`playwright install chromium` downloads the version of Chrome that the agent uses for browser-based evidence collection. It's about 200MB.

### Step 3 — Create your credentials file

```bash
cp .env.example .env
```

Open `.env` in any text editor (TextEdit, Notepad, VS Code — anything works) and fill in the values for the systems you use. See [section 4](#4-getting-your-api-credentials) for how to get each credential.

The `.env` file is listed in `.gitignore` so it will never be accidentally committed to GitHub.

### Step 4 — Verify setup

```bash
python -m agent.main --check-credentials
```

This checks each configured credential without making any API calls. You'll see a list of which integrations are ready and which are still missing.

---

## 4. Getting your API credentials

### Anthropic API key

1. Go to [console.anthropic.com](https://console.anthropic.com)
2. Click **API Keys** in the left sidebar
3. Click **Create Key** → give it a name like "Compliance Agent"
4. Copy the key (starts with `sk-ant-`) — you won't be able to see it again

### Google Drive service account

The agent uses a Google service account (a special non-human account) to create and upload files to Google Drive on your behalf.

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create a new project or select an existing one
3. In the search bar, search for **"Google Drive API"** and enable it
4. Also enable **"Admin SDK API"** (needed for Google Workspace user reports)
5. Go to **IAM & Admin → Service Accounts → Create Service Account**
6. Give it a name like "exhibit-sa" and click **Done**
7. Click on the new service account → **Keys** tab → **Add Key → Create new key → JSON**
8. Save the downloaded JSON file somewhere safe (e.g. `~/.config/exhibit/google_sa.json`)
9. Set `GOOGLE_CREDENTIALS_PATH` to that file path

**For Google Workspace evidence (user accounts, 2SV status, audit logs):**
The service account needs domain-wide delegation:
1. In the service account settings, enable **Domain-wide delegation** and note the **Client ID**
2. In Google Admin Console (admin.google.com) → **Security → API Controls → Domain-wide delegation → Add new**
3. Paste the Client ID and add these scopes (comma-separated):
   ```
   https://www.googleapis.com/auth/admin.directory.user.readonly,
   https://www.googleapis.com/auth/admin.reports.audit.readonly,
   https://www.googleapis.com/auth/admin.directory.group.readonly
   ```

### GitHub

1. Go to [github.com/settings/tokens](https://github.com/settings/tokens)
2. Click **Generate new token (classic)**
3. Name it "Compliance Agent" and set expiration to 1 year
4. Select scopes: `read:org`, `repo` (read), `read:user`
5. Click **Generate token** and copy it

Set `GITHUB_ORG` to your organization name — the part after `github.com/` in your org's URL.

### Okta

1. Log into your Okta admin console (usually `yourorg-admin.okta.com`)
2. Go to **Security → API → Tokens**
3. Click **Create Token** → name it "Compliance Agent"
4. Copy the token — you won't see it again

Set `OKTA_DOMAIN` to your Okta domain (e.g. `acme-corp.okta.com` — without `https://`).

### Atlassian (Jira + Confluence)

1. Go to [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens)
2. Click **Create API token** → name it "Compliance Agent"
3. Copy the token

Set `ATLASSIAN_DOMAIN` to your Atlassian domain (e.g. `acme-corp.atlassian.net`), `ATLASSIAN_EMAIL` to your Atlassian login email.

### CrowdStrike

1. Log into the Falcon console
2. Go to **Support & Resources → API Clients & Keys**
3. Click **Create API client**
4. Name it "Compliance Agent" and enable read-only scopes:
   - Hosts: Read
   - Prevention Policies: Read
   - Detections: Read
   - Spotlight vulnerabilities: Read
   - Event streams: Read (for SIEM evidence)
5. Save the **Client ID** and **Client Secret** shown — the secret won't be shown again

### Cloudflare

1. Log into [dash.cloudflare.com](https://dash.cloudflare.com) → **My Profile → API Tokens**
2. Click **Create Token → Custom token**
3. Add these permissions:
   - Zone: Zone Settings: Read
   - Zone: Firewall Services: Read
   - Account: Access: Apps and Policies: Read
4. Under **Account Resources**, select your account
5. Click **Continue to summary → Create Token**

To find your **Account ID**: it's in the URL when you're on the Cloudflare dashboard — `dash.cloudflare.com/<account-id>/`.

### Snowflake

Use an account with the `SECURITYADMIN` role (or a custom role with read access to `SNOWFLAKE.ACCOUNT_USAGE` views).

Set `SNOWFLAKE_ACCOUNT` to your account identifier — find it in Snowflake's account URL: `<account>.snowflakecomputing.com`.

### Kandji

1. Log into your Kandji dashboard → **Settings → Access**
2. Click **Add Token** → name it "Compliance Agent" → select read permissions
3. Copy the token

Set `KANDJI_SUBDOMAIN` to your subdomain (the part before `.api.kandji.io`).

### Semgrep

1. Log into [semgrep.dev](https://semgrep.dev) → **Settings → Tokens**
2. Click **Create new token** → name it "Compliance Agent"
3. Copy the token

Set `SEMGREP_ORG_SLUG` to your organization slug (visible in your Semgrep URL).

### Lacework

1. Log into the Lacework console → **Settings → API Keys**
2. Click **+ Create New Key** → name it "Compliance Agent"
3. Download the JSON file — copy `keyId` to `LACEWORK_API_KEY` and `secret` to `LACEWORK_API_SECRET`

Set `LACEWORK_ACCOUNT` to your tenant name (the part before `.lacework.net`).

### env0

1. Log into [app.env0.com](https://app.env0.com) → **Settings → API Keys**
2. Click **Generate API Key** → name it "Compliance Agent"
3. Copy the key

The `ENV0_ORG_ID` is auto-detected from the API key if left blank.

---

## 5. Running your first evidence collection

### Option A: Using Claude Code with the Docker MCP server

With the container running and Claude Code open, just describe what you want:

> "Run a dry run of the SOC 2 audit questionnaire as 'External Auditor Q2 2026'"

Claude will call `dry_run_collection` and show you which systems each question routes to — no API calls yet, just the plan.

When you're ready to collect:
> "Collect evidence for the SOC 2 audit, engagement name 'External Auditor Q2 2026'"

Claude calls `collect_evidence`, which runs the full pipeline and returns a Google Drive link when done.

**To paste a questionnaire directly into the conversation:**
> "Here's a questionnaire I need evidence for: [paste your questions]"

Claude will call `upload_questionnaire` to save it, then proceed with collection.

### Option B: Using the CLI

First activate the virtual environment:
```bash
cd ~/Projects/EXHIBIT
source .venv/bin/activate   # Windows: .venv\Scripts\activate
```

**Preview the collection plan (no API calls):**
```bash
python -m agent.main frameworks/example_soc2_audit.csv "External Auditor Q2 2026" --dry-run
```

**Run the full pipeline (collect + upload to Drive):**
```bash
python -m agent.main frameworks/example_soc2_audit.csv "External Auditor Q2 2026"
```

**Collect evidence locally without uploading (review first, upload later):**
```bash
python -m agent.main collect frameworks/soc2_type2.csv "External Auditor Q2 2026"
# Evidence saved to ~/.exhibit/workspaces/<run_id>/
# Inspect the files, then upload when ready:
python -m agent.main upload 20260612_143022
```

**List previous collection runs:**
```bash
python -m agent.main runs
```

**Collect from specific systems only (faster, useful for partial runs):**
```bash
python -m agent.main frameworks/example_soc2_audit.csv "External Auditor Q2 2026" --only aws,github,okta
```

**Resume a failed collection (skip already-completed items):**
```bash
python -m agent.main frameworks/example_soc2_audit.csv "External Auditor Q2 2026" --resume
```

**Skip the AI classification step (faster, works without an API key):**
```bash
python -m agent.main frameworks/example_soc2_audit.csv "External Auditor Q2 2026" --no-claude
```

**Force fresh API calls (bypass cache):**
```bash
python -m agent.main frameworks/example_soc2_audit.csv "External Auditor Q2 2026" --no-cache
```

**Check which credentials are configured:**
```bash
python -m agent.main --check-credentials
```

### Available framework templates

These are ready to use — just swap out the CSV path. Each framework template has a corresponding YAML mapping file that tells EXHIBIT exactly which systems to query for each control (no LLM required for routing):

| File | Framework | Controls mapped |
|---|---|---|
| `frameworks/soc2_type2.csv` | SOC 2 Type II | 40 criteria → 14 systems |
| `frameworks/iso27001_2022.csv` | ISO 27001:2022 Annex A | 54 controls → 14 systems |
| `frameworks/nist_csf_2.csv` | NIST CSF 2.0 | 57 subcategories → 12 systems |
| `frameworks/nydfs_500.csv` | NYDFS 23 NYCRR 500 | 24 sections → 9 systems |
| `frameworks/caiq_v4.csv` | CSA CAIQ v4 | 166 controls → 14 systems |
| `frameworks/sig_lite.csv` | SIG Lite (Shared Assessments) | 78 questions → 14 systems |
| `frameworks/example_soc2_audit.csv` | Custom audit request list | LLM/keyword routing |

Framework detection is automatic — EXHIBIT identifies which framework a questionnaire belongs to from its item IDs and routes accordingly. All framework mappings are validated against the system registry at startup — a typo in a YAML file will fail loud rather than silently misrouting.

---

## 6. Understanding the output

The agent creates a Google Drive folder named after your engagement (e.g. "External Auditor Q2 2026") and shares it with the email address you set in `GOOGLE_DRIVE_OWNER_EMAIL`.

```
External Auditor Q2 2026/
├── 00_Index/
│   ├── master_summary.md       ← start here — overview of all evidence collected
│   └── evidence_index.json     ← machine-readable index
├── 01_Access_Control/
│   ├── Q5.2_Privileged_Access/
│   │   ├── 00_explainer.md     ← plain-English explanation for the reviewer
│   │   ├── okta_users.json     ← actual evidence file
│   │   └── github_teams.json
│   └── Q7.1_Account_Listing/
│       ├── 00_explainer.md
│       └── aws_iam_users.json
├── 02_Change_Management/
│   └── ...
└── 03_Encryption/
    └── ...
```

**`00_explainer.md` (in every subfolder)** — this is the most useful file for auditors. It explains in plain English what the audit question is asking, what systems were queried, what was found, and how it answers the question. Reviewers can read these without knowing anything about the underlying APIs.

**`master_summary.md`** — one-page overview of the entire engagement: how many items were collected, which systems were queried, any errors, and a table linking each question to its evidence folder.

**JSON/CSV files** — raw evidence data pulled directly from the APIs. These are attached as-is so auditors can verify the source.

---

## 7. Using a custom questionnaire

If you receive a questionnaire in a different format (e.g. from an auditor), you can use it directly.

**CSV format (simplest):**

Create a file with at least two columns: `id` and `question`.

```csv
id,question
1,Please provide a list of all users with privileged access
2,Provide evidence of your patch management process
3,Provide a sample of access modification tickets from the past 90 days
```

Save it as a `.csv` file and pass it to the agent:
```bash
python -m agent.main my_questionnaire.csv "Auditor Name Q2 2026"
```

**Excel format:**

The agent also accepts `.xlsx` files — just make sure the first row has column headers including `id` and `question`.

**If you have a PDF or Word document from an auditor:**

You'll need to copy the questions into a CSV manually, or paste them into Claude Code and ask it to format them. Claude will call the `upload_questionnaire` tool to prepare the file automatically.

---

## 8. Troubleshooting

### "Docker: no such file or directory" or "docker compose: command not found"

Docker Desktop is not installed or not running. Download it from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/), install it, and open it. The whale icon in your menu bar/system tray confirms it's running.

### "Connection refused" when the MCP server tries to connect

The container may not be running. Check:
```bash
docker compose ps
```
If `exhibit-mcp` isn't listed as `Up`, start it:
```bash
docker compose up -d
```

### "ModuleNotFoundError" when running locally

The virtual environment isn't activated. Run:
```bash
source .venv/bin/activate   # macOS/Linux
.venv\Scripts\activate      # Windows
```
Your prompt should show `(.venv)` when activated.

### A credential shows as MISSING in `--check-credentials`

The environment variable for that system isn't set. Either:
- **Docker**: Open Docker Desktop → Containers → exhibit-mcp → Inspect → Env tab, and add the missing variable, then restart the container
- **Local**: Open `.env` in a text editor and add the value, then re-run the command

### "Google Drive upload failed" or "service account" error

The Google service account JSON path is wrong, or the file isn't accessible inside Docker. Verify:
1. The JSON file exists at the path you specified
2. For Docker: the volume mount in `docker-compose.yml` is uncommented and the host path is correct
3. The service account has been granted access to Google Drive (either directly, or via domain-wide delegation)

### The agent returns "manual review required" for many items

This means it couldn't route those questions to any configured system — either the credentials for those systems aren't set, or the questions don't match any known keywords. Run `--dry-run` to see the routing plan and check which systems are needed for each item.

### Some items reference internal applications

These internal applications don't have public APIs. For evidence:
- Connect to your corporate VPN first
- Then run the collection with `--only aws` to pull CloudTrail and IAM records for those systems from AWS
- Alternatively, use browser automation: the agent will open Chrome with your existing session and screenshot the relevant pages

---

## 9. For developers: extending the agent

### Adding a new system

1. **Create a collector** — add `agent/collectors/my_system_collector.py` with a class that has a `collect(request: EvidenceRequest) -> EvidenceResult` method. Look at `agent/collectors/kandji_collector.py` for a clean example.

2. **Register the system** — add `MY_SYSTEM = "my_system"` to the `System` enum in `agent/models.py`.

3. **Add routing keywords** — add an entry to `SYSTEM_KEYWORDS` in `agent/questionnaire_parser.py` with the keywords that should trigger collection from this system.

4. **Wire up the orchestrator** — add the collector to `COLLECTOR_MAP` and a credential check lambda to `CREDENTIAL_CHECKS` in `agent/main.py`.

5. **Update framework mappings** — add your system to the relevant controls in `frameworks/mappings/*.yml`. The loader validates all system names at startup, so typos are caught immediately.

6. **Expose in the MCP server** — no changes needed; the MCP server calls through to `agent/main.py` automatically.

### Adding a new framework

To add support for a new compliance framework, just drop a YAML file in `frameworks/mappings/`:

```yaml
# frameworks/mappings/hipaa.yml
framework: hipaa
name: HIPAA Security Rule
description: Security Rule safeguard-to-system mappings
id_pattern: "^164\\.3"

controls:
  "164.312(a)(1)":
    systems: [okta, aws]
    category: Access Control
  "164.312(a)(2)(i)":
    systems: [okta, aws, github]
    category: Access Control
  "164.312(b)":
    systems: [crowdstrike, aws]
    category: Audit Controls
```

**Rules:**
- Every system name must exist in the `System` enum — the loader will error on startup if you typo one
- `id_pattern` is a regex used to auto-detect this framework from questionnaire item IDs
- `category` is optional but recommended — it controls folder organization in the Drive output
- No Python changes required; the registry picks up new YAML files automatically

### Dev workflow

```bash
make install    # install deps + pre-commit hooks (one-time)
make check      # run lint + security + tests (before committing)
make test       # run 27 tests (parser, framework loader, pipeline)
make format     # auto-fix style issues
```

Pre-commit hooks run automatically — `ruff` (lint/format), `bandit` (security), and `pytest` gate every commit. All tests run without credentials.

### Running a manual smoke test

```bash
source .venv/bin/activate
python -m agent.main frameworks/soc2_type2.csv "Test SOC2" --dry-run --no-claude
```

This exercises the full parsing and routing pipeline without making any API calls or Drive writes.

### Environment variables reference

| Variable | Default | Purpose |
|---|---|---|
| `EXHIBIT_LLM_BACKEND` | auto-detect | LLM backend: `claude` or `heuristic` |
| `EXHIBIT_CLAUDE_MODEL` | `claude-sonnet-4-20250514` | Model for classification and explainers |
| `EXHIBIT_MAX_WORKERS` | `5` | Thread pool size for parallel collection |
| `EXHIBIT_CACHE_TTL` | `14400` (4 hours) | Response cache TTL in seconds |
| `EXHIBIT_MAX_RETRIES` | `2` | Max retries for transient API failures |
| `EXHIBIT_WORKSPACES_DIR` | `~/.exhibit/workspaces` | Pipeline workspace storage |
| `EXHIBIT_RUNS_DIR` | `~/.exhibit/runs` | Persistent run log storage |
| `EXHIBIT_CACHE_DIR` | `~/.exhibit/cache` | Response cache storage |
| `BROWSER_URL_MAP` | — | JSON mapping of keywords to dashboard URLs for browser collector |

### Architecture overview

```
agent/
  main.py              — CLI entry point, pipeline stages, parallel orchestration
  pipeline.py          — CollectionRun workspace: serializable state between stages
  models.py            — System enum, EvidenceRequest, EvidenceResult dataclasses
  llm.py               — LLM abstraction layer (Classifier + ExplainerGenerator protocols)
  questionnaire_parser.py — CSV/Excel parsing, LLM/heuristic routing
  framework_loader.py  — YAML framework mapping loader with validation
  drive_organizer.py   — Google Drive folder creation and file upload
  report_generator.py  — explainer docs and master summary generation
  cache.py             — File-based response cache with TTL
  retry.py             — Retry with backoff + run state for --resume
  run_logger.py        — Persistent JSON run logs
  collectors/
    aws_collector.py
    browser_collector.py
    github_collector.py
    ... (one file per system)
mcp_server/
  server.py            — FastMCP server exposing agent functions as MCP tools
frameworks/
  *.csv                — pre-built questionnaire templates
  mappings/*.yml       — framework control-to-system YAML mappings
```

**Pipeline stages:**

The collection process is split into three independent stages with serializable state between them:

1. **Parse** — reads the questionnaire, detects the framework, classifies items → saves `requests.json` to workspace
2. **Collect** — queries systems in parallel (5 threads by default), writes evidence files to workspace on disk
3. **Upload** — generates explainer docs, uploads everything to Google Drive

You can run all three in sequence (default), or run `collect` alone to review evidence locally before uploading. Each run creates a workspace at `~/.exhibit/workspaces/<run_id>/` with all evidence files accessible for inspection.

**LLM backend:**

EXHIBIT auto-detects whether an Anthropic API key is available:
- **With key**: uses Claude for intelligent question classification and rich explainer generation
- **Without key**: uses keyword matching + framework YAML maps for routing, and template-based explainers

Override with `EXHIBIT_LLM_BACKEND=heuristic` or `EXHIBIT_LLM_BACKEND=claude`.

---

## License

EXHIBIT uses a dual license:

| What | License |
|---|---|
| Source code (`agent/`, `mcp_server/`, `Dockerfile`, etc.) | [Apache 2.0](LICENSE) |
| Documentation & templates (`README.md`, `frameworks/*.csv`, skills) | [CC BY 4.0](LICENSE-docs) |

**Apache 2.0** means you can use, modify, and redistribute the code freely — including commercially — as long as you include the license and attribution.

**CC BY 4.0** means you can share and adapt the docs and templates for any purpose, as long as you credit the original.

Copyright 2026 Adam Duman
