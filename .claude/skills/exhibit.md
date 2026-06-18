# Skill: exhibit

EXHIBIT — Evidence eXtraction, Harvesting and Intelligence-Based Investigation Tool.

Collects compliance evidence for a given questionnaire or information request list.
Queries integrated systems via API and browser automation, then organizes everything
into a structured Google Drive folder that mirrors the questionnaire layout.

## When to invoke
- User says: `/exhibit <path> "<engagement name>"`
- User pastes a questionnaire or asks to collect evidence for an audit
- User says "run EXHIBIT" or "collect evidence for [any] audit"

## Integrated systems
AWS, GitHub, env0, Okta, Google Workspace, Jira, Confluence,
CrowdStrike (EDR + SIEM), Cloudflare, Snowflake, Kandji, Semgrep,
Lacework (CSPM), Playwright (browser)

## Pre-built framework templates
Located in `frameworks/` — auto-detected from ID patterns, no extra flags needed:
- `frameworks/soc2_type2.csv`
- `frameworks/nydfs_500.csv`
- `frameworks/iso27001_2022.csv`
- `frameworks/nist_csf_2.csv`
- `frameworks/example_soc2_audit.csv`

## Preferred: run via MCP server (Docker)

Credentials live in Docker Desktop — no .env file needed.

```bash
# First time: build the image and start the container
cd ~/Projects/EXHIBIT
docker compose up -d --build

# Claude Code picks it up automatically via .claude.json (http://localhost:8765/sse)
```

Then use MCP tools directly in conversation:
- `list_frameworks` — see available questionnaire templates
- `check_integration_status` — verify which credentials are configured
- `upload_questionnaire` — paste a questionnaire as text
- `dry_run_collection` — preview routing plan
- `collect_evidence` — run full collection, returns Drive link

Set credentials in Docker Desktop: open the `exhibit-mcp` container → **Inspect** → **Env** tab,
or edit the `environment:` block in `docker-compose.yml` before starting.

## Alternative: run locally via CLI

```bash
cd ~/Projects/EXHIBIT
source .venv/bin/activate
python -m agent.main "<questionnaire_path>" "<engagement_name>"
```

CLI flags:
- `--dry-run` — show collection plan with no API calls or Drive writes
- `--no-claude` — skip LLM classification, use built-in routing only (faster, works offline)
- `--only aws,github,crowdstrike` — restrict to specific systems
- `--check-credentials` — verify which integrations are configured

Arguments:
- `questionnaire_path`: path to CSV or Excel file; or paste raw text and I'll save it to `/tmp/questionnaire.csv`
- `engagement_name`: descriptive name e.g. `"Auditor Firm LLP Q2 2026"`

## Input CSV format
Required columns: `id`, `question`. Optional: `category`.
Framework templates include a `category` column — custom questionnaires don't need it.

## If the questionnaire is pasted as text
```python
import csv
lines = [l.strip() for l in pasted_text.split('\n') if l.strip()]
with open('/tmp/questionnaire.csv', 'w') as f:
    writer = csv.writer(f)
    writer.writerow(['id', 'question'])
    for i, line in enumerate(lines, 1):
        writer.writerow([str(i), line])
```

## Drive output structure
```
<engagement_name>/
  00_Index/
    master_summary.md       ← start here
    evidence_index.json
  01_<Category>/
    Q<id>_<short_title>/
      00_explainer.md       ← plain-English explanation for reviewer
      <evidence_files>...
  02_<Category>/
    ...
```

## In-house apps
Internal applications without public APIs route to `browser` and require Playwright with
the saved Chrome profile over corporate VPN. Alternatively, collect IAM/CloudTrail
evidence from AWS directly using `--only aws` since they run in the organization's AWS environment.

## Credential reference
All credential var names are in `docker-compose.yml` (environment block) and `.env.example`.
For the Docker path: set values in Docker Desktop UI or `docker-compose.yml` — never commit secrets.
For the CLI path: copy `.env.example` → `.env` and fill in values.
Google Drive service account setup: see `README.md`.
