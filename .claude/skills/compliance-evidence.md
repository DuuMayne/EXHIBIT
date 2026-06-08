# Skill: compliance-evidence

Collect compliance evidence for a given questionnaire or information request list.
Queries integrated systems via API and browser automation, then organizes
everything into a structured Google Drive folder that mirrors the questionnaire layout.

## When to invoke
- User says: `/compliance-evidence <path> "<engagement name>"`
- User pastes a questionnaire or asks to collect evidence for an audit
- User says "run the compliance agent" or "collect evidence for [any] audit"

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
- `frameworks/earnest_audit_2026.csv`

## How to run

1. Confirm `compliance-agent/` is at `~/Projects/compliance-agent/`
2. Confirm `.env` has `ANTHROPIC_API_KEY` and at least one integration credential
3. Run:

```bash
cd ~/Projects/compliance-agent
source .venv/bin/activate
python -m agent.main "<questionnaire_path>" "<engagement_name>"
```

4. Return the Google Drive link when complete.

## Flags
- `--dry-run` — show collection plan with no API calls or Drive writes
- `--no-claude` — skip LLM classification, use built-in routing only (faster, works offline)
- `--only aws,github,crowdstrike` — restrict to specific systems
- `--check-credentials` — verify which integrations are configured

## Arguments
- `questionnaire_path`: path to CSV or Excel file; or paste raw text and I'll save it to `/tmp/questionnaire.csv`
- `engagement_name`: descriptive name e.g. `"Acme Corp ISO 27001 Gap Assessment 2026"`

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

## In-house apps (MMAX, CASHI, School Hub, NEST)
These Earnest-internal apps route to `browser` and require Playwright with the saved
Chrome profile over corporate VPN. Alternatively, collect IAM/CloudTrail evidence from
AWS directly using `--only aws` since they run in Earnest's AWS environment.

## Credential reference
See `.env.example` for all credential vars. Run `--check-credentials` to see
current status. Google Drive service account setup instructions are in `README.md`.
