# Skill: compliance-evidence

Collect compliance evidence for a given questionnaire or information request list.
Queries AWS, GitHub, Okta, Google Workspace, and Jira/Confluence via API,
takes browser screenshots of any UI-only pages, and organizes everything into
a structured Google Drive folder that mirrors the questionnaire layout.

## When to invoke
- User says: `/compliance-evidence <path> "<engagement name>"`
- User pastes a questionnaire or asks to collect evidence for an audit
- User says "run the compliance agent" or "collect evidence for [framework] audit"

## How to run

1. Check that `compliance-agent/` exists at `~/Projects/compliance-agent/`
2. Verify `.env` exists (copy from `.env.example` if not, and ask user to fill in credentials)
3. Run the agent:

```bash
cd ~/Projects/compliance-agent
python -m agent.main "<questionnaire_path>" "<engagement_name>"
```

4. Return the Google Drive link to the user when complete.

## Arguments
- `questionnaire_path`: absolute or relative path to a CSV or Excel file
  - Required columns: one column with questions/requests, optionally one with IDs/numbers
  - If user pastes raw text, save it to `/tmp/questionnaire.csv` first
- `engagement_name`: descriptive name for this evidence collection run
  - Example: "Acme Corp SOC2 Type II Q2 2026" or "PCI DSS Annual 2026"

## Pre-flight checks

Before running, verify:
1. `~/Projects/compliance-agent/.env` exists and has `ANTHROPIC_API_KEY` set
2. `GOOGLE_CREDENTIALS_PATH` points to a valid service account JSON file
3. At least one other integration credential is set (GITHUB_TOKEN, AWS_PROFILE, etc.)

If credentials are missing, tell the user which ones are needed and where to add them.

## If the questionnaire is pasted as text

Create a temporary CSV:
```python
import csv, tempfile
lines = [line.strip() for line in pasted_text.split('\n') if line.strip()]
with open('/tmp/questionnaire.csv', 'w') as f:
    writer = csv.writer(f)
    writer.writerow(['id', 'question'])
    for i, line in enumerate(lines, 1):
        writer.writerow([str(i), line])
```
Then use `/tmp/questionnaire.csv` as the path.

## Browser-based evidence (Playwright)

For items routed to `browser` system, the script will open a visible Chrome window
reusing your profile session. If a login wall is detected, it pauses and prompts
you to authenticate manually before continuing.

Ensure Chrome is not already open with your profile before running browser collections.

## Output structure in Google Drive

```
<engagement_name>/
  00_Index/
    master_summary.md     ← table of all items with status
    evidence_index.json   ← machine-readable index
  01_Access_Control/
    Q1_1_IAM_Users.../
      00_explainer.md     ← plain-English explanation for auditor
      iam_users_mfa_status.json
      iam_password_policy.json
    Q1_2_.../
      ...
  02_Encryption/
    ...
```
