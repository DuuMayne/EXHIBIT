from __future__ import annotations
"""
Compliance evidence collection orchestrator.

Usage:
    python -m agent.main <questionnaire.csv> "<Engagement Name>" [--dry-run] [--only aws,github]

Flags:
    --dry-run         Parse questionnaire and show collection plan; no API calls, no Drive writes.
    --only <systems>  Comma-separated list of systems to collect from (e.g. aws,github,okta).
    --no-claude       Skip Claude classification; use heuristic/framework routing only.
"""
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from .collectors import AWSCollector, GitHubCollector, GSuiteCollector, JiraCollector, OktaCollector
from .drive_organizer import DriveOrganizer
from .models import EvidenceResult, System
from .questionnaire_parser import parse_questionnaire
from .report_generator import generate_explainer, generate_master_summary

load_dotenv()

COLLECTOR_MAP = {
    System.AWS: AWSCollector,
    System.GITHUB: GitHubCollector,
    System.OKTA: OktaCollector,
    System.GOOGLE_WORKSPACE: GSuiteCollector,
    System.JIRA: JiraCollector,
    System.CONFLUENCE: JiraCollector,
}

CREDENTIAL_CHECKS = {
    System.AWS: lambda: __import__("boto3").Session(
        profile_name=os.getenv("AWS_PROFILE", "default")
    ).client("sts").get_caller_identity(),
    System.GITHUB: lambda: bool(os.getenv("GITHUB_TOKEN")) and bool(os.getenv("GITHUB_ORG")),
    System.OKTA: lambda: bool(os.getenv("OKTA_DOMAIN")) and bool(os.getenv("OKTA_API_TOKEN")),
    System.GOOGLE_WORKSPACE: lambda: Path(os.getenv("GOOGLE_CREDENTIALS_PATH", "")).exists(),
    System.JIRA: lambda: bool(os.getenv("ATLASSIAN_DOMAIN")) and bool(os.getenv("ATLASSIAN_API_TOKEN")),
    System.CONFLUENCE: lambda: bool(os.getenv("ATLASSIAN_DOMAIN")) and bool(os.getenv("ATLASSIAN_API_TOKEN")),
}


def check_credentials() -> dict[System, bool]:
    results = {}
    for system, check in CREDENTIAL_CHECKS.items():
        try:
            results[system] = bool(check())
        except Exception:
            results[system] = False
    drive_ok = Path(os.getenv("GOOGLE_CREDENTIALS_PATH", "")).exists()
    print("\n=== Credential Check ===")
    print(f"  {'Google Drive (upload)':30s} {'OK' if drive_ok else 'MISSING — set GOOGLE_CREDENTIALS_PATH'}")
    for system, ok in results.items():
        status = "OK" if ok else f"MISSING — check .env for {system.value.upper()} vars"
        print(f"  {system.value:30s} {status}")
    print()
    return results


def _init_collector(system: System, cache: dict):
    if system not in cache:
        cls = COLLECTOR_MAP.get(system)
        if cls:
            try:
                cache[system] = cls()
            except Exception as e:
                print(f"  [warn] Could not initialize {system.value} collector: {e}")
                cache[system] = None
    return cache.get(system)


def dry_run(questionnaire_path: str, engagement_name: str, use_claude: bool = True):
    """Parse and print the collection plan without making any API calls."""
    print(f"\n=== DRY RUN: {engagement_name} ===")
    print(f"Questionnaire: {questionnaire_path}\n")

    requests = parse_questionnaire(questionnaire_path, use_claude=use_claude)

    system_counts: dict[str, int] = {}
    print(f"{'ID':<8} {'Category':<28} {'Systems':<45} Question (truncated)")
    print("-" * 120)
    for req in requests:
        systems_str = ", ".join(s.value for s in req.systems)
        for s in req.systems:
            system_counts[s.value] = system_counts.get(s.value, 0) + 1
        print(f"{req.id:<8} {req.category:<28} {systems_str:<45} {req.question[:50]}...")
        if req.hints:
            for h in req.hints:
                print(f"{'':8}   hint: {h}")

    print(f"\n{'=' * 60}")
    print(f"Total items: {len(requests)}")
    print(f"\nSystem call breakdown:")
    for system, count in sorted(system_counts.items(), key=lambda x: -x[1]):
        print(f"  {system:<30} {count} items")

    print(f"\nRun without --dry-run to collect evidence and upload to Drive.\n")


def run(
    questionnaire_path: str,
    engagement_name: str,
    only_systems: list[System] | None = None,
    use_claude: bool = True,
):
    print(f"\n=== Compliance Evidence Collection: {engagement_name} ===\n")

    # 1. Parse questionnaire
    print(f"[1/5] Parsing questionnaire: {questionnaire_path}")
    requests = parse_questionnaire(questionnaire_path, use_claude=use_claude)
    print(f"      {len(requests)} evidence requests identified")

    if only_systems:
        print(f"      Filtering to systems: {[s.value for s in only_systems]}")

    # 2. Create Drive folder structure
    print(f"\n[2/5] Creating Google Drive folder structure...")
    organizer = DriveOrganizer()
    root_folder_id = organizer.create_engagement_folder(engagement_name)
    drive_link = organizer.get_folder_link(root_folder_id)
    print(f"      Folder created: {drive_link}")

    # 3. Collect evidence
    print(f"\n[3/5] Collecting evidence ({len(requests)} items)...")
    collector_cache: dict[System, object] = {}
    all_results: dict[str, list[EvidenceResult]] = {}
    category_counter: dict[str, int] = {}

    for i, req in enumerate(requests, 1):
        print(f"\n  [{i}/{len(requests)}] Q{req.id}: {req.question[:70]}...")
        results = []

        active_systems = [
            s for s in req.systems
            if not only_systems or s in only_systems
        ]
        print(f"           Systems: {[s.value for s in active_systems]}")

        for system in active_systems:
            if system in (System.MANUAL, System.BROWSER):
                label = "manual review required" if system == System.MANUAL else "requires browser interaction"
                print(f"           [{system.value}] Skipped — {label}")
                continue

            collector = _init_collector(system, collector_cache)
            if not collector:
                print(f"           [{system.value}] Skipped — credentials not available")
                continue

            print(f"           [{system.value}] Collecting...", end=" ", flush=True)
            try:
                result = collector.collect(req)
                results.append(result)
                if result.error:
                    print(f"ERROR: {result.error}")
                else:
                    print(f"OK ({len(result.files)} files)")
            except Exception as e:
                print(f"FAILED: {e}")

        all_results[req.id] = results

    # 4. Generate explainers and upload
    print(f"\n[4/5] Generating explainers and uploading to Drive...")
    for req in requests:
        results = all_results.get(req.id, [])
        if not results or not any(r.files for r in results):
            print(f"  Q{req.id}: No evidence collected, skipping upload")
            continue

        print(f"  Q{req.id}: Generating explainer...", end=" ", flush=True)
        try:
            explainer = generate_explainer(req, results)
            uploaded = organizer.upload_evidence(
                root_folder_id, req, results, category_counter, explainer
            )
            for result in results:
                result.drive_file_ids = uploaded
            print(f"OK ({len(uploaded)} files)")
        except Exception as e:
            print(f"FAILED: {e}")

    # 5. Create master index
    print(f"\n[5/5] Creating master index...")
    summary_md, index_json = generate_master_summary(
        engagement_name, requests, all_results, drive_link
    )
    organizer.upload_index(root_folder_id, index_json, summary_md)

    print(f"\n=== Collection Complete ===")
    print(f"Drive folder: {drive_link}")
    total = sum(len(r.files) for results in all_results.values() for r in results)
    errors = sum(1 for results in all_results.values() for r in results if r.error)
    print(f"Evidence files: {total} | Errors: {errors}")
    print(f"\nOpen {drive_link} to review evidence before submission.\n")
    return drive_link


if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if args[0] == "--check-credentials":
        check_credentials()
        sys.exit(0)

    if len(args) < 2:
        print("Usage: python -m agent.main <questionnaire.csv> '<Engagement Name>' [--dry-run] [--only aws,github] [--no-claude]")
        sys.exit(1)

    questionnaire_path = args[0]
    engagement_name = args[1]
    is_dry_run = "--dry-run" in args
    no_claude = "--no-claude" in args
    use_claude = not no_claude

    only_systems = None
    if "--only" in args:
        idx = args.index("--only")
        if idx + 1 < len(args):
            only_systems = []
            for name in args[idx + 1].split(","):
                try:
                    only_systems.append(System(name.strip()))
                except ValueError:
                    print(f"Unknown system '{name}'. Valid: {[s.value for s in System]}")
                    sys.exit(1)

    if is_dry_run:
        dry_run(questionnaire_path, engagement_name, use_claude=use_claude)
    else:
        run(questionnaire_path, engagement_name, only_systems=only_systems, use_claude=use_claude)
