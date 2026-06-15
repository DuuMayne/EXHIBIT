from __future__ import annotations
"""
Compliance evidence collection orchestrator.

Usage:
    python -m agent.main <questionnaire> "<Engagement Name>" [--dry-run] [--only aws,github]
    python -m agent.main collect <questionnaire> "<Engagement Name>" [--only aws,github]
    python -m agent.main upload <run_id>
    python -m agent.main runs
    python -m agent.main new [output_path]

Commands:
    (default)         Full pipeline: parse → collect → upload (original behavior)
    collect           Parse + collect only; saves evidence to workspace for review
    upload            Upload a previous collection run to Google Drive
    runs              List recent collection runs and their status
    new               Create a template questionnaire file to fill in

Questionnaire formats:
    .csv              Standard CSV with id,question columns (category column optional)
    .xlsx/.xls        Excel with same column structure
    .txt/.md          Plain text — one question per line (auto-numbered)
    -                 Read questions from stdin (pipe or paste)

    Lines starting with # are treated as comments. Numbered lines (e.g. "1. ...")
    are parsed with the number as the ID. Unrecognized formats are tried as text.

Flags:
    --dry-run         Parse questionnaire and show collection plan; no API calls, no Drive writes.
    --only <systems>  Comma-separated list of systems to collect from (e.g. aws,github,okta).
    --no-claude       Skip Claude classification; use heuristic/framework routing only.
    --no-cache        Bypass response cache; always make fresh API calls.
    --resume          Resume a previous run, skipping already-completed items.

Examples:
    # Use a pre-built framework template
    python -m agent.main frameworks/soc2_type2.csv "Baker Tilly Q2 2026"

    # Use a plain text file with one question per line
    python -m agent.main my_questions.txt "Vendor Assessment 2026"

    # Pipe questions from stdin
    echo "Provide your MFA policy\\nProvide your encryption controls" | python -m agent.main - "Quick Check"

    # Create a template, fill it in, then run
    python -m agent.main new my_audit.csv
    # (edit my_audit.csv)
    python -m agent.main my_audit.csv "My Custom Audit" --dry-run
"""
import os
import pickle
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from .collectors import (
    AWSCollector, BrowserCollector, CloudflareCollector, CrowdStrikeCollector,
    Env0Collector, GitHubCollector, GSuiteCollector, JiraCollector,
    KandjiCollector, LaceworkCollector, OktaCollector, SemgrepCollector,
    SnowflakeCollector,
)
from .drive_organizer import DriveOrganizer
from .models import EvidenceFile, EvidenceRequest, EvidenceResult, System
from .pipeline import CollectionRun, Stage
from .questionnaire_parser import parse_questionnaire
from .report_generator import generate_explainer, generate_master_summary
from .cache import ResponseCache
from .checks_integration import is_available as checks_available, run_checks_for_request, get_routing_decision
from .retry import RunState, retry_collect
from .run_logger import RunLogger

load_dotenv()

COLLECTOR_MAP = {
    System.AWS: AWSCollector,
    System.ENV0: Env0Collector,
    System.GITHUB: GitHubCollector,
    System.OKTA: OktaCollector,
    System.GOOGLE_WORKSPACE: GSuiteCollector,
    System.JIRA: JiraCollector,
    System.CONFLUENCE: JiraCollector,
    System.CROWDSTRIKE: CrowdStrikeCollector,
    System.CLOUDFLARE: CloudflareCollector,
    System.SNOWFLAKE: SnowflakeCollector,
    System.KANDJI: KandjiCollector,
    System.SEMGREP: SemgrepCollector,
    System.LACEWORK: LaceworkCollector,
    System.BROWSER: BrowserCollector,
}

CREDENTIAL_CHECKS = {
    System.AWS: lambda: __import__("boto3").Session(
        profile_name=os.getenv("AWS_PROFILE", "default")
    ).client("sts").get_caller_identity(),
    System.ENV0: lambda: bool(os.getenv("ENV0_API_KEY")),
    System.GITHUB: lambda: bool(os.getenv("GITHUB_TOKEN")) and bool(os.getenv("GITHUB_ORG")),
    System.OKTA: lambda: bool(os.getenv("OKTA_DOMAIN")) and bool(os.getenv("OKTA_API_TOKEN")),
    System.GOOGLE_WORKSPACE: lambda: Path(os.getenv("GOOGLE_CREDENTIALS_PATH", "")).exists(),
    System.JIRA: lambda: bool(os.getenv("ATLASSIAN_DOMAIN")) and bool(os.getenv("ATLASSIAN_API_TOKEN")),
    System.CONFLUENCE: lambda: bool(os.getenv("ATLASSIAN_DOMAIN")) and bool(os.getenv("ATLASSIAN_API_TOKEN")),
    System.CROWDSTRIKE: lambda: bool(os.getenv("CROWDSTRIKE_CLIENT_ID")) and bool(os.getenv("CROWDSTRIKE_CLIENT_SECRET")),
    System.CLOUDFLARE: lambda: bool(os.getenv("CLOUDFLARE_API_TOKEN")),
    System.SNOWFLAKE: lambda: bool(os.getenv("SNOWFLAKE_ACCOUNT")) and bool(os.getenv("SNOWFLAKE_USER")),
    System.KANDJI: lambda: bool(os.getenv("KANDJI_API_TOKEN")) and bool(os.getenv("KANDJI_SUBDOMAIN")),
    System.SEMGREP: lambda: bool(os.getenv("SEMGREP_API_TOKEN")) and bool(os.getenv("SEMGREP_ORG_SLUG")),
    System.LACEWORK: lambda: bool(os.getenv("LACEWORK_ACCOUNT")) and bool(os.getenv("LACEWORK_API_KEY")) and bool(os.getenv("LACEWORK_API_SECRET")),
    System.BROWSER: lambda: True,
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


# ---------------------------------------------------------------------------
# Stage 1: Parse
# ---------------------------------------------------------------------------

def stage_parse(
    questionnaire_path: str,
    engagement_name: str,
    use_claude: bool = True,
    run: CollectionRun | None = None,
) -> CollectionRun:
    """Parse a questionnaire into structured EvidenceRequests."""
    if run is None:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        run = CollectionRun(
            run_id=run_id,
            engagement=engagement_name,
            questionnaire_path=questionnaire_path,
            flags={"use_claude": use_claude},
        )

    print(f"[1/3] Parsing questionnaire: {questionnaire_path}")
    run.requests = parse_questionnaire(questionnaire_path, use_claude=use_claude)
    print(f"      {len(run.requests)} evidence requests identified")

    run.stage = Stage.PARSED
    run.save()
    return run


# ---------------------------------------------------------------------------
# Stage 2: Collect
# ---------------------------------------------------------------------------

MAX_WORKERS = int(os.environ.get("EXHIBIT_MAX_WORKERS", "5"))


def _collect_one(
    collector,
    req: EvidenceRequest,
    system: System,
) -> tuple[System, EvidenceResult | None, Exception | None]:
    """Worker function for parallel collection. Returns (system, result, exception)."""
    try:
        result = retry_collect(collector, req, system)
        return (system, result, None)
    except Exception as e:
        return (system, None, e)


def stage_collect(
    run: CollectionRun,
    only_systems: list[System] | None = None,
    use_cache: bool = True,
    resume: bool = False,
    max_workers: int = MAX_WORKERS,
) -> CollectionRun:
    """Collect evidence from configured systems and save to workspace.

    Systems for each request are queried in parallel (up to max_workers threads).
    """
    if run.stage not in (Stage.PARSED, Stage.COLLECTED):
        raise ValueError(f"Cannot collect from stage '{run.stage.value}' — need 'parsed' or 'collected'")

    # Initialize subsystems
    logger = RunLogger(
        engagement=run.engagement,
        questionnaire=run.questionnaire_path,
        flags={"only_systems": [s.value for s in only_systems] if only_systems else None, "resume": resume},
    )
    logger.set_total_requests(len(run.requests))
    run_state = RunState(run.engagement)
    if resume:
        print(f"      Resuming — {run_state.completed_count} items already completed")
    else:
        run_state.clear()
    response_cache = ResponseCache() if use_cache else None
    collector_cache: dict[System, object] = {}

    if only_systems:
        print(f"      Filtering to systems: {[s.value for s in only_systems]}")

    print(f"\n[2/3] Collecting evidence ({len(run.requests)} items, {max_workers} workers)...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for i, req in enumerate(run.requests, 1):
            print(f"\n  [{i}/{len(run.requests)}] Q{req.id}: {req.question[:70]}...")

            active_systems = [
                s for s in req.systems
                if not only_systems or s in only_systems
            ]
            print(f"           Systems: {[s.value for s in active_systems]}")

            # Try CHECKS library first (Tier 1 — deterministic, cheap)
            if checks_available():
                checks_result = run_checks_for_request(req)
                if checks_result and checks_result.files:
                    run.save_evidence(req.id, checks_result)
                    print(f"           [checks] {len(checks_result.files)} check(s) provided evidence")
                    # Checks covered this request — skip individual system collectors
                    # (Evidence from deterministic checks is sufficient)
                    continue

            # Pre-filter: handle skips and cache hits synchronously
            systems_to_fetch: list[tuple[System, object]] = []  # (system, collector)
            for system in active_systems:
                if system == System.MANUAL:
                    print(f"           [{system.value}] Skipped — manual review required")
                    logger.log_skip(req.id, system, "manual review required")
                    continue

                if run_state.is_done(req.id, system):
                    print(f"           [{system.value}] Already done (resume)")
                    logger.log_skip(req.id, system, "already completed (resume)")
                    continue

                collector = _init_collector(system, collector_cache)
                if not collector:
                    print(f"           [{system.value}] Skipped — credentials not available")
                    logger.log_skip(req.id, system, "credentials not available")
                    continue

                # Check response cache
                cached_data = response_cache.get(system.value, req.id, call_key="collect") if response_cache else None
                if cached_data is not None:
                    result = pickle.loads(cached_data)
                    run.save_evidence(req.id, result)
                    logger.log_result(req.id, system, result)
                    run_state.mark_done(req.id, system)
                    print(f"           [{system.value}] CACHED ({len(result.files)} files)")
                    continue

                systems_to_fetch.append((system, collector))

            if not systems_to_fetch:
                continue

            # Dispatch remaining systems in parallel
            futures = {}
            for system, collector in systems_to_fetch:
                logger.start_item(req.id, system)
                future = executor.submit(_collect_one, collector, req, system)
                futures[future] = system

            # Gather results as they complete
            for future in as_completed(futures):
                system = futures[future]
                sys_name = system.value
                returned_system, result, exc = future.result()

                if exc is not None:
                    print(f"           [{sys_name}] FAILED: {exc}")
                    err_result = EvidenceResult(request_id=req.id, system=system, error=str(exc))
                    run.save_evidence(req.id, err_result)
                    logger.log_result(req.id, system, err_result)
                elif result is not None:
                    run.save_evidence(req.id, result)
                    logger.log_result(req.id, system, result)
                    if result.error:
                        print(f"           [{sys_name}] ERROR: {result.error}")
                    else:
                        if response_cache:
                            response_cache.set(system.value, req.id, call_key="collect", data=pickle.dumps(result))
                        run_state.mark_done(req.id, system)
                        print(f"           [{sys_name}] OK ({len(result.files)} files)")

    log_path = logger.finalize()
    run.stage = Stage.COLLECTED
    run.save()

    # Print summary
    all_results = run.load_all_evidence()
    total = sum(len(r.files) for results in all_results.values() for r in results)
    errors = sum(1 for results in all_results.values() for r in results if r.error)
    print(f"\n      Evidence files: {total} | Errors: {errors}")
    print(f"      Workspace: {run.workspace}")
    print(f"      Run log: {log_path}")
    return run


# ---------------------------------------------------------------------------
# Stage 3: Upload
# ---------------------------------------------------------------------------

def stage_upload(run: CollectionRun) -> CollectionRun:
    """Generate explainers and upload evidence to Google Drive."""
    if run.stage not in (Stage.COLLECTED, Stage.UPLOADED):
        raise ValueError(f"Cannot upload from stage '{run.stage.value}' — need 'collected'")

    all_results = run.load_all_evidence()

    # Create Drive folder structure
    print(f"\n[3/3] Uploading to Google Drive...")
    organizer = DriveOrganizer()
    root_folder_id = organizer.create_engagement_folder(run.engagement)
    drive_link = organizer.get_folder_link(root_folder_id)
    print(f"      Folder: {drive_link}")

    # Generate explainers and upload
    category_counter: dict[str, int] = {}
    for req in run.requests:
        results = all_results.get(req.id, [])
        if not results or not any(r.files for r in results):
            print(f"  Q{req.id}: No evidence, skipping")
            continue

        print(f"  Q{req.id}: Generating explainer...", end=" ", flush=True)
        try:
            # Check for cached explainer
            explainer = run.load_explainer(req.id)
            if not explainer:
                explainer = generate_explainer(req, results)
                run.save_explainer(req.id, explainer)

            uploaded = organizer.upload_evidence(
                root_folder_id, req, results, category_counter, explainer
            )
            for result in results:
                result.drive_file_ids = uploaded
            print(f"OK ({len(uploaded)} files)")
        except Exception as e:
            print(f"FAILED: {e}")

    # Create master index
    print(f"      Creating master index...")
    summary_md, index_json = generate_master_summary(
        run.engagement, run.requests, all_results, drive_link
    )
    organizer.upload_index(root_folder_id, index_json, summary_md)

    run.drive_link = drive_link
    run.stage = Stage.UPLOADED
    run.save()

    print(f"\n=== Upload Complete ===")
    print(f"Drive folder: {drive_link}")
    return run


# ---------------------------------------------------------------------------
# Convenience: full pipeline (backward-compatible)
# ---------------------------------------------------------------------------

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
    use_cache: bool = True,
    resume: bool = False,
) -> str:
    """Full pipeline: parse → collect → upload. Returns Drive link."""
    print(f"\n=== Compliance Evidence Collection: {engagement_name} ===\n")

    collection_run = stage_parse(questionnaire_path, engagement_name, use_claude=use_claude)
    collection_run = stage_collect(collection_run, only_systems=only_systems, use_cache=use_cache, resume=resume)
    collection_run = stage_upload(collection_run)

    print(f"\nOpen {collection_run.drive_link} to review evidence before submission.\n")
    return collection_run.drive_link


def collect_only(
    questionnaire_path: str,
    engagement_name: str,
    only_systems: list[System] | None = None,
    use_claude: bool = True,
    use_cache: bool = True,
    resume: bool = False,
) -> CollectionRun:
    """Parse + collect only. Returns the run for later upload."""
    print(f"\n=== Evidence Collection (no upload): {engagement_name} ===\n")

    collection_run = stage_parse(questionnaire_path, engagement_name, use_claude=use_claude)
    collection_run = stage_collect(collection_run, only_systems=only_systems, use_cache=use_cache, resume=resume)

    print(f"\n=== Collection Complete ===")
    print(f"Workspace: {collection_run.workspace}")
    print(f"Run ID: {collection_run.run_id}")
    print(f"\nTo upload: python -m agent.main upload {collection_run.run_id}")
    print(f"To inspect: ls {collection_run.evidence_dir}\n")
    return collection_run


def upload_run(run_id: str) -> str:
    """Upload a previously collected run to Drive."""
    print(f"\n=== Uploading run: {run_id} ===")
    collection_run = CollectionRun.load(run_id)
    print(f"Engagement: {collection_run.engagement}")
    print(f"Requests: {len(collection_run.requests)}")

    collection_run = stage_upload(collection_run)
    print(f"\nOpen {collection_run.drive_link} to review evidence before submission.\n")
    return collection_run.drive_link


def list_runs():
    """Print recent collection runs."""
    runs = CollectionRun.list_runs()
    if not runs:
        print("\nNo collection runs found.\n")
        return

    print(f"\n=== Recent Runs ===\n")
    print(f"{'Run ID':<20} {'Stage':<12} {'Engagement':<40} {'Created'}")
    print("-" * 90)
    for r in runs:
        print(f"{r['run_id']:<20} {r['stage']:<12} {r['engagement'][:38]:<40} {r['created_at'][:19]}")
    print()


TEMPLATE_CSV = """id,category,question
1,Access Control,Provide evidence that multi-factor authentication is enforced for all users with access to production systems
2,Access Control,Provide a current list of all user accounts with their role assignments and last login date
3,Access Control,Provide evidence of your access review process and most recent review results
4,Change Management,Provide evidence that code changes require peer review before deployment to production
5,Change Management,Provide evidence of your change management approval process
6,Encryption,Provide evidence that sensitive data is encrypted at rest and in transit
7,Logging & Monitoring,Provide evidence that audit logging is enabled and logs are retained per your retention policy
8,Vulnerability Management,Provide evidence of regular vulnerability scanning and remediation within defined SLAs
9,Incident Response,Provide your incident response plan and evidence of testing within the past 12 months
10,Business Continuity,Provide evidence of backup procedures and most recent restoration test
""".lstrip()

TEMPLATE_TXT = """# Custom Questionnaire — one question per line
# Lines starting with # are comments and will be skipped
# You can number lines (e.g., "1. question") or leave them unnumbered

Provide evidence that multi-factor authentication is enforced for all production access
Provide a list of all user accounts with role assignments and last login date
Provide evidence of your access review process
Provide evidence that code changes require peer review before production deployment
Provide evidence of encryption at rest and in transit for sensitive data
Provide evidence of centralized audit logging and your log retention policy
Provide evidence of vulnerability scanning and remediation SLAs
Provide your incident response plan and evidence of annual testing
Provide evidence of backup and restoration testing
"""


def create_template(output_path: str | None = None):
    """Create a questionnaire template file."""
    if output_path is None:
        output_path = "questionnaire.csv"

    path = Path(output_path)
    if path.exists():
        print(f"Error: {path} already exists. Choose a different name or delete it first.")
        sys.exit(1)

    if path.suffix in (".txt", ".md"):
        path.write_text(TEMPLATE_TXT)
    else:
        # Default to CSV
        if not path.suffix:
            path = path.with_suffix(".csv")
        path.write_text(TEMPLATE_CSV)

    print(f"\nCreated template: {path}")
    print(f"\nEdit this file with your audit questions, then run:")
    print(f"  python -m agent.main {path} \"Your Engagement Name\" --dry-run")
    print(f"\nTips:")
    print(f"  - The 'id' column can be any identifier (numbers, CC6.1, etc.)")
    print(f"  - The 'category' column is optional but helps organize Drive output")
    print(f"  - Be specific in questions — mention systems/artifacts you need")
    print(f"  - Or use a .txt file with one question per line (simpler)\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if args[0] == "--check-credentials":
        check_credentials()
        sys.exit(0)

    # Subcommands
    if args[0] == "runs":
        list_runs()
        sys.exit(0)

    if args[0] == "new":
        output = args[1] if len(args) > 1 else None
        create_template(output)
        sys.exit(0)

    if args[0] == "upload":
        if len(args) < 2:
            print("Usage: python -m agent.main upload <run_id>")
            sys.exit(1)
        upload_run(args[1])
        sys.exit(0)

    if args[0] == "collect":
        args = args[1:]  # shift past subcommand
        if len(args) < 2:
            print("Usage: python -m agent.main collect <questionnaire.csv> '<Engagement Name>' [--only aws,github]")
            sys.exit(1)
        questionnaire_path = args[0]
        engagement_name = args[1]
        no_claude = "--no-claude" in args
        no_cache = "--no-cache" in args
        is_resume = "--resume" in args
        only_systems = _parse_only_systems(args)
        collect_only(
            questionnaire_path, engagement_name,
            only_systems=only_systems,
            use_claude=not no_claude,
            use_cache=not no_cache,
            resume=is_resume,
        )
        sys.exit(0)

    # Default: full pipeline (original behavior)
    if len(args) < 2:
        print("Usage: python -m agent.main <questionnaire.csv> '<Engagement Name>' [--dry-run] [--only aws,github] [--no-claude]")
        sys.exit(1)

    questionnaire_path = args[0]
    engagement_name = args[1]
    is_dry_run = "--dry-run" in args
    no_claude = "--no-claude" in args
    no_cache = "--no-cache" in args
    is_resume = "--resume" in args

    only_systems = _parse_only_systems(args)

    if is_dry_run:
        dry_run(questionnaire_path, engagement_name, use_claude=not no_claude)
    else:
        run(
            questionnaire_path, engagement_name,
            only_systems=only_systems,
            use_claude=not no_claude,
            use_cache=not no_cache,
            resume=is_resume,
        )


def _parse_only_systems(args: list[str]) -> list[System] | None:
    if "--only" not in args:
        return None
    idx = args.index("--only")
    if idx + 1 >= len(args):
        return None
    only_systems = []
    for name in args[idx + 1].split(","):
        try:
            only_systems.append(System(name.strip()))
        except ValueError:
            print(f"Unknown system '{name}'. Valid: {[s.value for s in System]}")
            sys.exit(1)
    return only_systems
