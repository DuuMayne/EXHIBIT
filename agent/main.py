"""
Compliance evidence collection orchestrator.

Usage:
    python -m agent.main <questionnaire.csv> "<Engagement Name>"

Or via the Claude skill: /compliance-evidence path/to/questionnaire.csv "Acme SOC2 Q2 2026"
"""
import os
import sys
from collections import defaultdict
from pathlib import Path

from dotenv import load_dotenv

from .collectors import AWSCollector, BrowserCollector, GitHubCollector, GSuiteCollector, JiraCollector, OktaCollector
from .drive_organizer import DriveOrganizer
from .models import EvidenceRequest, EvidenceResult, System
from .questionnaire_parser import parse_questionnaire
from .report_generator import generate_explainer, generate_master_summary

load_dotenv()

COLLECTOR_MAP = {
    System.AWS: AWSCollector,
    System.GITHUB: GitHubCollector,
    System.OKTA: OktaCollector,
    System.GOOGLE_WORKSPACE: GSuiteCollector,
    System.JIRA: JiraCollector,
    System.CONFLUENCE: JiraCollector,  # Same client handles both
}


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


def run(questionnaire_path: str, engagement_name: str):
    print(f"\n=== Compliance Evidence Collection: {engagement_name} ===\n")

    # 1. Parse questionnaire
    print(f"[1/5] Parsing questionnaire: {questionnaire_path}")
    requests = parse_questionnaire(questionnaire_path)
    print(f"      {len(requests)} evidence requests identified")

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
        print(f"           Systems: {[s.value for s in req.systems]}")
        results = []

        for system in req.systems:
            if system == System.MANUAL:
                print(f"           [{system.value}] Skipping — manual review required")
                continue

            if system == System.BROWSER:
                print(f"           [{system.value}] Browser automation (requires interaction)")
                continue

            collector = _init_collector(system, collector_cache)
            if not collector:
                print(f"           [{system.value}] Skipped — collector not available")
                continue

            print(f"           [{system.value}] Collecting...", end=" ", flush=True)
            try:
                result = collector.collect(req)
                results.append(result)
                file_count = len(result.files)
                if result.error:
                    print(f"ERROR: {result.error}")
                else:
                    print(f"OK ({file_count} files)")
            except Exception as e:
                print(f"FAILED: {e}")

        all_results[req.id] = results

    # 4. Generate explainers and upload
    print(f"\n[4/5] Generating explainers and uploading to Drive...")
    for i, req in enumerate(requests, 1):
        results = all_results.get(req.id, [])
        if not results or not any(r.files for r in results):
            print(f"  Q{req.id}: No evidence to upload, skipping")
            continue

        print(f"  Q{req.id}: Generating explainer...", end=" ", flush=True)
        try:
            explainer = generate_explainer(req, results)
            uploaded = organizer.upload_evidence(
                root_folder_id, req, results, category_counter, explainer
            )
            for result in results:
                result.drive_file_ids = uploaded
            print(f"OK ({len(uploaded)} files uploaded)")
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
    if len(sys.argv) < 3:
        print("Usage: python -m agent.main <questionnaire.csv> '<Engagement Name>'")
        sys.exit(1)
    run(sys.argv[1], sys.argv[2])
