"""
Integration between EXHIBIT and the shared CHECKS library.

This module provides:
1. A ChecksCollector that runs checks from the shared library and
   converts results into EXHIBIT's EvidenceResult format
2. Integration with EXHIBIT's decision engine to route questions
   through checks before falling back to expensive collectors/agents

When a framework mapping includes a 'checks' field, EXHIBIT will:
  1. Run those checks via the shared library
  2. Use the pass/fail result + evidence as audit proof
  3. Skip the full collector for that system (already have what we need)

If the CHECKS library isn't installed, this module gracefully no-ops
and EXHIBIT falls back to its existing collector behavior.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from .models import EvidenceFile, EvidenceRequest, EvidenceResult, System

logger = logging.getLogger("exhibit.checks_integration")

try:
    from checks.runner import run_check, run_check_from_definition
    from checks.config import load_config, build_catalogs
    from checks.decision import route as checks_route
    from checks.models import CheckResult, Status, Tier

    CHECKS_AVAILABLE = True
except ImportError:
    CHECKS_AVAILABLE = False
    logger.info("CHECKS library not installed — integration inactive")


def is_available() -> bool:
    """Check if the CHECKS library is installed and usable."""
    return CHECKS_AVAILABLE


def run_checks_for_request(
    request: EvidenceRequest,
    check_keys: list[str] | None = None,
) -> Optional[EvidenceResult]:
    """Run relevant checks from the shared library for an evidence request.

    Args:
        request: The evidence request to collect for.
        check_keys: Specific check keys to run (from framework mapping).
                    If None, attempts to find relevant checks from config.

    Returns:
        EvidenceResult with check evidence, or None if no checks are applicable.
    """
    if not CHECKS_AVAILABLE:
        return None

    # Load check definitions from config
    config = load_config()
    checks = config.get("checks", {})

    # Determine which checks to run
    keys_to_run = []
    if check_keys:
        keys_to_run = [k for k in check_keys if k in checks]
    else:
        # Try to find checks relevant to the request's systems
        systems = [s.value for s in request.systems if s not in (System.MANUAL, System.BROWSER)]
        for key, defn in checks.items():
            if defn.get("connector") in systems:
                keys_to_run.append(key)

    if not keys_to_run:
        return None

    # Run checks and collect results
    all_evidence = {}
    all_summaries = []
    all_files = []

    for key in keys_to_run:
        defn = {"key": key, **checks[key]}
        result = run_check_from_definition(defn)

        # Convert to evidence file
        evidence_json = json.dumps({
            "check_key": key,
            "status": result.status.value,
            "summary": result.summary,
            "evidence": result.evidence,
            "failures": [
                {"resource_id": f.resource_id, "reason": f.reason, "details": f.details}
                for f in result.failures
            ],
            "executed_at": result.executed_at,
            "duration_ms": result.duration_ms,
        }, indent=2).encode()

        all_files.append(EvidenceFile(
            filename=f"check_{key}_result.json",
            content=evidence_json,
            mime_type="application/json",
            description=f"Check '{key}': {result.summary}",
        ))

        all_summaries.append(f"[{key}] {result.status.value.upper()}: {result.summary}")
        all_evidence[key] = result.evidence

    if not all_files:
        return None

    # Determine overall status
    any_fail = any("[FAIL]" in s for s in all_summaries) if all_summaries else False

    return EvidenceResult(
        request_id=request.id,
        system=request.systems[0] if request.systems else System.MANUAL,
        files=all_files,
        text_summary="\n".join(all_summaries),
        error=None,
    )


def get_routing_decision(question: str, systems: list[str]) -> Optional[dict]:
    """Use the CHECKS decision engine to determine the cheapest evidence tier.

    Returns a dict with 'tier' and context, or None if CHECKS isn't available.
    """
    if not CHECKS_AVAILABLE:
        return None

    config = load_config()
    check_catalog, retrieval_catalog = build_catalogs(config)

    decision = checks_route(
        question=question,
        systems=systems,
        check_catalog=check_catalog,
        retrieval_catalog=retrieval_catalog,
    )

    return {
        "tier": decision.tier.value,
        "reason": decision.reason,
        "check_keys": decision.check_keys,
        "retrieval_specs": decision.retrieval_specs,
    }
