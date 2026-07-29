"""
SIEM Export Module

Simulates forwarding security pipeline events to a SIEM (Splunk, Elastic, Datadog, etc.).
In production, replace the simulated transport with actual SIEM API calls or syslog forwarding.

Supported formats:
- JSON events (for HTTP Event Collector / webhook ingestion)
- CEF (Common Event Format) for syslog-based SIEMs

Environment variables (for production use):
- SIEM_ENDPOINT: URL of the SIEM ingestion endpoint
- SIEM_TOKEN: Authentication token for the SIEM API
- SIEM_FORMAT: "json" or "cef" (default: json)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Simulated SIEM endpoint (replace with actual endpoint in production)
SIEM_ENDPOINT = os.environ.get("SIEM_ENDPOINT", "https://siem.example.com/api/events")
SIEM_TOKEN = os.environ.get("SIEM_TOKEN", "simulated-token")
SIEM_FORMAT = os.environ.get("SIEM_FORMAT", "json")


def _build_siem_event(
    event_type: str,
    severity: str,
    source: str,
    details: dict[str, Any],
    commit_sha: str = "",
    repository: str = "",
) -> dict[str, Any]:
    """Build a structured SIEM event payload.

    Args:
        event_type: Type of security event (e.g., "policy_violation", "waiver_granted", "scan_complete")
        severity: Event severity ("critical", "high", "medium", "low", "info")
        source: Source system/scanner that generated the event
        details: Event-specific details
        commit_sha: Git commit SHA associated with the event
        repository: Repository name

    Returns:
        Structured event dict ready for SIEM ingestion.
    """
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": f"secure_factory.{event_type}",
        "severity": severity,
        "source": source,
        "repository": repository or os.environ.get("GITHUB_REPOSITORY", "unknown"),
        "commit_sha": commit_sha or os.environ.get("GITHUB_SHA", "unknown"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID", "unknown"),
        "details": details,
    }


def _format_as_cef(event: dict[str, Any]) -> str:
    """Convert a SIEM event to CEF (Common Event Format) string.

    CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    severity_map = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
    cef_severity = severity_map.get(event.get("severity", "info"), 1)

    extensions = " ".join(
        f"{k}={v}" for k, v in {
            "src": event.get("repository", ""),
            "cs1": event.get("commit_sha", ""),
            "cs1Label": "commitSHA",
            "cs2": event.get("source", ""),
            "cs2Label": "scanner",
            "msg": json.dumps(event.get("details", {})),
        }.items()
    )

    return (
        f"CEF:0|SecureFactory|Pipeline|1.0|{event['event_type']}|"
        f"{event['event_type']}|{cef_severity}|{extensions}"
    )


def export_to_siem(events: list[dict[str, Any]], dry_run: bool = True) -> dict[str, Any]:
    """Export security events to SIEM.

    Args:
        events: List of structured SIEM event dicts.
        dry_run: If True, simulate the export (log events instead of sending).
                 Set to False in production with actual SIEM_ENDPOINT configured.

    Returns:
        Export result with status, event count, and destination info.
    """
    result = {
        "status": "success",
        "events_exported": len(events),
        "destination": SIEM_ENDPOINT,
        "format": SIEM_FORMAT,
        "dry_run": dry_run,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if dry_run:
        logger.info(
            "SIEM EXPORT (simulated): %d events → %s", len(events), SIEM_ENDPOINT
        )
        for i, event in enumerate(events):
            if SIEM_FORMAT == "cef":
                formatted = _format_as_cef(event)
                logger.info("  [%d] CEF: %s", i + 1, formatted)
            else:
                logger.info("  [%d] JSON: %s", i + 1, json.dumps(event, indent=2))
        result["message"] = f"Simulated export of {len(events)} events to {SIEM_ENDPOINT}"
    else:
        # Production: send events via HTTP POST to SIEM endpoint
        # Uncomment and configure for actual SIEM integration:
        #
        # import requests
        # headers = {"Authorization": f"Bearer {SIEM_TOKEN}", "Content-Type": "application/json"}
        # for event in events:
        #     payload = _format_as_cef(event) if SIEM_FORMAT == "cef" else json.dumps(event)
        #     response = requests.post(SIEM_ENDPOINT, data=payload, headers=headers, timeout=10)
        #     response.raise_for_status()
        #
        result["message"] = f"Exported {len(events)} events to {SIEM_ENDPOINT}"

    return result


def export_scan_results(
    findings_by_scanner: dict[str, int],
    policy_passed: bool,
    violations: list[dict[str, Any]],
    waivers_applied: list[dict[str, Any]],
    commit_sha: str = "",
    repository: str = "",
    dry_run: bool = True,
) -> dict[str, Any]:
    """Export a complete pipeline run's results to SIEM.

    Generates structured events for:
    - Overall scan summary
    - Each policy violation
    - Each waiver applied
    - Pipeline pass/fail decision

    Args:
        findings_by_scanner: Dict of scanner_name → finding_count
        policy_passed: Whether the policy gate passed
        violations: List of violation dicts
        waivers_applied: List of waiver dicts
        commit_sha: Git commit SHA
        repository: Repository name
        dry_run: Simulate export if True

    Returns:
        Export result summary.
    """
    events: list[dict[str, Any]] = []

    # Event 1: Scan summary
    events.append(_build_siem_event(
        event_type="scan_complete",
        severity="info",
        source="pipeline",
        details={
            "total_findings": sum(findings_by_scanner.values()),
            "findings_by_scanner": findings_by_scanner,
            "scanners_executed": list(findings_by_scanner.keys()),
        },
        commit_sha=commit_sha,
        repository=repository,
    ))

    # Event 2: Policy decision
    events.append(_build_siem_event(
        event_type="policy_decision",
        severity="info" if policy_passed else "high",
        source="policy_gate",
        details={
            "passed": policy_passed,
            "violations_count": len(violations),
            "waivers_applied_count": len(waivers_applied),
        },
        commit_sha=commit_sha,
        repository=repository,
    ))

    # Event 3+: Individual violations
    for violation in violations:
        events.append(_build_siem_event(
            event_type="policy_violation",
            severity=violation.get("severity", "medium"),
            source=violation.get("policy_id", "unknown"),
            details=violation,
            commit_sha=commit_sha,
            repository=repository,
        ))

    # Event N+: Waivers applied
    for waiver in waivers_applied:
        events.append(_build_siem_event(
            event_type="waiver_granted",
            severity="medium",
            source="waiver_workflow",
            details=waiver,
            commit_sha=commit_sha,
            repository=repository,
        ))

    return export_to_siem(events, dry_run=dry_run)


def main() -> None:
    """CLI entry point for SIEM export simulation."""
    import argparse
    import sys

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = argparse.ArgumentParser(description="Export pipeline security events to SIEM")
    parser.add_argument("--sarif", help="Path to aggregated SARIF JSON file")
    parser.add_argument("--policy-decision", help="Path to policy decision JSON file")
    parser.add_argument("--commit-sha", default=os.environ.get("GITHUB_SHA", "unknown"))
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "unknown"))
    parser.add_argument("--dry-run", action="store_true", default=True, help="Simulate export (default)")
    parser.add_argument("--format", choices=["json", "cef"], default="json", help="Event format")

    args = parser.parse_args()

    # Load findings from SARIF
    findings_by_scanner: dict[str, int] = {}
    if args.sarif and os.path.isfile(args.sarif):
        with open(args.sarif) as f:
            sarif = json.load(f)
        for run in sarif.get("runs", []):
            tool = run.get("tool", {}).get("driver", {}).get("name", "unknown")
            findings_by_scanner[tool] = len(run.get("results", []))

    # Load policy decision
    policy_passed = True
    violations: list[dict[str, Any]] = []
    waivers_applied: list[dict[str, Any]] = []
    if args.policy_decision and os.path.isfile(args.policy_decision):
        with open(args.policy_decision) as f:
            decision = json.load(f)
        policy_passed = decision.get("passed", True)
        violations = decision.get("violations", [])
        waivers_applied = decision.get("waivers_applied", [])

    # Export
    global SIEM_FORMAT
    SIEM_FORMAT = args.format

    result = export_scan_results(
        findings_by_scanner=findings_by_scanner,
        policy_passed=policy_passed,
        violations=violations,
        waivers_applied=waivers_applied,
        commit_sha=args.commit_sha,
        repository=args.repository,
        dry_run=args.dry_run,
    )

    print()
    print("=" * 60)
    print("  SIEM EXPORT SUMMARY")
    print("=" * 60)
    print(f"  Status:          {result['status']}")
    print(f"  Events exported: {result['events_exported']}")
    print(f"  Destination:     {result['destination']}")
    print(f"  Format:          {result['format']}")
    print(f"  Dry run:         {result['dry_run']}")
    print(f"  Message:         {result['message']}")
    print("=" * 60)


if __name__ == "__main__":
    main()
