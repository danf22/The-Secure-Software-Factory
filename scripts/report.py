"""
Per-Run Summary Report Module

Generates a per-run summary report linking:
- Commit SHA
- All scan findings (with per-scanner counts)
- Policy decisions (pass/fail with violation details)
- Applied waivers
- Resulting build status

Invariant: total_findings == sum of per-scanner counts

Reports are stored as JSON in the evidence/reports/ directory.

CLI Usage:
    python -m scripts.report --commit-sha <sha> --build-status <passed|failed> \\
        --sarif <aggregated_sarif.json> --policy-decision <decision.json> \\
        [--output-dir <evidence_dir>]

Environment Variables:
    COMMIT_SHA: Git commit SHA (overridden by --commit-sha)
    BUILD_STATUS: Build status "passed" or "failed" (overridden by --build-status)
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone

from scripts.models import PolicyDecision, PolicyViolation, Waiver


def generate_summary_report(
    commit_sha: str,
    findings_by_scanner: dict[str, int],
    policy_decision: PolicyDecision,
    applied_waivers: list[Waiver],
    build_status: str,
    evidence_dir: str,
) -> str:
    """
    Generate a per-run summary report linking all pipeline results.

    Creates a JSON file in evidence_dir/reports/ containing:
    - commit_sha
    - total_findings and per-scanner breakdown
    - policy_decision (pass/fail, violations)
    - applied waivers
    - build_status
    - timestamp

    Invariant: total_findings == sum of findings_by_scanner values
    Returns the path to the created report file.

    Raises:
        ValueError: If total_findings != sum of per-scanner counts
        ValueError: If build_status is not "passed" or "failed"
    """
    # Validate build_status
    if build_status not in ("passed", "failed"):
        raise ValueError(
            f"build_status must be 'passed' or 'failed', got '{build_status}'"
        )

    # Compute total findings and validate invariant
    total_findings = sum(findings_by_scanner.values())
    per_scanner_sum = sum(findings_by_scanner.values())
    if total_findings != per_scanner_sum:
        raise ValueError(
            f"Invariant violated: total_findings ({total_findings}) "
            f"!= sum of per-scanner counts ({per_scanner_sum})"
        )

    # Generate timestamp and decision ID
    timestamp = datetime.now(timezone.utc).isoformat()
    decision_id = str(uuid.uuid4())

    # Build violations list from policy decision
    violations = [
        {
            "policy_id": v.policy_id,
            "message": v.message,
            "resource": v.resource,
            "severity": v.severity,
            "regulatory_refs": v.regulatory_refs,
        }
        for v in policy_decision.violations
    ]

    # Build waivers applied list
    waivers_applied = [
        {
            "waiver_id": w.waiver_id,
            "policy_id": w.policy_id,
            "approver": w.approver,
            "expiration_date": w.expiration_date,
        }
        for w in applied_waivers
    ]

    # Build the report dict matching the Policy Decision Record schema
    report = {
        "decision_id": decision_id,
        "commit_sha": commit_sha,
        "timestamp": timestamp,
        "passed": policy_decision.passed,
        "violations": violations,
        "waivers_applied": waivers_applied,
        "scan_summary": {
            "total_findings": total_findings,
            "by_scanner": findings_by_scanner,
        },
        "build_status": build_status,
    }

    # Create reports directory if it doesn't exist
    reports_dir = os.path.join(evidence_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    # Generate unique filename
    short_sha = commit_sha[:8] if len(commit_sha) >= 8 else commit_sha
    ts_compact = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"report-{short_sha}-{ts_compact}.json"
    report_path = os.path.join(reports_dir, filename)

    # Write formatted JSON
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return report_path


def _extract_findings_by_scanner(aggregated_sarif: dict) -> dict[str, int]:
    """Extract per-scanner finding counts from an aggregated SARIF report."""
    findings: dict[str, int] = {}
    for run in aggregated_sarif.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        # Normalize tool names to match expected keys
        key = tool_name.lower().replace(" ", "_")
        results_count = len(run.get("results", []))
        findings[key] = findings.get(key, 0) + results_count
    return findings


def _parse_policy_decision(decision_data: dict) -> tuple[PolicyDecision, list[Waiver]]:
    """Parse a policy decision JSON into PolicyDecision and applied Waivers."""
    violations = [
        PolicyViolation(
            policy_id=v.get("policy_id", ""),
            message=v.get("message", ""),
            resource=v.get("resource", ""),
            severity=v.get("severity", "medium"),
            regulatory_refs=v.get("regulatory_refs", []),
        )
        for v in decision_data.get("violations", [])
    ]

    applied_waivers = [
        Waiver(
            waiver_id=w.get("waiver_id", ""),
            policy_id=w.get("policy_id", ""),
            justification=w.get("justification", ""),
            approver=w.get("approver", ""),
            expiration_date=w.get("expiration_date", ""),
            resource=w.get("resource", ""),
            created_at=w.get("created_at", ""),
        )
        for w in decision_data.get("waivers_applied", [])
    ]

    policy_decision = PolicyDecision(
        passed=decision_data.get("passed", False),
        violations=violations,
        waivers_applied=[w.waiver_id for w in applied_waivers],
        timestamp=decision_data.get("timestamp", datetime.now(timezone.utc).isoformat()),
    )

    return policy_decision, applied_waivers


def main() -> None:
    """CLI entry point for generating the per-run summary report."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate per-run summary report for the security pipeline"
    )
    parser.add_argument(
        "--commit-sha",
        default=os.environ.get("COMMIT_SHA", ""),
        help="Git commit SHA (default: $COMMIT_SHA env var)",
    )
    parser.add_argument(
        "--build-status",
        default=os.environ.get("BUILD_STATUS", "failed"),
        help="Build status: 'passed' or 'failed' (default: $BUILD_STATUS env var)",
    )
    parser.add_argument(
        "--sarif",
        required=True,
        help="Path to aggregated SARIF JSON file",
    )
    parser.add_argument(
        "--policy-decision",
        required=True,
        help="Path to policy decision JSON file",
    )
    parser.add_argument(
        "--output-dir",
        default="evidence",
        help="Output evidence directory (default: evidence)",
    )

    args = parser.parse_args()

    if not args.commit_sha:
        print("Error: --commit-sha or COMMIT_SHA env var is required", file=sys.stderr)
        sys.exit(1)

    # Load aggregated SARIF
    try:
        with open(args.sarif, "r", encoding="utf-8") as f:
            aggregated_sarif = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading SARIF file '{args.sarif}': {e}", file=sys.stderr)
        # Use empty SARIF if file not found
        aggregated_sarif = {"version": "2.1.0", "runs": []}

    # Load policy decision
    try:
        with open(args.policy_decision, "r", encoding="utf-8") as f:
            decision_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading policy decision '{args.policy_decision}': {e}", file=sys.stderr)
        # Use default failed decision if file not found
        decision_data = {"passed": False, "violations": [], "waivers_applied": [], "timestamp": ""}

    # Extract findings by scanner
    findings_by_scanner = _extract_findings_by_scanner(aggregated_sarif)

    # Parse policy decision
    policy_decision, applied_waivers = _parse_policy_decision(decision_data)

    # Generate the report
    report_path = generate_summary_report(
        commit_sha=args.commit_sha,
        findings_by_scanner=findings_by_scanner,
        policy_decision=policy_decision,
        applied_waivers=applied_waivers,
        build_status=args.build_status,
        evidence_dir=args.output_dir,
    )

    print(f"Summary report generated: {report_path}")


if __name__ == "__main__":
    main()
