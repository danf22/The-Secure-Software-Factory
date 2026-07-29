"""
Audit Trail Module

Records waiver grants and policy decisions as immutable audit records.
Each audit record contains:
- Waiver justification
- Approver identity
- Expiration date
- Associated policy violation details

No required field may be empty or missing in audit records.
Records are stored as JSON in the evidence/audit/ directory.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from scripts.models import PolicyViolation, Waiver


def record_waiver_grant(
    waiver: Waiver,
    violation: PolicyViolation,
    evidence_dir: str,
) -> str:
    """
    Record a waiver grant in the audit trail.

    Creates a JSON file in evidence_dir/audit/ containing:
    - waiver_id, justification, approver, expiration_date
    - violation details (policy_id, message, resource, severity)
    - timestamp of when the record was created

    All required fields must be non-empty.
    Returns the path to the created audit record file.

    Raises:
        ValueError: If any required field is empty or missing.
    """
    # Validate waiver required fields
    _validate_non_empty("waiver.waiver_id", waiver.waiver_id)
    _validate_non_empty("waiver.justification", waiver.justification)
    _validate_non_empty("waiver.approver", waiver.approver)
    _validate_non_empty("waiver.expiration_date", waiver.expiration_date)
    _validate_non_empty("waiver.policy_id", waiver.policy_id)
    _validate_non_empty("waiver.resource", waiver.resource)

    # Validate violation required fields
    _validate_non_empty("violation.policy_id", violation.policy_id)
    _validate_non_empty("violation.message", violation.message)
    _validate_non_empty("violation.resource", violation.resource)
    _validate_non_empty("violation.severity", violation.severity)

    # Build the audit record
    timestamp = datetime.now(timezone.utc).isoformat()
    audit_record = {
        "waiver_id": waiver.waiver_id,
        "justification": waiver.justification,
        "approver": waiver.approver,
        "expiration_date": waiver.expiration_date,
        "violation": {
            "policy_id": violation.policy_id,
            "message": violation.message,
            "resource": violation.resource,
            "severity": violation.severity,
        },
        "timestamp": timestamp,
    }

    # Create the audit directory if it doesn't exist
    audit_dir = os.path.join(evidence_dir, "audit")
    os.makedirs(audit_dir, exist_ok=True)

    # Generate a unique filename using waiver_id and timestamp
    safe_timestamp = timestamp.replace(":", "-").replace("+", "p")
    filename = f"audit-{waiver.waiver_id}-{safe_timestamp}.json"
    filepath = os.path.join(audit_dir, filename)

    # Write the audit record as formatted JSON
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(audit_record, f, indent=2, ensure_ascii=False)

    return filepath


def _validate_non_empty(field_name: str, value: str) -> None:
    """Raise ValueError if value is None or an empty/whitespace-only string."""
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ValueError(f"Required field '{field_name}' must not be empty or missing")
