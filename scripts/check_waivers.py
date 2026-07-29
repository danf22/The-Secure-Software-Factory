"""
Waiver Checking Module

Validates and applies waivers to policy violations. A waiver is applied only if:
- Its policy_id matches the violation
- Its resource matches the violation's resource
- Its expiration_date is in the future
- All required fields are present (justification, approver, expiration_date, policy_id, resource)

Invariants:
- Expired waivers are never applied
- len(remaining_violations) + len(applied_waivers) == len(input_violations)
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime
from pathlib import Path

from scripts.models import PolicyViolation, Waiver
from scripts.validation import validate_waiver

logger = logging.getLogger(__name__)


def _load_waivers(waivers_dir: str) -> list[Waiver]:
    """Load and validate all waiver JSON files from the given directory.

    Skips files that:
    - Are not valid JSON
    - Fail schema validation (missing required fields, etc.)

    Args:
        waivers_dir: Path to directory containing waiver JSON files.

    Returns:
        List of valid Waiver objects.
    """
    waivers_path = Path(waivers_dir)
    waivers: list[Waiver] = []

    if not waivers_path.is_dir():
        logger.warning("Waivers directory does not exist: %s", waivers_dir)
        return waivers

    for file_path in sorted(waivers_path.glob("*.json")):
        try:
            with open(file_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Skipping malformed waiver file %s: %s", file_path.name, e)
            continue

        errors = validate_waiver(data)
        if errors:
            logger.warning(
                "Skipping invalid waiver file %s: %s", file_path.name, "; ".join(errors)
            )
            continue

        waiver = Waiver(
            waiver_id=data["waiver_id"],
            policy_id=data["policy_id"],
            resource=data["resource"],
            justification=data["justification"],
            approver=data["approver"],
            expiration_date=data["expiration_date"],
            created_at=data["created_at"],
        )
        waivers.append(waiver)

    return waivers


def _is_waiver_expired(waiver: Waiver) -> bool:
    """Check if a waiver's expiration_date is in the past.

    A waiver is expired if its expiration_date is before today's date.
    A waiver expiring today is still considered valid (not expired).

    Args:
        waiver: The waiver to check.

    Returns:
        True if expired, False if still valid.
    """
    try:
        expiration = date.fromisoformat(waiver.expiration_date)
    except (ValueError, TypeError):
        # If the date can't be parsed, treat as expired (fail-closed)
        logger.warning("Cannot parse expiration_date for waiver %s", waiver.waiver_id)
        return True

    return expiration < date.today()


def _matches_violation(waiver: Waiver, violation: PolicyViolation) -> bool:
    """Check if a waiver matches a specific violation by policy_id and resource.

    Args:
        waiver: The waiver to check.
        violation: The violation to match against.

    Returns:
        True if the waiver covers this violation.
    """
    return waiver.policy_id == violation.policy_id and waiver.resource == violation.resource


def check_waivers(
    violations: list[PolicyViolation], waivers_dir: str
) -> tuple[list[PolicyViolation], list[Waiver]]:
    """
    Checks if any active, non-expired waivers cover the given violations.

    For each violation, searches for a matching waiver where:
    - waiver.policy_id == violation.policy_id
    - waiver.resource == violation.resource
    - waiver.expiration_date is in the future (not expired)

    If a matching non-expired waiver is found, the violation is waived.

    Args:
        violations: List of policy violations to check against waivers.
        waivers_dir: Path to directory containing waiver JSON files.

    Returns:
        Tuple of (remaining_violations, applied_waivers) where:
        - remaining_violations: violations with no valid waiver
        - applied_waivers: waivers that were applied to cover violations

    Invariant: len(remaining_violations) + len(applied_waivers) == len(violations)
    """
    valid_waivers = _load_waivers(waivers_dir)

    # Filter out expired waivers upfront
    active_waivers = [w for w in valid_waivers if not _is_waiver_expired(w)]

    remaining_violations: list[PolicyViolation] = []
    applied_waivers: list[Waiver] = []

    for violation in violations:
        matched_waiver: Waiver | None = None
        for waiver in active_waivers:
            if _matches_violation(waiver, violation):
                matched_waiver = waiver
                break

        if matched_waiver is not None:
            applied_waivers.append(matched_waiver)
        else:
            remaining_violations.append(violation)

    # Verify invariant
    assert len(remaining_violations) + len(applied_waivers) == len(violations), (
        f"Invariant violated: {len(remaining_violations)} + {len(applied_waivers)} != {len(violations)}"
    )

    return remaining_violations, applied_waivers
