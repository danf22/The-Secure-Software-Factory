"""
Team Enforcement Module

Resolves the enforcement mode for a given team based on its configuration.
Each team's enforcement decision is independent of other teams.

Defaults:
- Missing team config → "warning" mode (fail-safe for new teams)
- Unknown team_id → "enforcing" mode (fail-closed for unknown origins)

Also validates that transition dates allow at least 5 business days of notice
before enforcement begins.
"""

from __future__ import annotations

import json
import os
from datetime import date, timedelta


def get_enforcement_mode(team_id: str, config_path: str) -> str:
    """
    Returns 'warning' or 'enforcing' for the given team.

    Loads the team configuration JSON from *config_path*, finds the entry
    whose ``team_id`` matches the provided *team_id*, and returns its
    ``enforcement_level``.

    The enforcement decision for a given team depends ONLY on that team's
    configuration (independent resolution).

    Args:
        team_id: Identifier of the team to check.
        config_path: Path to the team configuration JSON file
                     (must conform to team-config-schema.json).

    Returns:
        "warning" or "enforcing"

    Default behavior:
        - If config file doesn't exist or is malformed → "warning" (fail-safe).
        - If team_id is not found in config → "enforcing" (fail-closed for
          unknown origins).
    """
    # Fail-safe: if the config file cannot be read or parsed, default to "warning"
    if not os.path.isfile(config_path):
        return "warning"

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError):
        return "warning"

    # Validate minimal expected structure
    if not isinstance(config, dict) or "teams" not in config:
        return "warning"

    teams = config["teams"]
    if not isinstance(teams, list):
        return "warning"

    # Look up the team by team_id (independent resolution)
    for team in teams:
        if not isinstance(team, dict):
            continue
        if team.get("team_id") == team_id:
            level = team.get("enforcement_level")
            if level in ("warning", "enforcing"):
                return level
            # If enforcement_level is missing or invalid, treat as warning (fail-safe)
            return "warning"

    # Team not found → fail-closed for unknown origins
    return "enforcing"


def _count_business_days(start_date: date, end_date: date) -> int:
    """
    Count the number of business days (Monday–Friday) strictly between
    start_date (exclusive) and end_date (exclusive).

    This represents the number of full working days available for notice
    between the notification date and the transition date.

    If end_date <= start_date, returns 0.
    """
    if end_date <= start_date:
        return 0

    count = 0
    day = start_date + timedelta(days=1)
    while day < end_date:
        if day.weekday() < 5:  # Monday=0 ... Friday=4
            count += 1
        day += timedelta(days=1)

    return count


def validate_transition_date(
    transition_date: str, notification_date: str | None = None
) -> tuple[bool, str]:
    """
    Validate that a team's transition date allows at least 5 business days of notice.

    Args:
        transition_date: ISO 8601 date when enforcement begins (e.g., "2025-02-10")
        notification_date: ISO 8601 date when notification was/will be sent.
                         Defaults to today if not provided.

    Returns:
        (is_valid, message) — True if at least 5 business days between notification
        and transition, with a human-readable message explaining why.
    """
    # Parse transition_date
    try:
        t_date = date.fromisoformat(transition_date)
    except (ValueError, TypeError):
        return (
            False,
            f"Invalid: transition_date '{transition_date}' is not a valid ISO 8601 date",
        )

    # Parse or default notification_date
    if notification_date is None:
        n_date = date.today()
    else:
        try:
            n_date = date.fromisoformat(notification_date)
        except (ValueError, TypeError):
            return (
                False,
                f"Invalid: notification_date '{notification_date}' is not a valid ISO 8601 date",
            )

    # Check if transition date is in the past relative to notification date
    if t_date <= n_date:
        return (False, "Invalid: transition date is in the past")

    # Count business days between notification and transition
    business_days = _count_business_days(n_date, t_date)

    if business_days >= 5:
        return (True, f"Valid: {business_days} business days of notice")
    else:
        return (
            False,
            f"Invalid: only {business_days} business days before enforcement; minimum 5 required",
        )
