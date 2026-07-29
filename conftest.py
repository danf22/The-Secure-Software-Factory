"""Root conftest.py — shared fixtures and Hypothesis profiles for the Secure Software Factory."""

import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from hypothesis import HealthCheck, Phase, settings

# ---------------------------------------------------------------------------
# Hypothesis profiles
# ---------------------------------------------------------------------------
# Default: 100 examples — fast developer feedback loop
settings.register_profile(
    "default",
    max_examples=100,
    suppress_health_check=[HealthCheck.too_slow],
    phases=[Phase.explicit, Phase.reuse, Phase.generate, Phase.shrink],
)

# CI: 500 examples — thorough verification in continuous integration
settings.register_profile(
    "ci",
    max_examples=500,
    suppress_health_check=[HealthCheck.too_slow],
    phases=[Phase.explicit, Phase.reuse, Phase.generate, Phase.shrink],
)

# Load profile from HYPOTHESIS_PROFILE env var; fall back to "default"
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "default"))


# ---------------------------------------------------------------------------
# Shared path fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def project_root() -> Path:
    """Return the absolute path to the project root directory."""
    return Path(__file__).resolve().parent


@pytest.fixture
def tests_dir(project_root: Path) -> Path:
    """Return the absolute path to the tests/ directory."""
    return project_root / "tests"


@pytest.fixture
def scripts_dir(project_root: Path) -> Path:
    """Return the absolute path to the scripts/ directory."""
    return project_root / "scripts"


@pytest.fixture
def policies_dir(project_root: Path) -> Path:
    """Return the absolute path to the policies/opa/ directory."""
    return project_root / "policies" / "opa"


@pytest.fixture
def waivers_dir(project_root: Path) -> Path:
    """Return the absolute path to the waivers/ directory."""
    return project_root / "waivers"


@pytest.fixture
def schemas_dir(project_root: Path) -> Path:
    """Return the absolute path to the schemas/ directory."""
    return project_root / "schemas"


# ---------------------------------------------------------------------------
# Shared data fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_sarif_minimal() -> dict:
    """Return a minimal valid SARIF 2.1.0 document with zero findings."""
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "test-scanner",
                        "version": "1.0.0",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }


@pytest.fixture
def sample_policy_violation() -> dict:
    """Return a sample policy violation dict matching PolicyViolation fields."""
    return {
        "policy_id": "no_wildcard_iam",
        "message": "IAM policy uses wildcard actions",
        "resource": "aws_iam_policy.admin",
        "severity": "critical",
        "regulatory_refs": ["IFPE-OPS-3", "SOC2-CC6.1"],
    }


@pytest.fixture
def sample_waiver_valid() -> dict:
    """Return a sample valid (non-expired) waiver dict."""
    future_date = (date.today() + timedelta(days=90)).isoformat()
    return {
        "waiver_id": "waiver-001",
        "policy_id": "no_wildcard_iam",
        "resource": "aws_iam_policy.admin",
        "justification": "Temporary admin access for migration",
        "approver": "security-lead@company.com",
        "expiration_date": future_date,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@pytest.fixture
def sample_waiver_expired() -> dict:
    """Return a sample expired waiver dict."""
    past_date = (date.today() - timedelta(days=30)).isoformat()
    return {
        "waiver_id": "waiver-expired-001",
        "policy_id": "no_wildcard_iam",
        "resource": "aws_iam_policy.admin",
        "justification": "Legacy access — expired",
        "approver": "security-lead@company.com",
        "expiration_date": past_date,
        "created_at": (datetime.now(timezone.utc) - timedelta(days=120)).isoformat(),
    }


@pytest.fixture
def sample_team_config() -> dict:
    """Return a sample team configuration dict."""
    return {
        "team_id": "swat-alpha",
        "name": "SWAT Alpha",
        "enforcement_level": "warning",
        "transition_date": (date.today() + timedelta(days=14)).isoformat(),
        "notified": True,
        "repositories": ["org/payments-api", "org/treasury-service"],
    }


@pytest.fixture
def tmp_waivers_dir(tmp_path: Path) -> Path:
    """Create and return a temporary waivers directory."""
    waivers = tmp_path / "waivers"
    waivers.mkdir()
    return waivers


@pytest.fixture
def tmp_evidence_dir(tmp_path: Path) -> Path:
    """Create and return a temporary evidence directory with subdirs."""
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "audit").mkdir()
    (evidence / "reports").mkdir()
    return evidence
