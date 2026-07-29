"""Unit tests for the waiver checking module."""

import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts.check_waivers import check_waivers, _is_waiver_expired, _matches_violation, _load_waivers
from scripts.models import PolicyViolation, Waiver


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def violation_wildcard_iam() -> PolicyViolation:
    return PolicyViolation(
        policy_id="no_wildcard_iam",
        message="IAM policy uses wildcard actions",
        resource="aws_iam_policy.admin",
        severity="critical",
        regulatory_refs=["IFPE-OPS-3", "SOC2-CC6.1"],
    )


@pytest.fixture
def violation_unencrypted_storage() -> PolicyViolation:
    return PolicyViolation(
        policy_id="no_unencrypted_storage",
        message="S3 bucket not encrypted",
        resource="aws_s3_bucket.data",
        severity="high",
        regulatory_refs=["IFPE-OPS-5"],
    )


@pytest.fixture
def valid_waiver_data() -> dict:
    future_date = (date.today() + timedelta(days=30)).isoformat()
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
def expired_waiver_data() -> dict:
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


def _write_waiver(waivers_dir: Path, filename: str, data: dict) -> None:
    """Write a waiver JSON file to the waivers directory."""
    with open(waivers_dir / filename, "w") as f:
        json.dump(data, f)


# ---------------------------------------------------------------------------
# Tests for check_waivers (main entry point)
# ---------------------------------------------------------------------------


class TestCheckWaivers:
    """Test the main check_waivers function."""

    def test_applies_valid_waiver(
        self, tmp_waivers_dir: Path, violation_wildcard_iam: PolicyViolation, valid_waiver_data: dict
    ):
        _write_waiver(tmp_waivers_dir, "waiver-001.json", valid_waiver_data)

        remaining, applied = check_waivers([violation_wildcard_iam], str(tmp_waivers_dir))

        assert len(remaining) == 0
        assert len(applied) == 1
        assert applied[0].waiver_id == "waiver-001"

    def test_does_not_apply_expired_waiver(
        self, tmp_waivers_dir: Path, violation_wildcard_iam: PolicyViolation, expired_waiver_data: dict
    ):
        _write_waiver(tmp_waivers_dir, "waiver-expired.json", expired_waiver_data)

        remaining, applied = check_waivers([violation_wildcard_iam], str(tmp_waivers_dir))

        assert len(remaining) == 1
        assert len(applied) == 0
        assert remaining[0] == violation_wildcard_iam

    def test_does_not_apply_mismatched_policy_id(
        self, tmp_waivers_dir: Path, violation_unencrypted_storage: PolicyViolation, valid_waiver_data: dict
    ):
        # waiver is for no_wildcard_iam, violation is for no_unencrypted_storage
        _write_waiver(tmp_waivers_dir, "waiver-001.json", valid_waiver_data)

        remaining, applied = check_waivers([violation_unencrypted_storage], str(tmp_waivers_dir))

        assert len(remaining) == 1
        assert len(applied) == 0

    def test_does_not_apply_mismatched_resource(
        self, tmp_waivers_dir: Path, valid_waiver_data: dict
    ):
        # Violation has different resource than waiver
        violation = PolicyViolation(
            policy_id="no_wildcard_iam",
            message="IAM wildcard",
            resource="aws_iam_policy.different_resource",
            severity="critical",
        )
        _write_waiver(tmp_waivers_dir, "waiver-001.json", valid_waiver_data)

        remaining, applied = check_waivers([violation], str(tmp_waivers_dir))

        assert len(remaining) == 1
        assert len(applied) == 0

    def test_invariant_lengths(
        self, tmp_waivers_dir: Path, violation_wildcard_iam: PolicyViolation,
        violation_unencrypted_storage: PolicyViolation, valid_waiver_data: dict
    ):
        """Invariant: len(remaining) + len(applied) == len(input)."""
        _write_waiver(tmp_waivers_dir, "waiver-001.json", valid_waiver_data)
        violations = [violation_wildcard_iam, violation_unencrypted_storage]

        remaining, applied = check_waivers(violations, str(tmp_waivers_dir))

        assert len(remaining) + len(applied) == len(violations)

    def test_empty_violations_list(self, tmp_waivers_dir: Path, valid_waiver_data: dict):
        _write_waiver(tmp_waivers_dir, "waiver-001.json", valid_waiver_data)

        remaining, applied = check_waivers([], str(tmp_waivers_dir))

        assert len(remaining) == 0
        assert len(applied) == 0

    def test_empty_waivers_dir(self, tmp_waivers_dir: Path, violation_wildcard_iam: PolicyViolation):
        remaining, applied = check_waivers([violation_wildcard_iam], str(tmp_waivers_dir))

        assert len(remaining) == 1
        assert len(applied) == 0

    def test_nonexistent_waivers_dir(self, tmp_path: Path, violation_wildcard_iam: PolicyViolation):
        remaining, applied = check_waivers(
            [violation_wildcard_iam], str(tmp_path / "nonexistent")
        )

        assert len(remaining) == 1
        assert len(applied) == 0

    def test_skips_malformed_json_file(
        self, tmp_waivers_dir: Path, violation_wildcard_iam: PolicyViolation, valid_waiver_data: dict
    ):
        # Write a valid waiver
        _write_waiver(tmp_waivers_dir, "valid.json", valid_waiver_data)
        # Write a malformed JSON file
        (tmp_waivers_dir / "broken.json").write_text("{not valid json")

        remaining, applied = check_waivers([violation_wildcard_iam], str(tmp_waivers_dir))

        assert len(remaining) == 0
        assert len(applied) == 1

    def test_skips_waiver_missing_required_fields(
        self, tmp_waivers_dir: Path, violation_wildcard_iam: PolicyViolation, valid_waiver_data: dict
    ):
        # Write a valid waiver
        _write_waiver(tmp_waivers_dir, "valid.json", valid_waiver_data)
        # Write an incomplete waiver (missing justification)
        incomplete = {
            "waiver_id": "waiver-incomplete",
            "policy_id": "no_wildcard_iam",
            "resource": "aws_iam_policy.admin",
            # missing: justification, approver, expiration_date, created_at
        }
        _write_waiver(tmp_waivers_dir, "incomplete.json", incomplete)

        remaining, applied = check_waivers([violation_wildcard_iam], str(tmp_waivers_dir))

        # Should still apply the valid waiver
        assert len(remaining) == 0
        assert len(applied) == 1
        assert applied[0].waiver_id == "waiver-001"

    def test_multiple_violations_partial_waivers(self, tmp_waivers_dir: Path, valid_waiver_data: dict):
        """Only violations with matching waivers are removed."""
        v1 = PolicyViolation(
            policy_id="no_wildcard_iam",
            message="IAM wildcard",
            resource="aws_iam_policy.admin",
            severity="critical",
        )
        v2 = PolicyViolation(
            policy_id="no_unencrypted_storage",
            message="Unencrypted bucket",
            resource="aws_s3_bucket.data",
            severity="high",
        )
        v3 = PolicyViolation(
            policy_id="no_root_container",
            message="Root container",
            resource="container.app",
            severity="medium",
        )
        _write_waiver(tmp_waivers_dir, "waiver-001.json", valid_waiver_data)

        remaining, applied = check_waivers([v1, v2, v3], str(tmp_waivers_dir))

        assert len(applied) == 1
        assert len(remaining) == 2
        assert v1 not in remaining
        assert v2 in remaining
        assert v3 in remaining


# ---------------------------------------------------------------------------
# Tests for _is_waiver_expired
# ---------------------------------------------------------------------------


class TestIsWaiverExpired:
    def test_future_date_not_expired(self):
        waiver = Waiver(
            waiver_id="w1", policy_id="p1", justification="j", approver="a",
            expiration_date=(date.today() + timedelta(days=10)).isoformat(),
            resource="r", created_at=datetime.now(timezone.utc).isoformat(),
        )
        assert _is_waiver_expired(waiver) is False

    def test_past_date_expired(self):
        waiver = Waiver(
            waiver_id="w1", policy_id="p1", justification="j", approver="a",
            expiration_date=(date.today() - timedelta(days=1)).isoformat(),
            resource="r", created_at=datetime.now(timezone.utc).isoformat(),
        )
        assert _is_waiver_expired(waiver) is True

    def test_today_not_expired(self):
        waiver = Waiver(
            waiver_id="w1", policy_id="p1", justification="j", approver="a",
            expiration_date=date.today().isoformat(),
            resource="r", created_at=datetime.now(timezone.utc).isoformat(),
        )
        assert _is_waiver_expired(waiver) is False

    def test_invalid_date_treated_as_expired(self):
        waiver = Waiver(
            waiver_id="w1", policy_id="p1", justification="j", approver="a",
            expiration_date="not-a-date",
            resource="r", created_at=datetime.now(timezone.utc).isoformat(),
        )
        assert _is_waiver_expired(waiver) is True


# ---------------------------------------------------------------------------
# Tests for _matches_violation
# ---------------------------------------------------------------------------


class TestMatchesViolation:
    def test_exact_match(self):
        waiver = Waiver(
            waiver_id="w1", policy_id="no_wildcard_iam", justification="j", approver="a",
            expiration_date="2099-01-01", resource="aws_iam_policy.admin",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        violation = PolicyViolation(
            policy_id="no_wildcard_iam", message="msg", resource="aws_iam_policy.admin", severity="high"
        )
        assert _matches_violation(waiver, violation) is True

    def test_policy_id_mismatch(self):
        waiver = Waiver(
            waiver_id="w1", policy_id="no_wildcard_iam", justification="j", approver="a",
            expiration_date="2099-01-01", resource="aws_iam_policy.admin",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        violation = PolicyViolation(
            policy_id="no_unencrypted_storage", message="msg", resource="aws_iam_policy.admin", severity="high"
        )
        assert _matches_violation(waiver, violation) is False

    def test_resource_mismatch(self):
        waiver = Waiver(
            waiver_id="w1", policy_id="no_wildcard_iam", justification="j", approver="a",
            expiration_date="2099-01-01", resource="aws_iam_policy.admin",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        violation = PolicyViolation(
            policy_id="no_wildcard_iam", message="msg", resource="aws_iam_policy.other", severity="high"
        )
        assert _matches_violation(waiver, violation) is False
