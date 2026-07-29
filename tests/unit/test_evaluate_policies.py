"""Unit tests for the policy evaluation module."""

import json
from pathlib import Path

import pytest

from scripts.evaluate_policies import (
    evaluate_policies,
    _has_encryption_config,
    _has_wildcard_action,
    _has_non_root_user,
    _matches_policy,
    _extract_resource_from_sarif_finding,
)
from scripts.models import PolicyDecision, PolicyViolation


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def policies_dir(tmp_path: Path) -> str:
    """Create a temporary policies directory."""
    d = tmp_path / "policies" / "opa"
    d.mkdir(parents=True)
    return str(d)


@pytest.fixture
def resource_all_violations() -> dict:
    """Input with one violation for each policy."""
    return {
        "resources": [
            {
                "type": "aws_s3_bucket",
                "name": "unencrypted-bucket",
                "config": {},
            },
            {
                "type": "aws_iam_policy",
                "name": "admin-policy",
                "config": {
                    "policy": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"}
                        ]
                    }
                },
            },
            {
                "type": "container",
                "name": "root-container",
                "config": {},
            },
            {
                "type": "aws_security_group",
                "name": "open-sg",
                "config": {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
            },
        ]
    }


@pytest.fixture
def resource_no_violations() -> dict:
    """Input with all resources compliant."""
    return {
        "resources": [
            {
                "type": "aws_s3_bucket",
                "name": "secure-bucket",
                "config": {
                    "server_side_encryption_configuration": [
                        {"rule": {"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}}
                    ]
                },
            },
            {
                "type": "aws_iam_policy",
                "name": "least-priv-policy",
                "config": {
                    "policy": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}
                        ]
                    }
                },
            },
            {
                "type": "container",
                "name": "secure-container",
                "config": {"user": "appuser"},
            },
            {
                "type": "aws_security_group",
                "name": "private-sg",
                "config": {"ingress": [{"cidr_blocks": ["10.0.0.0/16"]}]},
            },
        ]
    }


@pytest.fixture
def sarif_with_violations() -> dict:
    """Aggregated SARIF with findings matching all 4 policies."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "checkov", "version": "3.0.0", "rules": []}},
                "results": [
                    {
                        "ruleId": "CKV_AWS_19",
                        "level": "error",
                        "message": {"text": "S3 bucket does not have encryption enabled"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "main.tf"}, "region": {"startLine": 10}}}
                        ],
                    },
                    {
                        "ruleId": "CKV_AWS_1",
                        "level": "error",
                        "message": {"text": "IAM policy uses wildcard actions"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "main.tf"}, "region": {"startLine": 50}}}
                        ],
                    },
                    {
                        "ruleId": "CKV_AWS_24",
                        "level": "error",
                        "message": {"text": "Security group allows ingress from 0.0.0.0/0"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "main.tf"}, "region": {"startLine": 80}}}
                        ],
                    },
                ],
            },
            {
                "tool": {"driver": {"name": "trivy", "version": "0.50.0", "rules": []}},
                "results": [
                    {
                        "ruleId": "CKV_DOCKER_3",
                        "level": "warning",
                        "message": {"text": "Container runs as root user"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "Dockerfile"}, "region": {"startLine": 1}}}
                        ],
                    }
                ],
            },
        ],
    }


# ---------------------------------------------------------------------------
# Tests for evaluate_policies (main entry point)
# ---------------------------------------------------------------------------


class TestEvaluatePoliciesResourceMode:
    """Test policy evaluation with direct resource definitions."""

    def test_detects_all_violations(self, resource_all_violations: dict, policies_dir: str):
        result = evaluate_policies(resource_all_violations, policies_dir)
        assert result.passed is False
        assert len(result.violations) == 4
        policy_ids = {v.policy_id for v in result.violations}
        assert policy_ids == {
            "no_unencrypted_storage",
            "no_wildcard_iam",
            "no_root_container",
            "no_open_security_group",
        }

    def test_passes_with_no_violations(self, resource_no_violations: dict, policies_dir: str):
        result = evaluate_policies(resource_no_violations, policies_dir)
        assert result.passed is True
        assert len(result.violations) == 0

    def test_empty_resources_passes(self, policies_dir: str):
        result = evaluate_policies({"resources": []}, policies_dir)
        assert result.passed is True
        assert len(result.violations) == 0

    def test_violations_have_required_fields(self, resource_all_violations: dict, policies_dir: str):
        result = evaluate_policies(resource_all_violations, policies_dir)
        for v in result.violations:
            assert v.policy_id != ""
            assert v.message != ""
            assert v.resource != ""
            assert v.severity in ("critical", "high", "medium", "low")
            assert isinstance(v.regulatory_refs, list)
            assert len(v.regulatory_refs) > 0

    def test_violation_message_contains_policy_id_and_resource(
        self, resource_all_violations: dict, policies_dir: str
    ):
        """Req 3.2: human-readable explanation identifying violated policy and resource."""
        result = evaluate_policies(resource_all_violations, policies_dir)
        for v in result.violations:
            assert v.policy_id in v.message
            assert v.resource in v.message

    def test_evaluates_all_policies_no_short_circuit(self, policies_dir: str):
        """Req 3.5: evaluate all policies, never stopping at first failure."""
        # Multiple violations across different policies
        input_data = {
            "resources": [
                {"type": "aws_s3_bucket", "name": "bucket-1", "config": {}},
                {"type": "aws_s3_bucket", "name": "bucket-2", "config": {}},
                {"type": "aws_iam_policy", "name": "policy-1", "config": {"policy": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}},
            ]
        }
        result = evaluate_policies(input_data, policies_dir)
        assert len(result.violations) == 3  # 2 buckets + 1 IAM
        policy_ids = [v.policy_id for v in result.violations]
        assert policy_ids.count("no_unencrypted_storage") == 2
        assert policy_ids.count("no_wildcard_iam") == 1

    def test_timestamp_is_iso_format(self, resource_all_violations: dict, policies_dir: str):
        result = evaluate_policies(resource_all_violations, policies_dir)
        assert result.timestamp != ""
        # Should parse as ISO format (contains 'T' and timezone info)
        assert "T" in result.timestamp

    def test_waivers_applied_empty_by_default(self, resource_all_violations: dict, policies_dir: str):
        result = evaluate_policies(resource_all_violations, policies_dir)
        assert result.waivers_applied == []


class TestEvaluatePoliciesSarifMode:
    """Test policy evaluation with aggregated SARIF input."""

    def test_detects_violations_from_sarif(self, sarif_with_violations: dict, policies_dir: str):
        result = evaluate_policies(sarif_with_violations, policies_dir)
        assert result.passed is False
        assert len(result.violations) == 4
        policy_ids = {v.policy_id for v in result.violations}
        assert policy_ids == {
            "no_unencrypted_storage",
            "no_wildcard_iam",
            "no_root_container",
            "no_open_security_group",
        }

    def test_empty_sarif_passes(self, policies_dir: str):
        sarif = {"version": "2.1.0", "runs": []}
        result = evaluate_policies(sarif, policies_dir)
        assert result.passed is True
        assert len(result.violations) == 0

    def test_sarif_with_no_matching_findings_passes(self, policies_dir: str):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep", "version": "1.0.0", "rules": []}},
                    "results": [
                        {
                            "ruleId": "python.lang.correctness.useless-comparison",
                            "level": "warning",
                            "message": {"text": "Useless comparison"},
                            "locations": [],
                        }
                    ],
                }
            ],
        }
        result = evaluate_policies(sarif, policies_dir)
        assert result.passed is True
        assert len(result.violations) == 0

    def test_sarif_deduplicates_same_finding(self, policies_dir: str):
        """Same ruleId + resource should not produce duplicate violations."""
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "checkov", "version": "3.0.0", "rules": []}},
                    "results": [
                        {
                            "ruleId": "CKV_AWS_19",
                            "level": "error",
                            "message": {"text": "S3 bucket unencrypted"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "main.tf"}, "region": {"startLine": 5}}}],
                        },
                        {
                            "ruleId": "CKV_AWS_19",
                            "level": "error",
                            "message": {"text": "S3 bucket unencrypted"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "main.tf"}, "region": {"startLine": 5}}}],
                        },
                    ],
                }
            ],
        }
        result = evaluate_policies(sarif, policies_dir)
        # Same ruleId + same resource (file) = deduplicated to 1
        enc_violations = [v for v in result.violations if v.policy_id == "no_unencrypted_storage"]
        assert len(enc_violations) == 1


class TestEvaluatePoliciesMixedMode:
    """Test when input has both resources and SARIF runs."""

    def test_both_modes_evaluated(self, policies_dir: str):
        """If input has both resources and runs, both are evaluated."""
        input_data = {
            "resources": [
                {"type": "aws_s3_bucket", "name": "bucket-a", "config": {}},
            ],
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "checkov", "version": "3.0.0", "rules": []}},
                    "results": [
                        {
                            "ruleId": "CKV_AWS_24",
                            "level": "error",
                            "message": {"text": "Open security group"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "sg.tf"}, "region": {"startLine": 1}}}],
                        }
                    ],
                }
            ],
        }
        result = evaluate_policies(input_data, policies_dir)
        assert result.passed is False
        assert len(result.violations) == 2
        policy_ids = {v.policy_id for v in result.violations}
        assert "no_unencrypted_storage" in policy_ids
        assert "no_open_security_group" in policy_ids


# ---------------------------------------------------------------------------
# Tests for individual policy helpers
# ---------------------------------------------------------------------------


class TestHasEncryptionConfig:
    """Test S3 encryption detection logic."""

    def test_no_config(self):
        assert _has_encryption_config({}) is False

    def test_empty_encryption_list(self):
        assert _has_encryption_config({"server_side_encryption_configuration": []}) is False

    def test_valid_encryption_config(self):
        assert _has_encryption_config({"server_side_encryption_configuration": [{"rule": {}}]}) is True

    def test_encryption_config_as_dict(self):
        assert _has_encryption_config({"server_side_encryption_configuration": {"rule": {}}}) is True

    def test_encryption_config_rule_fallback(self):
        assert _has_encryption_config({"server_side_encryption_configuration_rule": True}) is True

    def test_non_dict_input(self):
        assert _has_encryption_config("not a dict") is False


class TestHasWildcardAction:
    """Test IAM wildcard action detection."""

    def test_string_wildcard(self):
        assert _has_wildcard_action({"Action": "*"}) is True

    def test_list_with_wildcard(self):
        assert _has_wildcard_action({"Action": ["s3:Get*", "*"]}) is True

    def test_no_wildcard_string(self):
        assert _has_wildcard_action({"Action": "s3:GetObject"}) is False

    def test_no_wildcard_list(self):
        assert _has_wildcard_action({"Action": ["s3:GetObject", "s3:PutObject"]}) is False

    def test_empty_action(self):
        assert _has_wildcard_action({"Action": ""}) is False

    def test_missing_action(self):
        assert _has_wildcard_action({}) is False


class TestHasNonRootUser:
    """Test container root user detection."""

    def test_no_user_field(self):
        assert _has_non_root_user({}) is False

    def test_empty_user(self):
        assert _has_non_root_user({"user": ""}) is False

    def test_root_user(self):
        assert _has_non_root_user({"user": "root"}) is False

    def test_uid_zero(self):
        assert _has_non_root_user({"user": "0"}) is False

    def test_valid_user(self):
        assert _has_non_root_user({"user": "appuser"}) is True

    def test_numeric_user(self):
        assert _has_non_root_user({"user": "1000"}) is True

    def test_none_user(self):
        assert _has_non_root_user({"user": None}) is False

    def test_non_dict_config(self):
        assert _has_non_root_user("not a dict") is False


class TestMatchesPolicy:
    """Test SARIF finding to policy matching."""

    def test_matches_by_rule_id(self):
        finding = {"ruleId": "CKV_AWS_19", "message": {"text": "some text"}}
        assert _matches_policy(finding, "no_unencrypted_storage") is True

    def test_matches_by_message_pattern(self):
        finding = {"ruleId": "custom_rule", "message": {"text": "S3 bucket has no encryption configured"}}
        assert _matches_policy(finding, "no_unencrypted_storage") is True

    def test_no_match(self):
        finding = {"ruleId": "unrelated_rule", "message": {"text": "unrelated issue"}}
        assert _matches_policy(finding, "no_unencrypted_storage") is False

    def test_wildcard_iam_by_rule(self):
        finding = {"ruleId": "CKV_AWS_62", "message": {"text": ""}}
        assert _matches_policy(finding, "no_wildcard_iam") is True

    def test_open_sg_by_message(self):
        finding = {"ruleId": "", "message": {"text": "allows ingress from 0.0.0.0/0"}}
        assert _matches_policy(finding, "no_open_security_group") is True

    def test_root_container_by_rule(self):
        finding = {"ruleId": "CKV_DOCKER_3", "message": {"text": ""}}
        assert _matches_policy(finding, "no_root_container") is True


class TestExtractResourceFromSarifFinding:
    """Test resource extraction from SARIF findings."""

    def test_from_location_uri(self):
        finding = {
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "iac/main.tf"}, "region": {"startLine": 10}}}
            ]
        }
        assert _extract_resource_from_sarif_finding(finding) == "iac/main.tf"

    def test_from_properties_resource(self):
        finding = {"properties": {"resource": "aws_s3_bucket.my_bucket"}, "locations": []}
        assert _extract_resource_from_sarif_finding(finding) == "aws_s3_bucket.my_bucket"

    def test_from_message_quoted(self):
        finding = {"message": {"text": "Resource 'my-bucket' is insecure"}, "locations": []}
        assert _extract_resource_from_sarif_finding(finding) == "my-bucket"

    def test_unknown_fallback(self):
        finding = {}
        assert _extract_resource_from_sarif_finding(finding) == "unknown"
