"""Unit tests for the per-run summary report generation."""

import json
import os
import tempfile

import pytest

from scripts.models import PolicyDecision, PolicyViolation, Waiver
from scripts.report import generate_summary_report


class TestGenerateSummaryReport:
    """Tests for generate_summary_report function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.commit_sha = "abc123def456789"
        self.findings_by_scanner = {
            "gitleaks": 2,
            "semgrep": 3,
            "trivy_fs": 1,
            "checkov": 0,
            "trivy_image": 4,
        }
        self.policy_decision = PolicyDecision(
            passed=False,
            violations=[
                PolicyViolation(
                    policy_id="no_wildcard_iam",
                    message="IAM policy uses wildcard actions",
                    resource="aws_iam_policy.admin",
                    severity="critical",
                    regulatory_refs=["IFPE-OPS-3", "SOC2-CC6.1"],
                )
            ],
            waivers_applied=["waiver-001"],
            timestamp="2025-01-15T10:00:00Z",
        )
        self.applied_waivers = [
            Waiver(
                waiver_id="waiver-001",
                policy_id="no_wildcard_iam",
                justification="Temporary admin access for migration",
                approver="security-lead@company.com",
                expiration_date="2025-03-01",
                resource="aws_iam_policy.admin",
                created_at="2025-01-10T09:00:00Z",
            )
        ]
        self.build_status = "failed"

    def test_creates_report_file(self, tmp_path):
        """Report file is created in evidence_dir/reports/."""
        report_path = generate_summary_report(
            commit_sha=self.commit_sha,
            findings_by_scanner=self.findings_by_scanner,
            policy_decision=self.policy_decision,
            applied_waivers=self.applied_waivers,
            build_status=self.build_status,
            evidence_dir=str(tmp_path),
        )

        assert os.path.exists(report_path)
        assert "reports" in report_path
        assert report_path.startswith(str(tmp_path))

    def test_report_contains_commit_sha(self, tmp_path):
        """Report JSON contains the commit SHA."""
        report_path = generate_summary_report(
            commit_sha=self.commit_sha,
            findings_by_scanner=self.findings_by_scanner,
            policy_decision=self.policy_decision,
            applied_waivers=self.applied_waivers,
            build_status=self.build_status,
            evidence_dir=str(tmp_path),
        )

        with open(report_path) as f:
            report = json.load(f)

        assert report["commit_sha"] == self.commit_sha

    def test_report_total_findings_equals_sum(self, tmp_path):
        """total_findings equals sum of per-scanner counts."""
        report_path = generate_summary_report(
            commit_sha=self.commit_sha,
            findings_by_scanner=self.findings_by_scanner,
            policy_decision=self.policy_decision,
            applied_waivers=self.applied_waivers,
            build_status=self.build_status,
            evidence_dir=str(tmp_path),
        )

        with open(report_path) as f:
            report = json.load(f)

        expected_total = sum(self.findings_by_scanner.values())
        assert report["scan_summary"]["total_findings"] == expected_total
        assert report["scan_summary"]["total_findings"] == sum(
            report["scan_summary"]["by_scanner"].values()
        )

    def test_report_contains_policy_decision(self, tmp_path):
        """Report includes policy decision with violations."""
        report_path = generate_summary_report(
            commit_sha=self.commit_sha,
            findings_by_scanner=self.findings_by_scanner,
            policy_decision=self.policy_decision,
            applied_waivers=self.applied_waivers,
            build_status=self.build_status,
            evidence_dir=str(tmp_path),
        )

        with open(report_path) as f:
            report = json.load(f)

        assert report["passed"] is False
        assert len(report["violations"]) == 1
        assert report["violations"][0]["policy_id"] == "no_wildcard_iam"
        assert report["violations"][0]["severity"] == "critical"
        assert "IFPE-OPS-3" in report["violations"][0]["regulatory_refs"]

    def test_report_contains_waivers(self, tmp_path):
        """Report includes applied waivers."""
        report_path = generate_summary_report(
            commit_sha=self.commit_sha,
            findings_by_scanner=self.findings_by_scanner,
            policy_decision=self.policy_decision,
            applied_waivers=self.applied_waivers,
            build_status=self.build_status,
            evidence_dir=str(tmp_path),
        )

        with open(report_path) as f:
            report = json.load(f)

        assert len(report["waivers_applied"]) == 1
        assert report["waivers_applied"][0]["waiver_id"] == "waiver-001"
        assert report["waivers_applied"][0]["approver"] == "security-lead@company.com"

    def test_report_contains_build_status(self, tmp_path):
        """Report includes build status."""
        report_path = generate_summary_report(
            commit_sha=self.commit_sha,
            findings_by_scanner=self.findings_by_scanner,
            policy_decision=self.policy_decision,
            applied_waivers=self.applied_waivers,
            build_status=self.build_status,
            evidence_dir=str(tmp_path),
        )

        with open(report_path) as f:
            report = json.load(f)

        assert report["build_status"] == "failed"

    def test_report_contains_timestamp_and_decision_id(self, tmp_path):
        """Report includes a timestamp and decision_id."""
        report_path = generate_summary_report(
            commit_sha=self.commit_sha,
            findings_by_scanner=self.findings_by_scanner,
            policy_decision=self.policy_decision,
            applied_waivers=self.applied_waivers,
            build_status=self.build_status,
            evidence_dir=str(tmp_path),
        )

        with open(report_path) as f:
            report = json.load(f)

        assert "timestamp" in report
        assert "decision_id" in report
        assert len(report["decision_id"]) == 36  # UUID format

    def test_invalid_build_status_raises(self, tmp_path):
        """Invalid build_status raises ValueError."""
        with pytest.raises(ValueError, match="build_status must be"):
            generate_summary_report(
                commit_sha=self.commit_sha,
                findings_by_scanner=self.findings_by_scanner,
                policy_decision=self.policy_decision,
                applied_waivers=self.applied_waivers,
                build_status="unknown",
                evidence_dir=str(tmp_path),
            )

    def test_empty_findings(self, tmp_path):
        """Report handles empty findings correctly."""
        report_path = generate_summary_report(
            commit_sha=self.commit_sha,
            findings_by_scanner={},
            policy_decision=PolicyDecision(passed=True),
            applied_waivers=[],
            build_status="passed",
            evidence_dir=str(tmp_path),
        )

        with open(report_path) as f:
            report = json.load(f)

        assert report["scan_summary"]["total_findings"] == 0
        assert report["scan_summary"]["by_scanner"] == {}
        assert report["passed"] is True

    def test_filename_contains_short_sha(self, tmp_path):
        """Report filename includes truncated commit SHA."""
        report_path = generate_summary_report(
            commit_sha=self.commit_sha,
            findings_by_scanner=self.findings_by_scanner,
            policy_decision=self.policy_decision,
            applied_waivers=self.applied_waivers,
            build_status=self.build_status,
            evidence_dir=str(tmp_path),
        )

        filename = os.path.basename(report_path)
        assert filename.startswith(f"report-{self.commit_sha[:8]}")
        assert filename.endswith(".json")

    def test_creates_reports_directory(self, tmp_path):
        """Reports directory is created if it doesn't exist."""
        evidence_dir = str(tmp_path / "nested" / "evidence")
        report_path = generate_summary_report(
            commit_sha=self.commit_sha,
            findings_by_scanner=self.findings_by_scanner,
            policy_decision=self.policy_decision,
            applied_waivers=self.applied_waivers,
            build_status=self.build_status,
            evidence_dir=evidence_dir,
        )

        assert os.path.isdir(os.path.join(evidence_dir, "reports"))
        assert os.path.exists(report_path)
