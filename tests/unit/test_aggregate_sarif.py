"""Unit tests for the SARIF aggregation module."""

import json
from pathlib import Path

import pytest

from scripts.aggregate_sarif import aggregate_sarif, _is_valid_sarif


@pytest.fixture
def sarif_gitleaks(tmp_path: Path) -> str:
    """Create a sample Gitleaks SARIF file."""
    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "gitleaks",
                        "version": "8.18.0",
                        "rules": [],
                    }
                },
                "results": [
                    {
                        "ruleId": "generic-api-key",
                        "level": "error",
                        "message": {"text": "Generic API key detected"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "main.py"},
                                    "region": {"startLine": 5},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    path = tmp_path / "gitleaks.sarif"
    path.write_text(json.dumps(doc))
    return str(path)


@pytest.fixture
def sarif_semgrep(tmp_path: Path) -> str:
    """Create a sample Semgrep SARIF file with two findings."""
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "semgrep",
                        "version": "1.50.0",
                        "rules": [],
                    }
                },
                "results": [
                    {
                        "ruleId": "python.lang.security.audit.exec-detected",
                        "level": "warning",
                        "message": {"text": "Use of exec detected"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"startLine": 12},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "python.lang.security.audit.sql-injection",
                        "level": "error",
                        "message": {"text": "SQL injection detected"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "db.py"},
                                    "region": {"startLine": 30},
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }
    path = tmp_path / "semgrep.sarif"
    path.write_text(json.dumps(doc))
    return str(path)


@pytest.fixture
def sarif_empty_results(tmp_path: Path) -> str:
    """Create a SARIF file with zero findings."""
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "trivy",
                        "version": "0.48.0",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }
    path = tmp_path / "trivy.sarif"
    path.write_text(json.dumps(doc))
    return str(path)


class TestIsValidSarif:
    """Tests for SARIF document validation."""

    def test_valid_sarif(self):
        doc = {"version": "2.1.0", "runs": []}
        assert _is_valid_sarif(doc) is True

    def test_invalid_version(self):
        doc = {"version": "1.0.0", "runs": []}
        assert _is_valid_sarif(doc) is False

    def test_missing_version(self):
        doc = {"runs": []}
        assert _is_valid_sarif(doc) is False

    def test_missing_runs(self):
        doc = {"version": "2.1.0"}
        assert _is_valid_sarif(doc) is False

    def test_runs_not_a_list(self):
        doc = {"version": "2.1.0", "runs": "invalid"}
        assert _is_valid_sarif(doc) is False

    def test_not_a_dict(self):
        assert _is_valid_sarif([]) is False
        assert _is_valid_sarif("string") is False
        assert _is_valid_sarif(None) is False


class TestAggregateSarif:
    """Tests for the aggregate_sarif function."""

    def test_empty_file_list(self):
        result = aggregate_sarif([])
        assert result["version"] == "2.1.0"
        assert result["runs"] == []

    def test_single_file(self, sarif_gitleaks: str):
        result = aggregate_sarif([sarif_gitleaks])
        assert result["version"] == "2.1.0"
        assert len(result["runs"]) == 1
        assert result["runs"][0]["tool"]["driver"]["name"] == "gitleaks"
        assert len(result["runs"][0]["results"]) == 1

    def test_multiple_files_preserves_tool_identity(
        self, sarif_gitleaks: str, sarif_semgrep: str
    ):
        result = aggregate_sarif([sarif_gitleaks, sarif_semgrep])
        assert len(result["runs"]) == 2
        tool_names = [r["tool"]["driver"]["name"] for r in result["runs"]]
        assert "gitleaks" in tool_names
        assert "semgrep" in tool_names

    def test_findings_count_preserved(
        self, sarif_gitleaks: str, sarif_semgrep: str
    ):
        """Invariant: total findings in output == sum of findings across inputs."""
        result = aggregate_sarif([sarif_gitleaks, sarif_semgrep])
        total_findings = sum(len(run["results"]) for run in result["runs"])
        # gitleaks has 1 finding, semgrep has 2
        assert total_findings == 3

    def test_zero_findings_file_included(
        self, sarif_gitleaks: str, sarif_empty_results: str
    ):
        result = aggregate_sarif([sarif_gitleaks, sarif_empty_results])
        assert len(result["runs"]) == 2
        total_findings = sum(len(run["results"]) for run in result["runs"])
        assert total_findings == 1

    def test_preserves_locations(self, sarif_gitleaks: str):
        result = aggregate_sarif([sarif_gitleaks])
        finding = result["runs"][0]["results"][0]
        location = finding["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "main.py"
        assert location["region"]["startLine"] == 5

    def test_invalid_json_file_skipped(self, tmp_path: Path, sarif_gitleaks: str):
        """Invalid JSON files are skipped with a warning."""
        bad_file = tmp_path / "bad.sarif"
        bad_file.write_text("not valid json {{{")
        result = aggregate_sarif([str(bad_file), sarif_gitleaks])
        assert len(result["runs"]) == 1
        assert result["runs"][0]["tool"]["driver"]["name"] == "gitleaks"

    def test_nonexistent_file_skipped(self, sarif_gitleaks: str):
        """Non-existent files are skipped with a warning."""
        result = aggregate_sarif(["/nonexistent/path.sarif", sarif_gitleaks])
        assert len(result["runs"]) == 1

    def test_invalid_sarif_version_skipped(
        self, tmp_path: Path, sarif_gitleaks: str
    ):
        """Files with wrong SARIF version are skipped."""
        bad_sarif = tmp_path / "old.sarif"
        bad_sarif.write_text(json.dumps({"version": "1.0.0", "runs": []}))
        result = aggregate_sarif([str(bad_sarif), sarif_gitleaks])
        assert len(result["runs"]) == 1

    def test_output_has_schema_field(self, sarif_gitleaks: str):
        result = aggregate_sarif([sarif_gitleaks])
        assert "$schema" in result
        assert "sarif-schema-2.1.0" in result["$schema"]

    def test_multiple_runs_in_single_file(self, tmp_path: Path):
        """A SARIF file with multiple runs should have all runs included."""
        doc = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "scanner-a", "version": "1.0.0", "rules": []}},
                    "results": [
                        {
                            "ruleId": "rule-1",
                            "level": "error",
                            "message": {"text": "Finding 1"},
                            "locations": [],
                        }
                    ],
                },
                {
                    "tool": {"driver": {"name": "scanner-b", "version": "2.0.0", "rules": []}},
                    "results": [
                        {
                            "ruleId": "rule-2",
                            "level": "warning",
                            "message": {"text": "Finding 2"},
                            "locations": [],
                        }
                    ],
                },
            ],
        }
        path = tmp_path / "multi_run.sarif"
        path.write_text(json.dumps(doc))
        result = aggregate_sarif([str(path)])
        assert len(result["runs"]) == 2
        total_findings = sum(len(run["results"]) for run in result["runs"])
        assert total_findings == 2
