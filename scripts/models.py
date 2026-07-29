"""Core data models for the Secure Software Factory pipeline.

Defines dataclasses for scanner results, policy decisions, waivers,
supply chain evidence, and team configuration used across all pipeline scripts.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScannerResult:
    """Represents the output metadata from a single scanner execution."""

    tool_name: str  # e.g., "gitleaks", "semgrep", "trivy", "checkov"
    sarif_path: str  # path to the SARIF file
    findings_count: int  # number of findings detected
    exit_code: int  # 0 = no findings, 1 = findings detected, 2 = error


@dataclass
class PolicyViolation:
    """A single policy violation detected by the policy gate."""

    policy_id: str  # e.g., "no_wildcard_iam"
    message: str  # human-readable explanation
    resource: str  # offending resource identifier
    severity: str  # "critical", "high", "medium", "low"
    regulatory_refs: list[str] = field(default_factory=list)  # e.g., ["IFPE-OPS-3", "SOC2-CC6.1"]


@dataclass
class PolicyDecision:
    """The aggregate decision from the policy gate for a pipeline run."""

    passed: bool
    violations: list[PolicyViolation] = field(default_factory=list)
    waivers_applied: list[str] = field(default_factory=list)  # waiver IDs that allowed violations
    timestamp: str = ""  # ISO 8601


@dataclass
class Waiver:
    """A time-bound exception allowing a policy violation to pass the gate."""

    waiver_id: str
    policy_id: str
    justification: str
    approver: str
    expiration_date: str  # ISO 8601 date
    resource: str  # resource this waiver applies to
    created_at: str  # ISO 8601


@dataclass
class SupplyChainEvidence:
    """Evidence artifacts generated during the supply chain phase."""

    sbom_path: str  # path to SPDX JSON SBOM
    image_digest: str  # sha256 digest of signed image
    signature_ref: str  # cosign signature reference
    provenance: dict = field(default_factory=dict)  # SLSA provenance attestation content
    source_repo: str = ""
    commit_sha: str = ""
    workflow_run_id: str = ""


@dataclass
class TeamConfig:
    """Per-team enforcement configuration for phased rollout."""

    team_id: str
    enforcement_level: str  # "warning" | "enforcing"
    transition_date: str | None = None  # when enforcement begins (ISO 8601)
    notified: bool = False  # whether 5-day notice was sent
