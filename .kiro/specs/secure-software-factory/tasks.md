# Implementation Plan: Secure Software Factory

## Overview

This plan implements the Secure Software Factory — a multi-layer DevSecOps pipeline using GitHub Actions with OSS tools (Gitleaks, Semgrep, Trivy, Checkov, OPA/Conftest, Syft, cosign). The implementation proceeds from foundational project structure through vulnerable seed creation, pipeline scanning, policy enforcement, supply chain evidence, rollout mechanisms, and documentation artifacts.

## Tasks

- [x] 1. Set up project structure and core interfaces
  - [x] 1.1 Create directory structure and Python project scaffolding
    - Create top-level directories: `vulnerable-app/`, `remediated-app/`, `iac/vulnerable/`, `iac/remediated/`, `policies/opa/`, `scripts/`, `waivers/`, `docs/`, `tests/`, `.github/workflows/`
    - Add `pyproject.toml` with pytest, hypothesis, and project dependencies
    - Add `requirements.txt` for the vulnerable seed app (include a dependency with a known CVE)
    - Create `scripts/__init__.py` and stub modules: `aggregate_sarif.py`, `check_waivers.py`, `evaluate_policies.py`, `enforcement.py`, `audit.py`, `report.py`
    - _Requirements: 1.1, 2.1_

  - [x] 1.2 Define core data models and interfaces
    - Implement Python dataclasses in `scripts/models.py`: `ScannerResult`, `PolicyViolation`, `PolicyDecision`, `Waiver`, `SupplyChainEvidence`, `TeamConfig`
    - Add JSON schema files in `schemas/`: `waiver-schema.json`, `team-config-schema.json`, `policy-decision-schema.json`, `regulatory-mapping-schema.json`
    - Implement validation functions for each schema using jsonschema
    - _Requirements: 3.2, 3.4, 9.2, 9.4, 10.2_

  - [x] 1.3 Set up testing framework
    - Configure `pytest.ini` or `pyproject.toml` [tool.pytest] section with markers for unit, property, and integration tests
    - Add `conftest.py` with shared fixtures and Hypothesis profiles (min 100 examples)
    - Create `tests/` subdirectories: `tests/unit/`, `tests/property/`, `tests/integration/`
    - _Requirements: Testing strategy_

- [x] 2. Implement vulnerable seed application
  - [x] 2.1 Create the vulnerable FastAPI microservice
    - Write `vulnerable-app/main.py` with FastAPI app containing: a hardcoded API key/secret in source, an SQL injection vulnerability in a query endpoint, and an insecure deserialization or command injection flaw
    - Add `vulnerable-app/requirements.txt` with at least one dependency having a known CVE (e.g., an older version of a library with published CVE)
    - _Requirements: 1.1_

  - [x] 2.2 Create the vulnerable Dockerfile
    - Write `vulnerable-app/Dockerfile` that runs the application as root user (`USER root` or no USER directive)
    - Use a base image with known vulnerabilities (e.g., older python image)
    - _Requirements: 1.2_

  - [x] 2.3 Create vulnerable Terraform definitions
    - Write `iac/vulnerable/main.tf` containing: an S3 bucket with `acl = "public-read"` and no encryption, an IAM policy with `"Action": "*"` wildcard, a security group with ingress `cidr_blocks = ["0.0.0.0/0"]`
    - Include provider and variable definitions for realism
    - _Requirements: 1.3_

  - [x] 2.4 Write unit tests for vulnerable seed validation
    - Verify hardcoded secret exists in `vulnerable-app/main.py`
    - Verify `requirements.txt` contains a dependency with a known CVE version
    - Verify Dockerfile has no non-root USER directive
    - Verify Terraform contains public S3 bucket, IAM wildcard, open security group
    - _Requirements: 1.1, 1.2, 1.3_

- [x] 3. Implement remediated application
  - [x] 3.1 Create the remediated FastAPI microservice
    - Write `remediated-app/main.py` with secrets loaded from environment variables, parameterized queries, and no injection flaws
    - Add `remediated-app/requirements.txt` with all dependencies at patched versions (no known CVEs)
    - _Requirements: 5.2, 5.4_

  - [x] 3.2 Create the remediated Dockerfile
    - Write `remediated-app/Dockerfile` with a non-root user, minimal base image, and security best practices
    - _Requirements: 5.2, 5.4_

  - [x] 3.3 Create remediated Terraform definitions
    - Write `iac/remediated/main.tf` with: encrypted S3 bucket with private ACL, least-privilege IAM policies, restricted security group CIDRs
    - _Requirements: 5.2, 5.4_

- [x] 4. Implement SARIF aggregation and regulatory tagging
  - [x] 4.1 Implement the SARIF aggregation script
    - Write `scripts/aggregate_sarif.py` with `aggregate_sarif(sarif_files: list[str]) -> dict` function
    - Merge all SARIF runs preserving tool identity, results, and locations
    - Ensure total findings in output equals sum of findings across inputs (no loss or duplication)
    - _Requirements: 2.4, 8.3_

  - [x] 4.2 Implement regulatory metadata tagging
    - Create `config/regulatory-mapping.json` mapping scanner rules to CNBV/IFPE and SOC 2 controls
    - Add logic in aggregator to attach `regulatory_refs` property to each finding based on the mapping
    - _Requirements: 8.1, 8.2, 8.3_

  - [x] 4.3 Write property test for SARIF aggregation (Property 5)
    - **Property 5: SARIF aggregation preserves findings and attaches regulatory metadata**
    - Use Hypothesis to generate random sets of valid SARIF files with 0-50 findings each
    - Assert: total findings in aggregated output == sum of findings across inputs
    - Assert: each finding has `regulatory_refs` metadata
    - **Validates: Requirements 8.3, 2.4**

  - [x] 4.4 Write unit tests for aggregation edge cases
    - Test empty SARIF file list, single file, files with zero findings
    - Test invalid SARIF files are skipped with warnings
    - _Requirements: 2.4_

- [x] 5. Implement policy-as-code gate
  - [x] 5.1 Write OPA/Rego policies
    - Create `policies/opa/no_unencrypted_storage.rego` — deny unencrypted S3 buckets
    - Create `policies/opa/no_wildcard_iam.rego` — deny IAM policies with `*` actions
    - Create `policies/opa/no_root_container.rego` — deny containers running as root
    - Create `policies/opa/no_open_security_group.rego` — deny security groups open to 0.0.0.0/0
    - _Requirements: 3.1, 3.3_

  - [x] 5.2 Implement the policy evaluation script
    - Write `scripts/evaluate_policies.py` with `evaluate_policies(aggregated_sarif: dict, policies_dir: str) -> PolicyDecision`
    - Evaluate ALL policies without short-circuiting
    - Return complete list of violations with human-readable messages, policy IDs, resource names, severity, and regulatory references
    - _Requirements: 3.1, 3.2, 3.5_

  - [x] 5.3 Write property test for policy violation detection (Property 1)
    - **Property 1: Policy gate detects violations and produces human-readable output**
    - Use Hypothesis to generate random Terraform plan JSON with/without violations
    - Assert: all violations are detected AND output contains policy identifier and resource name
    - **Validates: Requirements 3.1, 3.2**

  - [x] 5.4 Write property test for exhaustive evaluation (Property 2)
    - **Property 2: Exhaustive policy evaluation**
    - Use Hypothesis to generate random sets of 1-10 violations across policies
    - Assert: exactly N violations reported for N distinct violations (no suppression or duplication)
    - **Validates: Requirements 3.5**

- [x] 6. Implement waiver mechanism
  - [x] 6.1 Implement waiver checking logic
    - Write `scripts/check_waivers.py` with `check_waivers(violations, waivers_dir) -> tuple[list[PolicyViolation], list[Waiver]]`
    - Match waivers by policy_id AND resource
    - Only apply non-expired waivers (check expiration_date against current date)
    - Validate waiver schema completeness (require justification, approver, expiration_date, policy_id, resource)
    - Return remaining_violations and applied_waivers where len(remaining) + len(applied) == len(input)
    - _Requirements: 3.4, 9.4, 10.2_

  - [x] 6.2 Create sample waiver files
    - Add example waivers in `waivers/` directory as JSON files following the waiver schema
    - Include one valid active waiver and one expired waiver for demonstration
    - _Requirements: 3.4_

  - [x] 6.3 Write property test for waiver validity (Property 3)
    - **Property 3: Waiver validity determines gate passage**
    - Use Hypothesis to generate random waivers with valid/expired/mismatched fields
    - Assert: valid matching non-expired waivers allow passage; expired waivers block identically to no waiver
    - **Validates: Requirements 3.4, 9.4**

  - [x] 6.4 Write property test for waiver schema validation (Property 4)
    - **Property 4: Waiver schema validation rejects incomplete waivers**
    - Use Hypothesis to generate random waiver objects with selectively removed fields
    - Assert: waiver missing any required field is rejected and never applied
    - **Validates: Requirements 9.4**

- [x] 7. Checkpoint - Core logic verification
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Implement team enforcement and gradual rollout
  - [x] 8.1 Implement team enforcement module
    - Write `scripts/enforcement.py` with `get_enforcement_mode(team_id, config_path) -> str`
    - Return "warning" or "enforcing" based only on that team's config (independent resolution)
    - Default to "warning" for missing config, "enforcing" for unknown team_id
    - _Requirements: 9.1, 9.2_

  - [x] 8.2 Implement notification scheduling logic
    - Add function to validate transition dates allow 5 business days of notice
    - Flag invalid configurations where transition date doesn't allow sufficient notice
    - Account for weekends when counting business days
    - _Requirements: 9.3_

  - [x] 8.3 Create team configuration files
    - Write `config/teams.json` following team config schema with 5 example teams
    - Include teams at different enforcement levels for demonstration
    - _Requirements: 9.2_

  - [x] 8.4 Write property test for team enforcement mode (Property 6)
    - **Property 6: Team enforcement mode resolves independently**
    - Use Hypothesis to generate random team configs with mixed levels
    - Assert: enforcement decision depends only on that team's config; "warning" mode never blocks
    - **Validates: Requirements 9.1, 9.2**

  - [x] 8.5 Write property test for notification scheduling (Property 7)
    - **Property 7: Enforcement notification scheduling**
    - Use Hypothesis to generate random transition dates across weekdays/weekends/holidays
    - Assert: notification date is at least 5 business days before enforcement; invalid configs flagged
    - **Validates: Requirements 9.3**

- [x] 9. Implement audit trail and reporting
  - [x] 9.1 Implement audit trail recording
    - Write `scripts/audit.py` with functions to record waiver grants with justification, approver, expiration, and violation details
    - Store audit records as JSON in `evidence/audit/` directory
    - Ensure no required field is empty or missing in audit records
    - _Requirements: 10.1, 10.2_

  - [x] 9.2 Implement per-run summary report generation
    - Write `scripts/report.py` with function to generate a per-run summary linking commit SHA, all scan findings (with per-scanner counts), policy decisions, waivers, and build status
    - Validate that total_findings == sum of per-scanner counts
    - Output as JSON in `evidence/reports/` directory
    - _Requirements: 10.3_

  - [x] 9.3 Write property test for audit trail completeness (Property 8)
    - **Property 8: Audit trail completeness for waivers**
    - Use Hypothesis to generate random waiver grants with varying field content
    - Assert: audit record contains justification, approver, expiration, and violation details; no field empty
    - **Validates: Requirements 10.2**

  - [x] 9.4 Write property test for summary report completeness (Property 9)
    - **Property 9: Per-run summary report completeness**
    - Use Hypothesis to generate random pipeline runs with varying finding counts per scanner
    - Assert: report links commit SHA, all findings, decisions, waivers, and total == sum of per-scanner
    - **Validates: Requirements 10.3**

- [x] 10. Checkpoint - Policy and audit logic verification
  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. Implement GitHub Actions pipeline
  - [x] 11.1 Create the main security pipeline workflow
    - Write `.github/workflows/security-pipeline.yml` triggered on push
    - Define jobs for each scanner: `secrets-scan` (Gitleaks), `sast-scan` (Semgrep), `sca-scan` (Trivy fs), `iac-scan` (Checkov), `build-image`, `container-scan` (Trivy image)
    - Configure scanners to output SARIF format
    - Ensure each scanner job runs independently (use `continue-on-error` or independent jobs)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [x] 11.2 Add policy gate job to pipeline
    - Add `policy-gate` job that depends on all scanner jobs completing
    - Run SARIF aggregation, policy evaluation, and waiver checking
    - Integrate team enforcement mode (warning vs enforcing)
    - Fail the build or warn based on enforcement level and policy results
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 9.1_

  - [x] 11.3 Add supply chain evidence jobs
    - Add `sbom-generation` job using Syft after policy gate passes
    - Add `image-signing` job using cosign for keyless signing with OIDC
    - Add provenance attestation step
    - Upload SARIF, SBOM, signed image reference, and policy decisions as build artifacts with 2-year retention
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 10.1_

  - [x] 11.4 Add per-run summary report step
    - Add final job that generates the summary report JSON linking commit SHA, findings, decisions, and build status
    - Upload as build artifact
    - _Requirements: 10.3_

- [x] 12. Implement pre-commit hooks
  - [x] 12.1 Create pre-commit hook configuration
    - Write `.pre-commit-config.yaml` with Gitleaks and Semgrep hooks
    - Configure Semgrep to use a subset of rules for speed (<30s target)
    - Add installation script or Makefile target for developer setup
    - _Requirements: 11.1, 11.3_

  - [x] 12.2 Configure hook blocking behavior
    - Ensure Gitleaks hook blocks commits on secret detection with file and line output
    - Configure appropriate timeout (30s) for hook execution
    - Implement fail-open behavior for crashes/missing binaries (warn but allow commit)
    - _Requirements: 11.2, 11.3_

- [x] 13. Implement red/green demonstration
  - [x] 13.1 Create red demonstration workflow
    - Write `.github/workflows/red-demo.yml` that runs the pipeline against `vulnerable-app/` and `iac/vulnerable/`
    - Verify the policy gate fails and produces a report listing violations from each scanning layer (secrets, SAST, SCA, IaC, container)
    - Store the red-demo report as an artifact
    - _Requirements: 5.1, 5.3_

  - [x] 13.2 Create green demonstration workflow
    - Write `.github/workflows/green-demo.yml` that runs the pipeline against `remediated-app/` and `iac/remediated/`
    - Verify the policy gate passes and produces a compliance confirmation report
    - Store the green-demo report as an artifact
    - _Requirements: 5.2, 5.4_

  - [x] 13.3 Write integration tests for red/green outcomes
    - Test that red-demo workflow fails with at least one finding per scanner layer
    - Test that green-demo workflow passes with zero policy violations
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

- [x] 14. Checkpoint - Pipeline integration verification
  - Ensure all tests pass, ask the user if questions arise.

- [x] 15. Create documentation artifacts
  - [x] 15.1 Write the threat model document
    - Create `docs/threat-model.md` covering: supply-chain attacks on dependencies, compromised build environment, insider threats, external adversaries
    - Map each threat to the pipeline layer or control that mitigates it
    - Document residual risks for threats not fully mitigated
    - _Requirements: 6.1, 6.2, 6.3_

  - [x] 15.2 Write Architecture Decision Records
    - Create `docs/adr/` directory with ADR template
    - Write ADRs for: Gitleaks (secrets scanning), Semgrep (SAST), Trivy (SCA + container), Checkov (IaC), Syft (SBOM), cosign (signing)
    - Each ADR documents: context, decision, alternatives, trade-offs, false-positive strategy, OSS vs commercial justification
    - _Requirements: 7.1, 7.2, 7.3_

  - [x] 15.3 Write regulatory mapping documents
    - Create `docs/regulatory-mapping-cnbv-ifpe.md` linking pipeline controls to CNBV/IFPE requirements
    - Create `docs/regulatory-mapping-soc2.md` linking pipeline controls to SOC 2 Trust Services Criteria
    - _Requirements: 8.1, 8.2_

  - [x] 15.4 Write the comprehensive README
    - Create `README.md` with: architecture diagram (Mermaid), pipeline layer descriptions, red/green demo reproduction instructions, references to ADRs/threat model/regulatory mappings, cost estimation for production at scale
    - _Requirements: 12.1, 12.2, 12.3, 12.4_

- [x] 16. Final checkpoint - Full system verification
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation of core logic before building upon it
- Property tests validate universal correctness properties using Hypothesis with min 100 iterations
- Unit tests validate specific examples and edge cases
- The pipeline uses Python for all scripts/logic and GitHub Actions YAML for orchestration
- All scanner outputs use SARIF 2.1.0 format for consistency
- Supply chain evidence uses cosign keyless signing with GitHub OIDC

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2", "1.3"] },
    { "id": 1, "tasks": ["2.1", "2.2", "2.3", "3.1", "3.2", "3.3"] },
    { "id": 2, "tasks": ["2.4", "4.1", "5.1"] },
    { "id": 3, "tasks": ["4.2", "4.3", "4.4", "5.2"] },
    { "id": 4, "tasks": ["5.3", "5.4", "6.1", "6.2"] },
    { "id": 5, "tasks": ["6.3", "6.4", "8.1", "8.2", "8.3"] },
    { "id": 6, "tasks": ["8.4", "8.5", "9.1", "9.2"] },
    { "id": 7, "tasks": ["9.3", "9.4", "11.1"] },
    { "id": 8, "tasks": ["11.2", "11.3", "11.4", "12.1"] },
    { "id": 9, "tasks": ["12.2", "13.1", "13.2"] },
    { "id": 10, "tasks": ["13.3", "15.1", "15.2"] },
    { "id": 11, "tasks": ["15.3", "15.4"] }
  ]
}
```
