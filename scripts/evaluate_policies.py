"""
Policy Evaluation Module

Evaluates all OPA/Rego policies against aggregated scan results.
Evaluates ALL policies without short-circuiting, returning a complete
list of violations with human-readable messages.

Each violation includes:
- Policy identifier
- Human-readable explanation
- Offending resource name
- Severity level
- Regulatory references

This module provides Python-native policy evaluation that mirrors the Rego
policy logic defined in policies/opa/. It supports two evaluation modes:

1. SARIF-based evaluation: Parses aggregated SARIF results to identify
   findings that correspond to policy violations.
2. Resource-based evaluation: Evaluates directly against resource definitions
   (e.g., Terraform plan JSON with a "resources" array).
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from scripts.models import PolicyDecision, PolicyViolation


# Default regulatory references per policy, used when config/regulatory-mapping.json
# is not available.
_DEFAULT_REGULATORY_REFS: dict[str, list[str]] = {
    "no_unencrypted_storage": ["IFPE-ART58-DATA", "SOC2-CC6.1"],
    "no_wildcard_iam": ["IFPE-OPS-3", "SOC2-CC6.1", "SOC2-CC6.3"],
    "no_root_container": ["IFPE-OPS-5", "SOC2-CC6.1"],
    "no_open_security_group": ["IFPE-OPS-4", "SOC2-CC6.6"],
}

# Default severity per policy
_POLICY_SEVERITY: dict[str, str] = {
    "no_unencrypted_storage": "high",
    "no_wildcard_iam": "critical",
    "no_root_container": "high",
    "no_open_security_group": "critical",
}

# Patterns used to match SARIF findings to policies.
# Each entry maps a policy_id to a list of (rule_id_pattern, message_pattern) tuples.
# A finding matches if either its ruleId or message text matches any pattern.
_SARIF_POLICY_PATTERNS: dict[str, list[dict[str, str]]] = {
    "no_unencrypted_storage": [
        {"rule_pattern": r"\bCKV_AWS_19\b|\bCKV2_AWS_6\b"},
        {"message_pattern": r"(?i)(unencrypted\s+s3|s3.*not.*encrypt|bucket.*no.*encrypt|no.*server.side.encrypt)"},
    ],
    "no_wildcard_iam": [
        {"rule_pattern": r"\bCKV_AWS_1\b|\bCKV_AWS_62\b|\bCKV_AWS_63\b"},
        {"message_pattern": r"(?i)(wildcard.*action|action.*wildcard|\"\*\".*action|iam.*wildcard|full.*admin.*privilege)"},
    ],
    "no_root_container": [
        {"rule_pattern": r"\bCKV_DOCKER_3\b|\bCKV_DOCKER_8\b|\bCKV2_DOCKER_1\b"},
        {"message_pattern": r"(?i)(root\s*user|run.*as.*root|USER\s+root|no.*non-root|user\s*directive)"},
    ],
    "no_open_security_group": [
        {"rule_pattern": r"\bCKV_AWS_24\b|\bCKV2_AWS_5\b"},
        {"message_pattern": r"(?i)(ingress.*0\.0\.0\.0/0|0\.0\.0\.0/0.*ingress|unrestricted.*ingress|inbound.*0\.0\.0\.0)"},
    ],
}


def _load_regulatory_mapping(policies_dir: str) -> dict[str, list[str]]:
    """Load regulatory mapping from config file if available.

    Searches for regulatory-mapping.json in common locations relative to
    the policies directory:
    - ../config/regulatory-mapping.json
    - ../../config/regulatory-mapping.json
    - alongside the policies dir

    Returns the default mapping if no file is found.
    """
    search_paths = [
        os.path.join(policies_dir, "..", "config", "regulatory-mapping.json"),
        os.path.join(policies_dir, "..", "..", "config", "regulatory-mapping.json"),
        os.path.join(policies_dir, "regulatory-mapping.json"),
    ]

    for path in search_paths:
        abs_path = os.path.abspath(path)
        if os.path.isfile(abs_path):
            try:
                with open(abs_path, "r", encoding="utf-8") as f:
                    mapping_data = json.load(f)
                return _parse_regulatory_mapping(mapping_data)
            except (OSError, json.JSONDecodeError, KeyError):
                pass

    return _DEFAULT_REGULATORY_REFS


def _parse_regulatory_mapping(mapping_data: Any) -> dict[str, list[str]]:
    """Parse regulatory mapping JSON into policy_id -> refs dict."""
    result: dict[str, list[str]] = dict(_DEFAULT_REGULATORY_REFS)

    if isinstance(mapping_data, list):
        for entry in mapping_data:
            if not isinstance(entry, dict):
                continue
            pipeline_control = entry.get("pipeline_control", "")
            refs: list[str] = []
            if entry.get("cnbv_ifpe_ref"):
                refs.append(entry["cnbv_ifpe_ref"])
            if entry.get("soc2_tsc_ref"):
                refs.append(entry["soc2_tsc_ref"])
            if refs:
                # Extract policy_id from pipeline_control string
                for policy_id in _DEFAULT_REGULATORY_REFS:
                    if policy_id in pipeline_control.lower().replace("-", "_"):
                        result[policy_id] = refs
                        break

    return result


def _get_regulatory_refs(policy_id: str, reg_mapping: dict[str, list[str]]) -> list[str]:
    """Get regulatory references for a given policy."""
    return reg_mapping.get(policy_id, [])


def _extract_resource_from_sarif_finding(finding: dict) -> str:
    """Extract a resource name from a SARIF finding.

    Attempts to determine the resource name from locations, properties,
    or the message text.
    """
    # Try to get resource from properties
    props = finding.get("properties", {})
    if isinstance(props, dict):
        resource = props.get("resource", "") or props.get("resourceName", "")
        if resource:
            return resource

    # Try to extract from locations
    locations = finding.get("locations", [])
    if locations:
        loc = locations[0] if isinstance(locations[0], dict) else {}
        phys = loc.get("physicalLocation", {})
        artifact = phys.get("artifactLocation", {})
        uri = artifact.get("uri", "")
        if uri:
            return uri

    # Try to extract resource name from the message
    message = finding.get("message", {})
    text = message.get("text", "") if isinstance(message, dict) else ""
    if text:
        # Try patterns like "'resource_name'" or "resource 'name'"
        match = re.search(r"['\"]([^'\"]+)['\"]", text)
        if match:
            return match.group(1)
        # Fall back to first meaningful word after common prefixes
        return text[:80]

    return "unknown"


def _matches_policy(finding: dict, policy_id: str) -> bool:
    """Check if a SARIF finding matches a given policy's patterns."""
    patterns = _SARIF_POLICY_PATTERNS.get(policy_id, [])
    rule_id = finding.get("ruleId", "")
    message = finding.get("message", {})
    message_text = message.get("text", "") if isinstance(message, dict) else ""

    for pattern_set in patterns:
        if "rule_pattern" in pattern_set:
            if rule_id and re.search(pattern_set["rule_pattern"], rule_id):
                return True
        if "message_pattern" in pattern_set:
            if message_text and re.search(pattern_set["message_pattern"], message_text):
                return True

    return False


def _evaluate_sarif_findings(aggregated_sarif: dict, reg_mapping: dict[str, list[str]]) -> list[PolicyViolation]:
    """Evaluate aggregated SARIF results against all policy patterns.

    Iterates through all findings across all runs and checks each against
    every policy pattern. A single finding produces at most one violation
    per policy (deduplicated by policy_id + resource + ruleId).
    """
    violations: list[PolicyViolation] = []
    seen: set[tuple[str, str, str]] = set()  # (policy_id, resource, ruleId) for dedup

    runs = aggregated_sarif.get("runs", [])
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results", [])
        for finding in results:
            if not isinstance(finding, dict):
                continue

            for policy_id in _SARIF_POLICY_PATTERNS:
                if _matches_policy(finding, policy_id):
                    resource = _extract_resource_from_sarif_finding(finding)
                    dedup_key = (policy_id, resource, finding.get("ruleId", ""))
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        message_obj = finding.get("message", {})
                        finding_text = message_obj.get("text", "") if isinstance(message_obj, dict) else ""
                        violation_msg = (
                            f"{policy_id}: Resource '{resource}' - {finding_text}"
                            if finding_text
                            else f"{policy_id}: Resource '{resource}' has a policy violation"
                        )
                        violations.append(PolicyViolation(
                            policy_id=policy_id,
                            message=violation_msg,
                            resource=resource,
                            severity=_POLICY_SEVERITY.get(policy_id, "medium"),
                            regulatory_refs=_get_regulatory_refs(policy_id, reg_mapping),
                        ))

    return violations


def _evaluate_resources(resources: list[dict], reg_mapping: dict[str, list[str]]) -> list[PolicyViolation]:
    """Evaluate a list of resource definitions against all policies.

    This mirrors the Rego policy logic for the simplified resource format:
    [{"type": "...", "name": "...", "config": {...}}, ...]
    """
    violations: list[PolicyViolation] = []

    for resource in resources:
        if not isinstance(resource, dict):
            continue

        res_type = resource.get("type", "")
        res_name = resource.get("name", "unknown")
        config = resource.get("config", {})

        # no_unencrypted_storage: S3 buckets without encryption
        if res_type == "aws_s3_bucket":
            if not _has_encryption_config(config):
                violations.append(PolicyViolation(
                    policy_id="no_unencrypted_storage",
                    message=f"no_unencrypted_storage: S3 bucket '{res_name}' does not have server-side encryption configured",
                    resource=res_name,
                    severity=_POLICY_SEVERITY["no_unencrypted_storage"],
                    regulatory_refs=_get_regulatory_refs("no_unencrypted_storage", reg_mapping),
                ))

        # no_wildcard_iam: IAM policies with wildcard actions
        if res_type == "aws_iam_policy":
            policy_doc = config.get("policy", {})
            if isinstance(policy_doc, str):
                try:
                    policy_doc = json.loads(policy_doc)
                except (json.JSONDecodeError, TypeError):
                    policy_doc = {}
            statements = policy_doc.get("Statement", [])
            if not isinstance(statements, list):
                statements = [statements]
            for statement in statements:
                if not isinstance(statement, dict):
                    continue
                if statement.get("Effect") == "Allow" and _has_wildcard_action(statement):
                    violations.append(PolicyViolation(
                        policy_id="no_wildcard_iam",
                        message=f"no_wildcard_iam: IAM policy '{res_name}' contains wildcard (*) actions",
                        resource=res_name,
                        severity=_POLICY_SEVERITY["no_wildcard_iam"],
                        regulatory_refs=_get_regulatory_refs("no_wildcard_iam", reg_mapping),
                    ))
                    break  # One violation per resource

        # no_root_container: containers running as root
        if res_type in ("container", "dockerfile"):
            if not _has_non_root_user(config):
                if res_type == "container":
                    msg = f"no_root_container: Container '{res_name}' runs as root user"
                else:
                    msg = f"no_root_container: Container '{res_name}' does not specify a non-root USER directive"
                violations.append(PolicyViolation(
                    policy_id="no_root_container",
                    message=msg,
                    resource=res_name,
                    severity=_POLICY_SEVERITY["no_root_container"],
                    regulatory_refs=_get_regulatory_refs("no_root_container", reg_mapping),
                ))

        # no_open_security_group: security groups open to 0.0.0.0/0
        if res_type == "aws_security_group":
            ingress_rules = config.get("ingress", [])
            if not isinstance(ingress_rules, list):
                ingress_rules = [ingress_rules]
            for ingress in ingress_rules:
                if not isinstance(ingress, dict):
                    continue
                cidr_blocks = ingress.get("cidr_blocks", [])
                if not isinstance(cidr_blocks, list):
                    cidr_blocks = [cidr_blocks]
                if "0.0.0.0/0" in cidr_blocks:
                    violations.append(PolicyViolation(
                        policy_id="no_open_security_group",
                        message=f"no_open_security_group: Security group '{res_name}' allows ingress from 0.0.0.0/0",
                        resource=res_name,
                        severity=_POLICY_SEVERITY["no_open_security_group"],
                        regulatory_refs=_get_regulatory_refs("no_open_security_group", reg_mapping),
                    ))
                    break  # One violation per resource

        # no_open_security_group: security group rules
        if res_type == "aws_security_group_rule":
            if config.get("type") == "ingress":
                cidr_blocks = config.get("cidr_blocks", [])
                if not isinstance(cidr_blocks, list):
                    cidr_blocks = [cidr_blocks]
                if "0.0.0.0/0" in cidr_blocks:
                    violations.append(PolicyViolation(
                        policy_id="no_open_security_group",
                        message=f"no_open_security_group: Security group rule '{res_name}' allows ingress from 0.0.0.0/0",
                        resource=res_name,
                        severity=_POLICY_SEVERITY["no_open_security_group"],
                        regulatory_refs=_get_regulatory_refs("no_open_security_group", reg_mapping),
                    ))

    return violations


def _has_encryption_config(config: dict) -> bool:
    """Check if an S3 bucket config has encryption configured.

    Mirrors the Rego logic in no_unencrypted_storage.rego.
    """
    if not isinstance(config, dict):
        return False

    enc_config = config.get("server_side_encryption_configuration")
    if enc_config and (isinstance(enc_config, list) and len(enc_config) > 0 or isinstance(enc_config, dict)):
        return True

    if config.get("server_side_encryption_configuration_rule"):
        return True

    return False


def _has_wildcard_action(statement: dict) -> bool:
    """Check if an IAM policy statement has wildcard actions.

    Mirrors the Rego logic in no_wildcard_iam.rego.
    """
    action = statement.get("Action", "")
    if action == "*":
        return True
    if isinstance(action, list):
        return "*" in action
    return False


def _has_non_root_user(config: dict) -> bool:
    """Check if a container config specifies a non-root user.

    Mirrors the Rego logic in no_root_container.rego.
    """
    if not isinstance(config, dict):
        return False
    user = config.get("user")
    if not user:
        return False
    if user == "":
        return False
    if user in ("root", "0"):
        return False
    return True


def evaluate_policies(aggregated_sarif: dict, policies_dir: str) -> PolicyDecision:
    """
    Evaluates all Rego policies against aggregated scan results.

    Evaluates ALL policies (no short-circuit).
    Returns complete violation list.

    This function supports two input formats:
    1. Standard aggregated SARIF (from aggregate_sarif.py) - findings are
       matched against policy patterns based on rule IDs and message text.
    2. Resource-based input - if the input contains a "resources" key with
       a list of resource definitions, they are evaluated directly against
       the policy logic (mirroring the Rego simplified resource format).

    Args:
        aggregated_sarif: Aggregated SARIF dict from aggregate_sarif(), or a
            dict with a "resources" key for direct resource evaluation.
        policies_dir: Path to directory containing Rego policy files.
            Also used to locate config/regulatory-mapping.json.

    Returns:
        PolicyDecision with pass/fail status and all violations found.
    """
    # Load regulatory mapping
    reg_mapping = _load_regulatory_mapping(policies_dir)

    violations: list[PolicyViolation] = []

    # Mode 1: If input has "resources" key, evaluate directly against resource definitions
    resources = aggregated_sarif.get("resources")
    if isinstance(resources, list) and resources:
        violations.extend(_evaluate_resources(resources, reg_mapping))

    # Mode 2: If input has SARIF "runs", evaluate findings against policy patterns
    runs = aggregated_sarif.get("runs")
    if isinstance(runs, list) and runs:
        violations.extend(_evaluate_sarif_findings(aggregated_sarif, reg_mapping))

    # Determine pass/fail: passed only if no violations found
    passed = len(violations) == 0

    return PolicyDecision(
        passed=passed,
        violations=violations,
        waivers_applied=[],
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
