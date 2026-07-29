"""Schema validation functions for the Secure Software Factory.

Provides validation against JSON schemas for waivers, team configurations,
policy decisions, and regulatory mappings using the jsonschema library.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
from jsonschema import Draft7Validator, ValidationError

# Base path for schema files
SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"


def _load_schema(schema_filename: str) -> dict[str, Any]:
    """Load a JSON schema file from the schemas directory."""
    schema_path = SCHEMAS_DIR / schema_filename
    with open(schema_path) as f:
        return json.load(f)


def validate_waiver(data: dict[str, Any]) -> list[str]:
    """Validate a waiver object against the waiver schema.

    Args:
        data: Dictionary representing a waiver.

    Returns:
        List of validation error messages. Empty list if valid.
    """
    schema = _load_schema("waiver-schema.json")
    return _validate_against_schema(data, schema)


def validate_team_config(data: dict[str, Any]) -> list[str]:
    """Validate a team configuration object against the team config schema.

    Args:
        data: Dictionary representing team configuration (with 'teams' key).

    Returns:
        List of validation error messages. Empty list if valid.
    """
    schema = _load_schema("team-config-schema.json")
    return _validate_against_schema(data, schema)


def validate_policy_decision(data: dict[str, Any]) -> list[str]:
    """Validate a policy decision record against the policy decision schema.

    Args:
        data: Dictionary representing a policy decision record.

    Returns:
        List of validation error messages. Empty list if valid.
    """
    schema = _load_schema("policy-decision-schema.json")
    return _validate_against_schema(data, schema)


def validate_regulatory_mapping(data: dict[str, Any]) -> list[str]:
    """Validate a regulatory mapping object against the regulatory mapping schema.

    Args:
        data: Dictionary representing regulatory mappings (with 'mappings' key).

    Returns:
        List of validation error messages. Empty list if valid.
    """
    schema = _load_schema("regulatory-mapping-schema.json")
    return _validate_against_schema(data, schema)


def _validate_against_schema(data: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    """Validate data against a JSON schema and return all errors.

    Args:
        data: The data to validate.
        schema: The JSON schema to validate against.

    Returns:
        List of human-readable error messages. Empty if valid.
    """
    validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    return [_format_error(error) for error in errors]


def _format_error(error: ValidationError) -> str:
    """Format a validation error into a human-readable string."""
    path = ".".join(str(p) for p in error.absolute_path)
    if path:
        return f"{path}: {error.message}"
    return error.message


def is_valid_waiver(data: dict[str, Any]) -> bool:
    """Check if a waiver object is valid (convenience boolean check)."""
    return len(validate_waiver(data)) == 0


def is_valid_team_config(data: dict[str, Any]) -> bool:
    """Check if a team config object is valid (convenience boolean check)."""
    return len(validate_team_config(data)) == 0


def is_valid_policy_decision(data: dict[str, Any]) -> bool:
    """Check if a policy decision record is valid (convenience boolean check)."""
    return len(validate_policy_decision(data)) == 0


def is_valid_regulatory_mapping(data: dict[str, Any]) -> bool:
    """Check if a regulatory mapping object is valid (convenience boolean check)."""
    return len(validate_regulatory_mapping(data)) == 0
