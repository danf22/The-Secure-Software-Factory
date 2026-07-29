"""
SARIF Aggregation Module

Combines multiple SARIF 2.1.0 files from individual scanners into a single
aggregated report, preserving tool identity, results, and locations.

Invariant: total findings in output == sum of findings across inputs
"""

from __future__ import annotations

import json
import sys
from typing import Any


def _is_valid_sarif(data: Any) -> bool:
    """Check if a parsed JSON object is a valid SARIF 2.1.0 document.

    A valid SARIF document must have:
    - "version" field equal to "2.1.0"
    - "runs" field that is a list
    """
    if not isinstance(data, dict):
        return False
    if data.get("version") != "2.1.0":
        return False
    if not isinstance(data.get("runs"), list):
        return False
    return True


def _load_regulatory_mapping(mapping_path: str) -> dict:
    """Load the regulatory mapping JSON file.

    Args:
        mapping_path: Path to the regulatory-mapping.json file

    Returns:
        Parsed mapping dict with 'rule_mappings' and 'default_refs' keys,
        or an empty structure if loading fails.
    """
    try:
        with open(mapping_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"WARNING: Could not load regulatory mapping '{mapping_path}': {exc}",
            file=sys.stderr,
        )
        return {"rule_mappings": {}, "default_refs": {}}

    if not isinstance(data, dict):
        return {"rule_mappings": {}, "default_refs": {}}

    return {
        "rule_mappings": data.get("rule_mappings", {}),
        "default_refs": data.get("default_refs", {}),
    }


def _get_scanner_name(run: dict) -> str:
    """Extract the scanner/tool name from a SARIF run object.

    Returns lowercase tool name or empty string if not found.
    """
    try:
        return run["tool"]["driver"]["name"].lower()
    except (KeyError, TypeError, AttributeError):
        return ""


def _attach_regulatory_refs(aggregated: dict, mapping: dict) -> None:
    """Attach regulatory_refs to each finding based on the mapping.

    For each result in each run:
    - If the result's ruleId has an explicit entry in rule_mappings, use those refs
    - Otherwise, fall back to the scanner's default_refs
    - Refs are added to result['properties']['regulatory_refs']

    Modifies the aggregated dict in place.
    """
    rule_mappings = mapping.get("rule_mappings", {})
    default_refs = mapping.get("default_refs", {})

    for run in aggregated.get("runs", []):
        scanner_name = _get_scanner_name(run)
        scanner_defaults = default_refs.get(scanner_name, [])

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")

            # Check explicit rule mapping first
            if rule_id in rule_mappings:
                refs = rule_mappings[rule_id].get("regulatory_refs", [])
            else:
                refs = scanner_defaults

            # Attach to properties.regulatory_refs
            if "properties" not in result:
                result["properties"] = {}
            result["properties"]["regulatory_refs"] = list(refs)


def aggregate_sarif(
    sarif_files: list[str],
    regulatory_mapping_path: str | None = None,
) -> dict:
    """
    Combines multiple SARIF files into a single aggregated report.

    Args:
        sarif_files: List of paths to individual SARIF 2.1.0 files
        regulatory_mapping_path: Optional path to regulatory-mapping.json.
            When provided, each finding will be tagged with regulatory_refs
            from the mapping. When None, the tagging step is skipped.

    Returns:
        Aggregated SARIF dict with all runs merged, preserving:
        - tool identity per run
        - all results with original locations
        - regulatory metadata tags (when mapping provided)

    Invariant: total findings in output == sum of findings across inputs
    """
    aggregated_runs: list[dict] = []

    for file_path in sarif_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            print(
                f"WARNING: Skipping invalid SARIF file '{file_path}': {exc}",
                file=sys.stderr,
            )
            continue

        if not _is_valid_sarif(data):
            print(
                f"WARNING: Skipping '{file_path}': not a valid SARIF 2.1.0 document",
                file=sys.stderr,
            )
            continue

        for run in data["runs"]:
            aggregated_runs.append(run)

    aggregated = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": aggregated_runs,
    }

    # Attach regulatory metadata if mapping is provided
    if regulatory_mapping_path is not None:
        mapping = _load_regulatory_mapping(regulatory_mapping_path)
        _attach_regulatory_refs(aggregated, mapping)

    return aggregated


def main() -> None:
    """CLI entry point: aggregate SARIF files passed as arguments, output to stdout.

    Usage: aggregate_sarif.py [--mapping <path>] <sarif_file1> [sarif_file2] ...
    """
    args = sys.argv[1:]
    mapping_path: str | None = None

    if "--mapping" in args:
        idx = args.index("--mapping")
        if idx + 1 < len(args):
            mapping_path = args[idx + 1]
            args = args[:idx] + args[idx + 2:]
        else:
            print("ERROR: --mapping requires a file path argument", file=sys.stderr)
            sys.exit(1)

    if not args:
        print(
            "Usage: aggregate_sarif.py [--mapping <path>] <sarif_file1> [sarif_file2] ...",
            file=sys.stderr,
        )
        sys.exit(1)

    sarif_files = args
    result = aggregate_sarif(sarif_files, regulatory_mapping_path=mapping_path)
    json.dump(result, sys.stdout, indent=2)
    print()  # trailing newline


if __name__ == "__main__":
    main()
