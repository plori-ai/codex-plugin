#!/usr/bin/env python3
"""Approve the one reviewed scanner false positive without suppressing new findings."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


EXPECTED_SKILL_PATH = "skills/plori/SKILL.md"
EXPECTED_SKILL_SHA256 = "33aed3c1a30c0d40f25c377b0ceee42f56fd064662b32ca16794ea21e90f5125"
EXPECTED_RULE_ID = "RISKY_SKILL_INSTRUCTION"
EXPECTED_MESSAGE = (
    'The skill includes "curl -fsSL https://plori.ai/install.sh" and sends '
    "workspace data to a remote endpoint."
)
KNOWN_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def fail(message: str) -> None:
    raise ValueError(message)


def require_integer(value: str, name: str) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        fail(f"{name} must be a decimal integer")
    return int(value)


def load_results(sarif_path: Path) -> list[dict]:
    try:
        document = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid SARIF report: {error}")

    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        fail("report is not SARIF 2.1.0")
    runs = document.get("runs")
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        fail("report must contain exactly one SARIF run")
    results = runs[0].get("results")
    if not isinstance(results, list) or not all(isinstance(result, dict) for result in results):
        fail("report has no valid results list")
    return results


def severity(result: dict) -> str:
    properties = result.get("properties")
    value = properties.get("severity") if isinstance(properties, dict) else None
    if value not in KNOWN_SEVERITIES:
        fail("every scanner result must have a known severity")
    return value


def is_reviewed_finding(result: dict) -> bool:
    properties = result.get("properties")
    if not isinstance(properties, dict):
        return False
    locations = result.get("locations")
    if not isinstance(locations, list) or len(locations) != 1 or not isinstance(locations[0], dict):
        return False
    physical = locations[0].get("physicalLocation")
    artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
    location_path = artifact.get("uri") if isinstance(artifact, dict) else None
    message = result.get("message")
    message_text = message.get("text") if isinstance(message, dict) else None
    return (
        result.get("ruleId") == EXPECTED_RULE_ID
        and result.get("level") == "error"
        and properties.get("severity") == "high"
        and properties.get("source") == "native"
        and properties.get("category") == "skill-security"
        and message_text == EXPECTED_MESSAGE
        and location_path == EXPECTED_SKILL_PATH
    )


def review(sarif_path: Path, skill_path: Path, score_text: str, exit_code_text: str, outcome: str) -> str:
    score = require_integer(score_text, "scanner score")
    if not 80 <= score <= 100:
        fail("scanner score must be between 80 and 100")
    action_exit_code = require_integer(exit_code_text, "scanner action exit code")
    if action_exit_code not in {0, 1}:
        fail("scanner action exit code must be 0 or 1")
    if outcome not in {"success", "failure"}:
        fail("scanner outcome must be success or failure")
    if (outcome == "success") != (action_exit_code == 0):
        fail("scanner outcome and action exit code disagree")

    results = load_results(sarif_path)
    if any(result.get("level") == "error" and not is_reviewed_finding(result) for result in results):
        fail("scanner reported an unreviewed error-level finding")
    elevated = [result for result in results if severity(result) in {"high", "critical"}]
    if outcome == "success":
        if elevated:
            fail("a successful scanner action reported HIGH or CRITICAL findings")
        return "scanner passed without HIGH or CRITICAL findings"

    if len(elevated) != 1 or not is_reviewed_finding(elevated[0]):
        fail("scanner failure is not the one reviewed RISKY_SKILL_INSTRUCTION finding")
    actual_hash = hashlib.sha256(skill_path.read_bytes()).hexdigest()
    if actual_hash != EXPECTED_SKILL_SHA256:
        fail("reviewed finding requires the canonical skill bytes")
    return "scanner failure matches the reviewed finding and canonical skill bytes"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sarif", type=Path, required=True)
    parser.add_argument("--skill", type=Path, required=True)
    parser.add_argument("--score", required=True)
    parser.add_argument("--action-exit-code", required=True)
    parser.add_argument("--outcome", required=True)
    args = parser.parse_args()
    try:
        print(review(args.sarif, args.skill, args.score, args.action_exit_code, args.outcome))
    except (OSError, ValueError) as error:
        print(f"scanner review rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
