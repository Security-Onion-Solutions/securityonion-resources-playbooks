#!/usr/bin/env python3
"""
Playbook YAML Validator for Security Onion

This script validates all playbook YAML files in both the `public/` and `securityonion-normalized/` directories.

Checks performed:
- YAML syntax correctness
- Required metadata fields:
    - name
    - id (must be a valid UUIDv4, unique within each source tree)
    - description
    - type (must be 'detection')
    - detection_id (string or empty)
    - detection_category (string or empty)
    - detection_type (must be 'sigma', 'yara', or 'nids')
    - contributors (non-empty list)
    - date (YYYY-MM-DD format)
- Uniqueness of the `id` field within each source tree (public and normalized)

Usage:
    python3 scripts/validate_playbooks.py

Exits with code 1 if any errors are found; otherwise prints success message.
"""
import os
import sys
import yaml
import re
import uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

REQUIRED_FIELDS = [
    "name", "id", "description", "type", "detection_id", "detection_category", "detection_type", "contributors", "date"
]
VALID_DETECTION_TYPES = {"sigma", "yara", "nids"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

SRC_DIRS = [
    ("public", Path(__file__).parent.parent / "public"),
    ("normalized", Path(__file__).parent.parent / "securityonion-normalized")
]

def find_yaml_files():
    files = {"public": [], "normalized": []}
    for label, src_dir in SRC_DIRS:
        for root, _, filenames in os.walk(src_dir):
            for fname in filenames:
                if fname.endswith(".yaml") or fname.endswith(".yml"):
                    files[label].append(Path(root) / fname)
    return files


def check_yaml_syntax(filepath):
    try:
        with open(filepath, "r") as f:
            content = yaml.safe_load(f)
        return True, content, None
    except Exception as e:
        return False, None, str(e)


def validate_playbook_fields(filepath, content, seen_uuids):
    errors = []
    if not isinstance(content, dict):
        errors.append("Top-level YAML is not a mapping (dict)")
        return errors
    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in content:
            errors.append(f"Missing required field: {field}")
    # Field-specific checks
    if "id" in content:
        try:
            playbook_uuid = uuid.UUID(str(content["id"]))
            if playbook_uuid.version != 4:
                errors.append("id is not a UUIDv4")
            if content["id"] in seen_uuids:
                errors.append("id is not unique across playbooks")
            seen_uuids.add(content["id"])
        except Exception:
            errors.append("id is not a valid UUID")
    if "name" in content and not str(content["name"]).strip():
        errors.append("name is empty")
    if "description" in content and not str(content["description"]).strip():
        errors.append("description is empty")
    if "type" in content and content["type"] != "detection":
        errors.append("type must be 'detection'")
    if "detection_type" in content and content["detection_type"] not in VALID_DETECTION_TYPES:
        errors.append(f"detection_type must be one of {VALID_DETECTION_TYPES}")
    if "contributors" in content:
        if not isinstance(content["contributors"], list) or not content["contributors"]:
            errors.append("contributors must be a non-empty list")
    if "date" in content:
        if not DATE_RE.match(str(content["date"])):
            errors.append("date must be in YYYY-MM-DD format")
    return errors


def validate_file(filepath, seen_uuids):
    syntax_ok, content, syntax_err = check_yaml_syntax(filepath)
    errors = []
    if not syntax_ok:
        errors.append(f"YAML syntax error: {syntax_err}")
        return filepath, errors
    errors.extend(validate_playbook_fields(filepath, content, seen_uuids))
    # Additional checks for normalized directory
    # Use normalized_dir variable from SRC_DIRS
    normalized_dir = dict(SRC_DIRS)["normalized"]
    try:
        if normalized_dir in filepath.parents or filepath.parent == normalized_dir:
            with open(filepath, "r") as f:
                text = f.read()
                # Check for forbidden '|expand' string and print offending lines
                expand_lines = [line for line in text.splitlines() if "|expand" in line]
                if expand_lines:
                    for l in expand_lines:
                        errors.append(f"Contains forbidden '|expand' string: {l.strip()}")
                # Check for unmapped %...% variable patterns and print offending lines
                percent_pat = re.compile(r'%[^\s%]+%')
                for i, line in enumerate(text.splitlines(), 1):
                    for match in percent_pat.finditer(line):
                        errors.append(f"Line {i}: Unmapped variable pattern: {match.group(0)} in line: {line.strip()}")
                # Check for lines that look like a YAML mapping but are missing a colon
                # e.g., dns.query.name|contains '{dns.query_name}'
                missing_colon_pat = re.compile(r"^([ \t\-]*)([\w\.]+\|\w+)\s+['\"]?{[\w\.]+}['\"]?")
                for i, line in enumerate(text.splitlines(), 1):
                    if missing_colon_pat.match(line):
                        errors.append(f"Line {i}: Possible missing colon in mapping: {line.strip()}")
    except Exception as e:
        errors.append(f"Error during normalized file checks: {e}")
    return filepath, errors


def main():
    files = find_yaml_files()
    results = []
    for label, src_dir in SRC_DIRS:
        seen_uuids = set()
        these_files = files[label]
        print(f"Validating {len(these_files)} playbook files in {src_dir}...")
        with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
            futures = {executor.submit(validate_file, f, seen_uuids): f for f in these_files}
            for future in as_completed(futures):
                filepath, errors = future.result()
                if errors:
                    results.append((filepath, errors))
    if results:
        print("\nValidation errors found:")
        for filepath, errs in results:
            print(f"\n{filepath}:")
            for err in errs:
                print(f"  - {err}")
        sys.exit(1)
    else:
        print("All playbooks passed validation!")

import argparse
import subprocess

def get_staged_files():
    # Get staged YAML files (added/modified/deleted) in public/ and securityonion-normalized/
    src_paths = [str(src_dir) for _, src_dir in SRC_DIRS]
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-status", "--", *src_paths],
        capture_output=True, text=True, check=False
    )
    changed = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        status, path = line.split("\t", 1)
        if status == "D":
            continue  # deleted, skip
        if path.endswith(".yaml") or path.endswith(".yml"):
            changed.append(Path(path))
    return changed

def main():
    parser = argparse.ArgumentParser(description="Validate playbook YAML files.")
    parser.add_argument('--staged', action='store_true', help='Only validate YAML files staged for commit (for pre-commit)')
    args = parser.parse_args()

    if args.staged:
        files_to_check = get_staged_files()
        if not files_to_check:
            print("No staged YAML files to validate.")
            sys.exit(0)
        results = []
        seen_uuids = set()
        print(f"Validating {len(files_to_check)} staged playbook files...")
        with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
            futures = {executor.submit(validate_file, f, seen_uuids): f for f in files_to_check}
            for future in as_completed(futures):
                filepath, errors = future.result()
                if errors:
                    results.append((filepath, errors))
        if results:
            print("\nValidation errors found:")
            for filepath, errs in results:
                print(f"\n{filepath}:")
                for err in errs:
                    print(f"  - {err}")
            sys.exit(1)
        else:
            print("All staged playbooks passed validation!")
    else:
        files = find_yaml_files()
        results = []
        for label, src_dir in SRC_DIRS:
            seen_uuids = set()
            these_files = files[label]
            print(f"Validating {len(these_files)} playbook files in {src_dir}...")
            with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
                futures = {executor.submit(validate_file, f, seen_uuids): f for f in these_files}
                for future in as_completed(futures):
                    filepath, errors = future.result()
                    if errors:
                        results.append((filepath, errors))
        if results:
            print("\nValidation errors found:")
            for filepath, errs in results:
                print(f"\n{filepath}:")
                for err in errs:
                    print(f"  - {err}")
            sys.exit(1)
        else:
            print("All playbooks passed validation!")

if __name__ == "__main__":
    main()
