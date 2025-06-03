#!/usr/bin/env python3
"""
Playbook Normalization Script for Security Onion

- Reads playbook YAML files from public/ and normalizes them using pattern files.
- Writes normalized files to securityonion-normalized/, preserving directory structure.
- Uses scripts/patterns_sigma.yaml for Sigma rules and engine/engine_sigma.yaml.
- Uses scripts/patterns_nids.yaml for NIDS rules and engine/engine_nids.yaml.
- Deletes orphaned normalized files when source files are deleted.
- Supports --all (full run), --staged (pre-commit).

Directory conventions:
- Source playbooks: public/
- Normalized playbooks: securityonion-normalized/
- Pattern files: scripts/patterns_sigma.yaml, scripts/patterns_nids.yaml
"""
import os
import sys
import yaml
import shutil

from pathlib import Path

# Set up paths
BASE_DIR = Path(__file__).parent.parent
SRC_DIR = BASE_DIR / "public"
DST_DIR = BASE_DIR / "securityonion-normalized"
PATTERNS_SIGMA = BASE_DIR / "scripts/patterns_sigma.yaml"
PATTERNS_NIDS = BASE_DIR / "scripts/patterns_nids.yaml"

# Helper: Load patterns from YAML
def load_patterns(yaml_path):
    with open(yaml_path, 'r') as f:
        return yaml.safe_load(f)

# Helper: Apply patterns to text
def apply_patterns(text, patterns):
    for search, replace in patterns.items():
        text = text.replace(search, replace)
    return text

# Helper: Determine which pattern file to use
def get_pattern_file(src_path):
    rel = src_path.relative_to(SRC_DIR)
    rel_str = str(rel)
    if rel_str.startswith("sigma/") or rel_str == "engine/engine_sigma.yaml":
        return PATTERNS_SIGMA
    elif rel_str.startswith("nids/") or rel_str == "engine/engine_nids.yaml":
        return PATTERNS_NIDS
    else:
        return None

def normalize_file(src_path, dst_path, patterns):
    import re
    with open(src_path, 'r') as f:
        lines = f.readlines()
    # Remove all occurrences of '|expand'
    new_lines = [re.sub(r'\|expand', '', line) for line in lines]
    normalized = "".join(new_lines)
    # Apply patterns as before
    normalized = apply_patterns(normalized, patterns)
    # Check for unmapped %...% variables
    percent_pat = re.compile(r'%[^\s%]+%')
    errors = []
    for i, line in enumerate(normalized.splitlines(), 1):
        for match in percent_pat.finditer(line):
            errors.append(f"{src_path} Line {i}: Unmapped variable pattern: {match.group(0)} in line: {line.strip()}")
    if errors:
        for err in errors:
            print(f"ERROR: {err}")
        raise RuntimeError(f"Unmapped variables found in {src_path}, aborting normalization.")
    os.makedirs(dst_path.parent, exist_ok=True)
    with open(dst_path, 'w') as f:
        f.write(normalized)

import argparse
import subprocess

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normalize playbooks for Security Onion.")
    parser.add_argument('--all', action='store_true', help='Normalize all files')
    parser.add_argument('--staged', action='store_true', help='Only normalize files staged for commit (for pre-commit)')
    args = parser.parse_args()

    # Ensure scripts directory exists before proceeding
    os.makedirs(Path(__file__).parent, exist_ok=True)

    if not args.all and not args.staged:
        parser.print_help()
        sys.exit(0)

    if args.staged:
        # Get staged YAML files (added/modified/deleted) in public/
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-status", "--relative", "public/"],
            capture_output=True, text=True
        )
        changed = []
        deleted = []
        for line in result.stdout.splitlines():
            status, path = line.split('\t', 1)
            if not path.endswith('.yaml'):
                continue
            src_path = SRC_DIR / Path(path)
            if status == 'D':
                deleted.append(src_path)
            else:
                changed.append(src_path)
        # Normalize changed/added files
        expected_dst_files = set()
        normalized_count = 0
        for src in changed:
            if not src.exists():
                continue
            pattern_file = get_pattern_file(src)
            if not pattern_file or not pattern_file.exists():
                print(f"[SKIP] {src} (no applicable pattern file)")
                continue
            patterns = load_patterns(pattern_file)
            rel = src.relative_to(SRC_DIR)
            dst = DST_DIR / rel
            normalize_file(src, dst, patterns)
            print(f"[NORMALIZED] {src} -> {dst}")
            expected_dst_files.add(dst.resolve())
            normalized_count += 1
        # Delete corresponding normalized files for deleted sources
        for src in deleted:
            rel = src.relative_to(SRC_DIR)
            dst = DST_DIR / rel
            if dst.exists():
                print(f"[DELETE] {dst}")
                dst.unlink()
                parent = dst.parent
                while parent != DST_DIR and not any(parent.iterdir()):
                    parent.rmdir()
                    parent = parent.parent
        print(f"\nSummary: {normalized_count} playbook(s) normalized.")
    elif args.all:
        # Find all YAML files in SRC_DIR
        if not SRC_DIR.exists():
            print(f"[ERROR] Source directory {SRC_DIR} does not exist.")
            sys.exit(1)
        src_files = [p for p in SRC_DIR.rglob('*.yaml')]

        # Track files that should exist in DST_DIR after normalization
        expected_dst_files = set()

        normalized_count = 0
        for src in src_files:
            pattern_file = get_pattern_file(src)
            if not pattern_file or not pattern_file.exists():
                print(f"[SKIP] {src} (no applicable pattern file)")
                continue
            patterns = load_patterns(pattern_file)
            rel = src.relative_to(SRC_DIR)
            dst = DST_DIR / rel
            normalize_file(src, dst, patterns)
            print(f"[NORMALIZED] {src} -> {dst}")
            expected_dst_files.add(dst.resolve())
            normalized_count += 1
        print(f"\nSummary: {normalized_count} playbook(s) normalized.")

        # Delete orphaned files in DST_DIR
        if DST_DIR.exists():
            for dst in DST_DIR.rglob('*.yaml'):
                if dst.resolve() not in expected_dst_files:
                    print(f"[DELETE] {dst}")
                    dst.unlink()
                    # Remove empty parent dirs
                    parent = dst.parent
                    while parent != DST_DIR and not any(parent.iterdir()):
                        parent.rmdir()
                        parent = parent.parent
