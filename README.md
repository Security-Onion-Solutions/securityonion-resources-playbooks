# Security Onion Playbooks

## Directory Structure

- `public/` — Source YAML playbooks (edit these)
  - `sigma/` — Playbooks for Sigma detection rules
  - `nids/` — Playbooks for NIDS rules
  - `yara/` — Playbooks for YARA rules
- `securityonion-normalized/` — Normalized output (auto-generated, do not edit by hand)
- `scripts/patterns_sigma.yaml` — Substitution patterns for Sigma rules and engine
- `scripts/patterns_nids.yaml` — Substitution patterns for NIDS rules and engine
- `scripts/validate_playbooks.py` — Python script for validation - run before normalization
- `scripts/normalize_playbooks.py` — Python script for normalization

## Playbook ID Numbering Scheme

Playbook IDs use a 7-digit numbering system:
- **Range**: 1,000,000 - 1,999,999 (reserved for Security Onion Playbooks)
- **Starting Point**: 1,200,001
- **Format**: 7-digit number (e.g., 1200001, 1200002, 1200003)
- **Assignment**: Start at 1,200,001 and increment sequentially

## How to Use the Validation Script

The validation script recursively checks source playbooks in all subdirectories for correct metadata and valid Sigma query syntax. It should be run before normalization to ensure playbook quality.

### Validate All Playbooks
```bash
python scripts/validate_playbooks.py public/
```
This will validate all YAML files in `public/` and its subdirectories (`public/sigma/`, `public/nids/`, `public/yara/`, etc.)

### Validate with Auto-Fix
```bash
python scripts/validate_playbooks.py public/ --fixup
```
- Automatically fixes common Sigma query structure issues
- Fixes misplaced `condition` fields
- Adds missing `condition: selection` for simple cases
- Corrects `|regex` modifiers to `|re`
- Updates detection_category when detection_id is set

### Validate Only Staged Files
```bash
python scripts/validate_playbooks.py public/ --staged
```
- Only validates files staged for git commit
- Useful for pre-commit hooks

### Additional Options
- `--workers N` — Set number of parallel workers (default: auto, max 8)
- `--reset DIR` — Delete failed playbooks from validation and reset directories, create backups in ./failed/
- `--verbose` — Show detailed validation output

### What the Script Validates
1. **Metadata Requirements:**
   - Required fields: name, id, description, type, detection_id, detection_category, detection_type, contributors, created, questions
   - ID must be between 1200001-1999999
   - Name must include "ET" or "GPL" category
   - Type must be "detection"
   - Detection type must be "nids"
   - Contributors must include "SecurityOnionSolutions"
   - Created date must be YYYY-MM-DD format
   - Must have 8-15 questions

2. **Sigma Query Validation:**
   - Validates each question's Sigma query syntax using sigma-cli
   - Checks for required fields: logsource, detection
   - Ensures no unexpanded template references exist
   - Validates query structure and syntax

3. **Duplicate ID Detection:**
   - Checks for duplicate playbook IDs across all files

## How to Use the Normalization Script

### Normalize All Files (One-Time/Full Run)
```bash
python scripts/normalize_playbooks.py --all
```
- Normalizes **all** YAML files in `public/` and writes to `securityonion-normalized/`.
- Deletes any orphaned files in `securityonion-normalized/`.

### Normalize Only Staged Files (Pre-commit Mode)
```bash
python scripts/normalize_playbooks.py --staged
```
- Only normalizes files staged for commit (added/modified/deleted).
- Intended for use with pre-commit hooks.

## Setting Up Pre-commit Hooks

1. Install pre-commit (if not already):
   ```bash
   pip install pre-commit
   ```
2. Add a `.pre-commit-config.yaml`
3. Install the hook:
   ```bash
   pre-commit install
   ```

## Contribution Workflow
- Always edit files in `public/`.
- Never edit `securityonion-normalized/` by hand.
- Use the normalization script to keep everything in sync.

