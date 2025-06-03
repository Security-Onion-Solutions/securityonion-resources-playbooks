# Security Onion Playbooks

## Directory Structure

- `public/` — Source YAML playbooks (edit these)
- `securityonion-normalized/` — Normalized output (auto-generated, do not edit by hand)
- `scripts/patterns_sigma.yaml` — Substitution patterns for Sigma rules and engine
- `scripts/patterns_nids.yaml` — Substitution patterns for NIDS rules and engine
- `scripts/validate_playbooks.py` — Python script for validation - run before normalization
- `scripts/normalize_playbooks.py` — Python script for normalization


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

