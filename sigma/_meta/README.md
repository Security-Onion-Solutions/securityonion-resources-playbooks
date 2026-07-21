# `_meta/`

Generated reference material *about* the playbooks in this repo — not playbooks
themselves. Files here are derived artifacts; treat them as read-only and
regenerate rather than hand-edit.

## Contents

| file | what it is | regenerate |
|---|---|---|
| `field_inventory.md` | Catalogue of every field name used in the playbook question queries, grouped by logsource category, with the SO/ECS field each converts to. ECS targets are ground-truth — derived by running `sigma convert` through the deployed pipeline stack. | (generator lived in the original authoring pipeline's `scratch/`; not shipped here) |
| `generation_meta.json` | Build-time provenance lifted out of every playbook: the per-question `source:` marker (which template / ATT&CK analytic produced each question) and the full `_generation_meta` audit block (techniques, attack-chain & dimension coverage, dedup and hint dispositions, template sets applied, generation stats), plus a corpus-level rollup. | `python3 sigma/_meta/build_generation_meta.py` |
| `../../docs/generation_meta.html` | Self-contained viewer for `generation_meta.json`. **Lives in the repo-root `docs/` (the GitHub Pages web root), not here** — `_meta/` is outside the web root and would not be served. It fetches this archive from `raw.githubusercontent.com` (falling back only when a repo-relative copy is reachable, i.e. local browsing). Linked from the site index. | n/a (static) |

> **Regenerating `generation_meta.json`:** the published playbooks no longer carry
> the `_generation_meta` block or per-question `source:` markers — a pre-merge pass
> strips them into this archive. The generator handles that: playbooks that still
> carry provenance are archived fresh; already-stripped playbooks keep their
> previously archived entry. Run it **before** stripping a new batch (the strip
> tool refuses to strip anything not yet archived), then strip:
> ```bash
> python3 sigma/_meta/build_generation_meta.py
> python3 5_validate/strip_provenance.py --write   # from the authoring pipeline root
> ```
> `generation_meta.json` uses compact (no-whitespace) JSON — read it with `jq`.

## Field-name convention (summary)

Playbook queries use **Sigma-spec field names** (`Image`, `CommandLine`,
`ImageLoaded`, `EventID`, `Channel`, `ParentName`, …). The SO pipeline
(`sigma_so_pipeline.yaml` + `ecs_windows`) maps them to ECS at convert time.

The only bare ECS field names allowed are the **platform floor** — host scoping
and prior-detection lookup, which have no Sigma-taxonomy expression:
`host.name`, `rule.uuid`, `rule.name`, `event.module`, `event.severity_label`.

This is enforced at authoring time by `lint_ecs_field_names` in
`5_validate/normalize_and_validate.py` and documented in
`4_playbook/AGENTS.md` ("Field names: use Sigma-spec, never raw ECS").
See `field_inventory.md` for the full field→ECS mapping.
