#!/usr/bin/env python3
"""Generate _meta/generation_meta.json — the provenance index for the playbooks.

Every freshly authored playbook under ../playbooks/ carries two kinds of
build-time provenance that are noise to an analyst running the playbook in
Security Onion but valuable when auditing how the corpus was generated:

  * `_generation_meta` — techniques, attack-chain / dimension coverage, dedup and
    hint dispositions, the template sets applied, and generation stats.
  * a per-question `source:` marker (e.g. `template:cue_process_tool.scope`,
    `attack:T1548.002.registry_set`) recording which template or ATT&CK analytic
    produced each question.

This script lifts both out of every playbook into a single JSON document and a
corpus-level rollup, so the provenance can be browsed (see docs/generation_meta.html)
without bloating the playbooks themselves. It does NOT modify the playbooks.

Playbooks that have already been stripped keep their previously archived entry:
the existing generation_meta.json is loaded first and its entry is carried
forward whenever the on-disk playbook no longer has provenance. Run it BEFORE
stripping a new batch so the fresh provenance is captured; re-running after a
strip is a no-op for already-archived playbooks.

    python3 _meta/build_generation_meta.py

Set SIGMA_DIR to point at a different playbook tree (searched recursively).
"""
import json
import os
import pathlib
from collections import Counter

META = pathlib.Path(__file__).resolve().parent
SIGMA = pathlib.Path(os.environ.get("SIGMA_DIR") or (META.parent / "playbooks"))
OUT = META / "generation_meta.json"

try:
    import yaml
except ImportError:
    raise SystemExit("PyYAML required: pip install pyyaml")


def first_line(text):
    if not text:
        return ""
    return " ".join(str(text).split())


def source_kind(src):
    """`template:foo.bar` -> 'template', `attack:T1.image_load` -> 'attack'."""
    if not src or ":" not in src:
        return "unknown"
    return src.split(":", 1)[0]


def template_family(src):
    """`template:cue_process_tool.scope` -> 'cue_process_tool'. None for non-templates."""
    if not src or not src.startswith("template:"):
        return None
    body = src.split(":", 1)[1]
    return body.split(".", 1)[0] if "." in body else body


def load_archive():
    """Map playbook id -> previously archived entry (provenance survives stripping)."""
    if not OUT.exists():
        return {}
    try:
        doc = json.loads(OUT.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    return {p["id"]: p for p in doc.get("playbooks", [])}


def has_provenance(entry):
    return bool(entry.get("generation_meta")) or any(
        q.get("source") for q in entry.get("questions", []))


def main():
    archived = load_archive()
    entries = []
    playbooks_missing_meta = []
    carried = 0

    for path in sorted(SIGMA.rglob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as e:
            print(f"  skip {path.name}: {e}")
            continue

        meta = data.get("_generation_meta") or {}

        questions = []
        for i, q in enumerate(data.get("questions") or [], start=1):
            # `kind` is intentionally not stored — it's derivable from the source
            # prefix (`template:` / `attack:`); the viewer computes it on the fly.
            questions.append({
                "n": i,
                "source": q.get("source"),
                "question": first_line(q.get("question")),
            })

        entry = {
            "id": path.stem,
            "name": data.get("name", path.stem),
            "description": first_line(data.get("description"))[:300],
            "question_count": len(questions),
            "questions": questions,
            "generation_meta": meta,
        }

        # Already stripped on disk but archived earlier — keep the archived
        # provenance rather than overwriting it with an empty record.
        if not has_provenance(entry) and has_provenance(archived.get(path.stem, {})):
            entry = archived[path.stem]
            carried += 1

        if not entry.get("generation_meta"):
            playbooks_missing_meta.append(path.stem)
        entries.append(entry)

    entries.sort(key=lambda e: e["name"].lower())

    # Corpus-level tallies, recomputed from the final (fresh + carried) entries.
    source_count = Counter()       # full source string -> uses
    kind_count = Counter()         # template / attack / unknown -> uses
    family_count = Counter()       # template family -> uses
    set_count = Counter()          # technique_sets_applied -> playbooks
    technique_count = Counter()    # ATT&CK id -> playbooks
    for e in entries:
        for q in e["questions"]:
            src = q.get("source")
            if src:
                source_count[src] += 1
                kind_count[source_kind(src)] += 1
                fam = template_family(src)
                if fam:
                    family_count[fam] += 1
        meta = e.get("generation_meta") or {}
        for s in meta.get("technique_sets_applied") or []:
            set_count[s] += 1
        for t in meta.get("techniques") or []:
            if t.get("id"):
                technique_count[t["id"]] += 1

    rollup = {
        "playbooks": len(entries),
        "playbooks_missing_meta": playbooks_missing_meta,
        "total_questions": sum(e["question_count"] for e in entries),
        "source_kinds": dict(kind_count.most_common()),
        "template_families": dict(family_count.most_common()),
        "technique_sets_applied": dict(set_count.most_common()),
        "techniques": dict(technique_count.most_common()),
        "sources": dict(source_count.most_common()),
    }

    doc = {"rollup": rollup, "playbooks": entries}
    # Compact separators: this is a generated, machine-read artifact (the HTML
    # viewer parses it) — the data is ~10 MB of unique prose, so pretty-printing
    # only adds whitespace. Use `jq` if you need to read it by hand.
    OUT.write_text(json.dumps(doc, separators=(",", ":")) + "\n")

    print(f"Wrote {len(entries)} playbooks -> {OUT.relative_to(META.parent)}")
    print(f"  {rollup['total_questions']} questions, "
          f"{len(family_count)} template families, "
          f"{len(set_count)} technique sets")
    if carried:
        print(f"  {carried} already-stripped playbooks carried from previous archive")
    if playbooks_missing_meta:
        print(f"  WARNING: {len(playbooks_missing_meta)} playbooks have no _generation_meta")


if __name__ == "__main__":
    main()
