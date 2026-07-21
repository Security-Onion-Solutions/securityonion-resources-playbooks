#!/usr/bin/env python3
"""Generate docs/playbooks.json — a lightweight search index for the lookup page.

Walks ../playbooks/**/*.yaml and emits {id, name, description, questions,
techniques, data_sources, source, source_group, path} per playbook. The index
powers search-by-name and the coverage breakdown; preview content is fetched
live from GitHub so it always reflects the current repo. Re-run after adding or
editing playbooks:

    python3 docs/build_index.py     # from the repo root

`source` is derived from the directory tree (sigmahq / sos/idh / sos/grid /
engine / category). `source_group` is the display bucket for the coverage strip
(SigmaHQ / Security Onion / Baseline). `path` is the repo-relative file path,
used to build GitHub view/edit and raw-fetch URLs (the tree is no longer flat,
so a UUID alone no longer determines the path).
"""
import json
import pathlib

DOCS = pathlib.Path(__file__).resolve().parent   # repo-root docs/ (web root)
REPO = DOCS.parent
PLAYBOOKS = REPO / "sigma" / "playbooks"
OUT = DOCS / "playbooks.json"

# Display names for known individual-rule sources. Unknown source dirs fall back
# to a title-cased dir name, so a future ruleset (e.g. individual/elastic/) shows
# up automatically without a code change.
SOURCE_DISPLAY = {"sigmahq": "SigmaHQ"}


def classify(rel: pathlib.Path):
    """Map a path relative to playbooks/ to (source slug, display group)."""
    parts = rel.parts
    top = parts[0]
    if top == "individual":
        src_dir = parts[1] if len(parts) > 1 else "unknown"
        if src_dir == "sos":
            sub = parts[2] if len(parts) > 3 else None
            return (f"sos/{sub}" if sub else "sos"), "Security Onion"
        return src_dir, SOURCE_DISPLAY.get(src_dir, src_dir.replace("-", " ").title())
    if top in ("engine", "category"):
        # Baseline (engine/category) playbooks are authored by Security Onion —
        # group them under Security Onion for the detection-source breakdown. The
        # granular `source` slug still distinguishes engine vs category.
        return top, "Security Onion"
    return top, top.title()
# Provenance (techniques, logsource diversity) was lifted out of the playbooks
# into this archive; it is the source of truth for those fields here.
GEN_META = REPO / "sigma" / "_meta" / "generation_meta.json"

try:
    import yaml
except ImportError:
    raise SystemExit("PyYAML required: pip install pyyaml")


def load_gen_meta():
    """Map playbook id -> its _generation_meta block from the _meta archive."""
    if not GEN_META.exists():
        print(f"  WARNING: {GEN_META.name} not found — techniques/data_sources will "
              f"fall back to query parsing. Run _meta/build_generation_meta.py first.")
        return {}
    doc = json.loads(GEN_META.read_text())
    return {p["id"]: (p.get("generation_meta") or {}) for p in doc.get("playbooks", [])}


def first_line(text):
    if not text:
        return ""
    return " ".join(str(text).split())


def techniques_of(meta):
    out = []
    for t in meta.get("techniques") or []:
        tid = t.get("id")
        if tid:
            out.append({"id": tid, "name": t.get("name", "")})
    return out


def data_sources_of(meta, data):
    """Distinct logsource categories used across the playbook's question queries."""
    diversity = (meta.get("generation_stats") or {}).get("logsource_diversity") or {}
    if diversity:
        return sorted(diversity.keys())
    # Fallback: parse each question query's logsource. Use category when present,
    # else product (honeypot/auth playbooks are scoped by product: alert / linux
    # with no category, so a category-only read would drop them entirely).
    cats = set()
    for q in data.get("questions") or []:
        try:
            qq = yaml.safe_load(q.get("query", "") or "")
        except yaml.YAMLError:
            continue
        if isinstance(qq, dict):
            ls = qq.get("logsource") or {}
            cat = ls.get("category") or ls.get("product")
            if cat:
                cats.add(cat)
    return sorted(cats)


def main():
    gen_meta = load_gen_meta()
    entries = []
    for path in sorted(PLAYBOOKS.rglob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as e:
            print(f"  skip {path.name}: {e}")
            continue
        rel = path.relative_to(PLAYBOOKS)
        source, group = classify(rel)
        meta = gen_meta.get(path.stem, {})
        entries.append({
            "id": path.stem,
            "name": data.get("name", path.stem),
            "description": first_line(data.get("description"))[:400],
            "questions": len(data.get("questions") or []),
            "techniques": techniques_of(meta),
            "data_sources": data_sources_of(meta, data),
            "source": source,
            "source_group": group,
            "path": str(path.relative_to(REPO)),
        })

    entries.sort(key=lambda e: e["name"].lower())
    OUT.write_text(json.dumps(entries, indent=2) + "\n")

    techs = {t["id"] for e in entries for t in e["techniques"]}
    srcs = {s for e in entries for s in e["data_sources"]}
    groups = {}
    for e in entries:
        groups[e["source_group"]] = groups.get(e["source_group"], 0) + 1
    print(f"Wrote {len(entries)} playbooks -> {OUT.relative_to(DOCS.parent)}")
    print(f"  {len(techs)} ATT&CK techniques, {len(srcs)} telemetry types")
    print("  by source: " + ", ".join(f"{g} {n}" for g, n in
                                       sorted(groups.items(), key=lambda x: -x[1])))


if __name__ == "__main__":
    main()
