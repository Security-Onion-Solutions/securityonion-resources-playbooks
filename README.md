# Security Onion Playbooks

Human-Centered Investigation Playbooks for Security Onion

Instead of listing procedural steps, each playbook poses the **investigative questions** an
analyst asks when working an alert. Every question is paired with the *context* for why it
matters, the *data source* that answers it, a relative *time range*, and a ready-to-run
*query*. The format follows the
[Human-Centered Investigation Playbook standard (v1.1)](https://chrissanders.org/2025/06/human-centered-playbooks/)
— readable by analysts, parseable by tools like [Security Onion](https://securityonion.net/).

## Browse and search the Playbooks: 
<https://security-onion-solutions.github.io/securityonion-resources-playbooks/>

The site lets you search by name or Sigma UUID, preview a playbook rendered as question
cards (or raw YAML), and jump straight to view/edit it on GitHub. It also shows corpus
coverage — playbook, question, and telemetry-type counts broken down by detection source.


## Repository structure

```
sigma/
  playbooks/
    individual/            one playbook per detection rule, named for its detection_id
      sigmahq/             playbooks for upstream SigmaHQ rules
      sos/
        idh/               Security Onion IDH detections
        grid/              Security Onion Grid/Infrastructure detections
    category/              baseline playbooks scoped to a logsource category
    engine/                baseline playbook for the detection engine itself
  _meta/                   generated reference material *about* the playbooks
docs/                      the GitHub Pages site (web root)
nids/                      placeholder — NIDS playbooks (none yet)
yara/                      placeholder — YARA playbooks (none yet)
```

## Playbook anatomy

```yaml
name: <Playbook name>
id: <Playbook UUIDv4>
description: |
  <What the rule detects and how to investigate it>
type: detection
detection_id: <Source Sigma rule UUID>    # the file is named for this
detection_category: ''
detection_type: sigma
contributors:
  - <At least one contributor>
created: <YYYY-MM-DD>

questions:
  - question: <Investigation question>
    context: <Why it matters / how to read the answer>
    range: <Relative time window, e.g. +/-5m, -7d>
    answer_sources:          # optional — data sources that answer the question
      - <e.g. process_creation, asset_inventory>
    query: |
      <Sigma fragment; %placeholders% bind to the alert at investigation time>
```

Query field names follow the **Sigma spec** (`Image`, `CommandLine`, `EventID`, …); the
Security Onion pipeline maps them to ECS at convert time. See
[`sigma/_meta/field_inventory.md`](sigma/_meta/field_inventory.md) for the full mapping and
[`sigma/_meta/README.md`](sigma/_meta/README.md) for the conventions.


## Branches

`published` is the release branch for playbook content and the branch the site links into
for view/edit;

## Licensing

Playbooks are derived from detection rules and inherit **the license of the detection they
are based on**. See [LICENSE](LICENSE) for the per-source terms.
