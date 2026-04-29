# ATT&CK Data Source Inventory

**Live demo:** https://dev-nobytes-io.github.io/Mitre-cti-log-to-detection/

A static web app that walks you through five steps:

1. **MITRE CTI** — load the ATT&CK STIX bundle (or a local file).
2. **Log Inventory** — score the data sources / log feeds you collect.
3. **Detections** — what you can detect, derived from your inventory.
4. **Threats** — pick the threat-actor groups you care about.
5. **Gap Analysis** — cross-reference the threats' techniques against
   your detections to surface coverage gaps.

Built like [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) +
[Dettectinator](https://github.com/siriussecurity/dettectinator) but
all in the browser — no install, no backend.

It pulls ATT&CK STIX data straight from
[github.com/mitre/cti](https://github.com/mitre/cti), maps your data
components to techniques via the official STIX `detects` relationships, and
emits a Navigator layer JSON you can drop into the
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

## Why another tool?

DeTT&CT is great but is a Python CLI that ships an Excel-driven workflow.
Dettectinator generates Navigator layers from various detection sources but
also runs as a CLI / library. This app is a 5-minute,
zero-install browser UI for the same flow:

1. Load ATT&CK (cached in IndexedDB after the first fetch).
2. Score each data source / component (0–5) for collection quality.
3. See which techniques you can detect, weighted by score and component
   coverage ratio.
4. Export an ATT&CK Navigator layer JSON.

## Sample data

Every section has a *Samples* link or download you can use without
typing anything. Pulled in from `samples/`:

| Tab | File | What it is |
|---|---|---|
| MITRE CTI | `samples/stix-mini-bundle.json` | 24 KB synthetic STIX bundle — 6 data sources, 12 techniques, 5 groups. Loads instantly; great for kicking the tyres without the 30 MB enterprise bundle. |
| Log Inventory | `samples/persona-mature-enterprise.yaml` | Enterprise SOC w/ Sysmon + EDR + Zeek — most things scored 3-5. |
| Log Inventory | `samples/persona-cloud-saas.yaml` | Cloud-first SaaS — strong cloud + identity, dark on host telemetry. |
| Log Inventory | `samples/persona-network-mssp.yaml` | Perimeter-only MSSP customer — strong network, zero host. |
| Log Inventory | `samples/persona-greenfield-startup.yaml` | Just rolled out an EDR — useful as a "before" picture. |
| Threats | `samples/threats.example.yaml` | Mixed sample (APT29 / 28 / 41, FIN7, Wizard Spider…). |
| Threats | `samples/threats-ransomware.yaml` | Ransomware-affiliated crews. |
| Threats | `samples/threats-state-apts.yaml` | State-aligned APTs. |
| Threats | `samples/threats-financial.yaml` | Financially-motivated cybercrime. |

Click a sample link inside the live app to download the file, then use
the matching *Import* / *Upload* control on that tab.

## Run it

It's a fully static site. Open `index.html` over `http://` (file:// will
break ES modules and `fetch`). Any static server works:

```
python3 -m http.server 8080
# or
npx serve .
```

Then open http://localhost:8080.

## Live demo

The site is set up to work with **either** of GitHub Pages'
[publishing sources](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site):

**Option A — GitHub Actions (recommended).** A workflow at
[`.github/workflows/pages.yml`](.github/workflows/pages.yml) packages the
repo root and deploys it via `actions/deploy-pages` on every push to
`main`. Enable it once:

1. **Settings → Pages → Build and deployment → Source: GitHub Actions**.
2. Push to `main` (or use *Actions → Deploy live demo → Run workflow*).
3. The deployed URL appears in the *deployment* step output.

**Option B — Deploy from a branch.** A `.nojekyll` marker at the repo
root tells Pages to serve files as-is (no Jekyll). Enable it once:

1. **Settings → Pages → Build and deployment → Source: Deploy from a
   branch → Branch: `main` / Folder: `/ (root)`**.
2. Pages publishes within ~1 minute.

Same artifact, same URL — pick whichever source the dropdown is on.
Typical URL: `https://<owner>.github.io/<repo>/`.

The site is fully static (relative paths, HTTPS-only deps) so it also
deploys cleanly to Cloudflare Pages, Netlify, or Vercel by pointing the
provider at this repo with no build command.

## Workflow

### 1. Load ATT&CK

On the **Load ATT&CK** tab, pick a domain (`enterprise-attack`,
`mobile-attack`, `ics-attack`) and click *Load / Refresh*. The bundle is
fetched from `https://raw.githubusercontent.com/mitre/cti/master/<domain>/<domain>.json`
and cached in IndexedDB so subsequent visits are instant.

You can also drop a local STIX bundle JSON via *Load local STIX file* —
useful for offline use or for pinning to a specific ATT&CK version.

### 2. Inventory

For every ATT&CK data source you have a *visibility score* (0–5). Component
overrides let you say "I have great Process Creation but only fair Process
Access." The inventory persists in `localStorage`.

You can import / export the inventory as YAML or JSON. The YAML schema is
the same as DeTT&CT's `data-source-administration` file (v1.2), so existing
DeTT&CT YAMLs should round-trip. See `samples/inventory.example.yaml`.

### 3. Coverage

Each technique has zero or more data components that detect it (per the
official STIX `detects` relationships). For each technique we compute:

- **Coverage ratio**: covered detecting components / total detecting
  components (0..1).
- **Max source score**: best score across components that cover it (0..5).
- **Weighted score**: `max_score × ratio` (0..5, fractional).

The technique table shows everything filterable by tactic, name, and
coverage class.

### 4. Threats (gap analysis)

Pulls MITRE ATT&CK threat-actor groups (`intrusion-set` STIX objects)
out of the same bundle. Tick one or more (e.g. APT29, FIN7) and the
app cross-references the techniques those groups use against your
data-source coverage to surface:

- **Covered** — group uses it and you'd detect it.
- **Partial** — you have some of the detecting components.
- **Gap** — group uses it and you have zero coverage.
- **Undetectable** — ATT&CK has no `detects` relationships for it; no
  data-source telemetry maps to it at all (a known blind zone).

Two Navigator-layer exports:

- **Threat-groups overlay** — score = number of selected groups using
  each technique.
- **Gap layer** — score = `groups × (1 − coverage_ratio)`; high score
  = bigger detection gap.

The group selection imports / exports as DeTT&CT-style
`group-administration` YAML — see `samples/threats.example.yaml`.

### 5. Relationships

A dedicated tab visualizes the data flow with [Mermaid](https://mermaid.js.org/)
diagrams:

- **Conceptual model** — how a raw log becomes a Navigator score (always
  shown).

  ```mermaid
  flowchart LR
    log[/"Raw log"/] --> src["Data Source"]
    src --> cmp["Data Component"]
    cmp -->|detects| tech["Technique"] --> tac["Tactic"]
    tech -. weighted by score .-> nav[("Navigator layer")]
  ```

- **Per-source drill-down** — pick a data source to see its components and
  every technique they detect, colored by your visibility score.
- **Per-technique view** — search for a technique to see which data
  components detect it (and which of yours cover them).
- **Coverage overview** — top data sources ranked by detection breadth, with
  a bar showing covered / total techniques.

### 6. Export

Generates a [Navigator layer 4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/LAYERFORMATv4_5.md)
JSON. Open Navigator → *Open Existing Layer* → *Upload from local* and you
get a colored heat map of your detection coverage across the matrix.

Every technique entry includes metadata (component coverage ratio, max
score, list of covering components) that Navigator surfaces on hover.

## Mapping logic — the short version

```
data source ──has─▶ data component ──detects─▶ technique
                          │
                       (your visibility score)
```

- ATT&CK data source = an information *category* (e.g., "Process").
- ATT&CK data component = a sub-event of that source (e.g., "Process
  Creation"). Components are what STIX `detects` relationships actually
  point at.
- Your inventory scores at the source level, with optional per-component
  overrides. The app resolves the effective score for each component, then
  scores each technique based on which of its detecting components you
  have.

## Files

```
index.html                 # UI shell
css/styles.css             # styles
js/app.js                  # UI controller
js/attack.js               # STIX bundle loader + indexer (uses IndexedDB cache)
js/inventory.js            # inventory state + YAML/JSON import/export
js/coverage.js             # technique coverage computation
js/diagrams.js             # mermaid diagram generators
js/navigator.js            # Navigator layer JSON builder
samples/inventory.example.yaml
```

## Acknowledgements

- MITRE ATT&CK® data — © The MITRE Corporation. ATT&CK® is a registered
  trademark of The MITRE Corporation.
- Inspired by [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) and
  [Dettectinator](https://github.com/siriussecurity/dettectinator).
- YAML parsing via [js-yaml](https://github.com/nodeca/js-yaml).
