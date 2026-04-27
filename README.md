# HUNTER v2.1

Layered Threat-Hunting Knowledge Graph and Hunt Pack Builder

HUNTER v2.1 is a PySide6 desktop application for building analyst-readable
threat hunt packs from MITRE ATT&CK, local threat profiles, local tool packs,
and optional SigmaHQ rule coverage.

The current runtime is the Qt shell under `hunter/qt/`. The previous UI
packages have been removed from the active codebase.

---

## Table of Contents

1. [What HUNTER Does](#what-hunter-does)
2. [What Is New In v2.1](#what-is-new-in-v21)
3. [Requirements](#requirements)
4. [Quick Start](#quick-start)
5. [How To Use HUNTER v2.1](#how-to-use-hunter-v21)
6. [Search Grammar](#search-grammar)
7. [Threat And Tool Authoring](#threat-and-tool-authoring)
8. [Sync And Settings](#sync-and-settings)
9. [Hunt Generation, Review, And Export](#hunt-generation-review-and-export)
10. [Project Layout](#project-layout)
11. [Architecture](#architecture)
12. [Data And Portability](#data-and-portability)
13. [Development And Tests](#development-and-tests)
14. [Troubleshooting](#troubleshooting)

---

## What HUNTER Does

HUNTER helps analysts turn knowledge sources into reviewable hunt plans.

It combines:

- MITRE ATT&CK Enterprise technique metadata
- authored local threat profiles from `modules/threats/`
- authored local tool packs from `modules/tools/`
- optional SigmaHQ rules stored in the local database
- analyst selections made in the Qt desktop workflow

The main application uses a five-step workflow:

1. `MITRE`
2. `Threats`
3. `Tools`
4. `Generate`
5. `Review`

The result is a hunt pack that can be reviewed in the app, saved in SQLite,
exported as JSON, or rendered into a DOCX report.

---

## What Is New In v2.1

HUNTER v2.1 focuses on restoring the analyst workflow inside the new Qt shell
while removing the previous UI implementation.

Highlights:

- Qt-native MITRE, Threat, Tool, Generate, and Review workflow.
- Readable HTML detail panes for MITRE techniques, threat profiles, and tool
  packs.
- Old mini-query search grammar restored in visible Qt search boxes.
- Double-click browse-to-Generate selection for MITRE, Threats, and Tools.
- Consistent selected-row UI: green highlight plus blue left marker.
- Structured Threat and Tool editors with tabs, tables, selectors, and payload
  preservation.
- Responsive editor layouts that scroll instead of crushing controls when the
  dialog is resized.
- Threat/Tool record buttons restored: Add, Remove, Edit.
- Legacy UI code and tracked bytecode removed from the current runtime.

---

## Requirements

| Requirement | Version | Purpose |
|---|---:|---|
| Python | 3.11+ | Run the desktop application |
| PySide6 | installed through the repo/runtime environment | Qt desktop UI |
| Node.js | 18+ | DOCX export only |
| npm packages `docx`, `jszip` | installed on first DOCX export if missing | Word report rendering |

HUNTER also supports repo-local Python vendor packages for Sigma translation
support. If they are missing, startup can install or repair them under
`vendor/python/`.

---

## Quick Start

From the project root:

```bash
python main.py
```

On first run:

1. Accept the vendor-package repair prompt if HUNTER asks for it.
2. Open the gear button in the top-right corner.
3. Use `Settings / Sync` to sync MITRE ATT&CK if the database is empty.
4. Use `Load Layered Modules` to load local threats and tools from `modules/`.
5. Return to the main workflow.
6. Select MITRE techniques, threats, and tools.
7. Build a draft in `Generate`.
8. Finish, disable, delete, or export hunt steps in `Review`.

If `data/hunter_v2.sqlite3` already exists, HUNTER opens from the local database
first and does not automatically resync every source on startup.

---

## Offline Windows Bundle

HUNTER v2.1 can be packaged for isolated Windows systems. Build the bundle on a
connected or prepared workstation, then copy the generated folder or zip to the
offline system.

```bash
python tools/build_offline_bundle.py --output dist/HUNTER-v2.1-offline-win64 --include-current-knowledge
```

The bundle contains the app source, authored modules, a first-run seed knowledge
bundle, local Python vendor packages when `vendor/python/` exists, local DOCX
packages when `node_modules/` exists, and `run_hunter.bat`.

On the offline system:

1. Extract `dist/HUNTER-v2.1-offline-win64.zip`.
2. Run `run_hunter.bat`.
3. Use HUNTER normally from the generated local database.
4. Use `Settings / Sync -> Import Offline Bundle` to load a newer exported
   knowledge bundle later.

`run_hunter.bat` sets `HUNTER_PORTABLE_ROOT` to the bundle folder and
`HUNTER_OFFLINE=1` so HUNTER does not attempt `pip install` or `npm ci`.

DOCX export works offline only when the bundle includes `node_modules/docx`,
`node_modules/jszip`, and either `runtime/node/node.exe` or Node.js installed on
the offline machine.

To refresh MITRE or Sigma offline, use local source paths such as:

- MITRE: `bundle_file=modules/mitre/enterprise-attack.json`
- Sigma: `rules_dir=modules/SIGMA/local_lab`
- Sigma: `archive_path=modules/SIGMA/sigma.zip`

---

## How To Use HUNTER v2.1

### 1. Browse MITRE

Open the `01 MITRE` tab to inspect ATT&CK techniques.

Use it to:

- search by ID, name, tactic, platform, data source, or phrase
- single-click a technique to read its detail pane
- double-click a technique to add or remove it from Generate
- right-click a technique and choose `Open ATT&CK Page`

Selected techniques show the same visual state used in Generate: green row
highlight with a blue left marker.

### 2. Browse Threats

Open the `02 Threats` tab to inspect authored threat profiles.

Use it to:

- search threat names, aliases, indicators, techniques, references, and notes
- single-click a threat to read aliases, indicators, mapped ATT&CK techniques,
  unresolved mapping warnings, and Sigma overlap
- double-click a threat to add or remove it from Generate
- use `Add Threat`, `Remove Threat`, or `Edit Threat` to manage local records

Threats are saved as layered local JSON files under `modules/threats/`.

### 3. Browse Tools

Open the `03 Tools` tab to inspect tool packs.

Use it to:

- search by platform, execution surface, method name, template content, IOC
  fields, or ATT&CK coverage
- single-click a tool to read execution surface, defaults, Sigma translation
  summary, and grouped hunt-method coverage
- double-click a tool to add or remove it from Generate
- use `Add Tool`, `Remove Tool`, or `Edit Tool` to manage local records

Tools are saved as layered local JSON files under `modules/tools/`.

### 4. Build Scope In Generate

Open `04 Generate`.

The Generate page is the canonical selection state for:

- selected threats
- selected tools
- manual MITRE techniques
- Sigma family options where configured

Selections made by double-clicking in MITRE, Threats, or Tools are mirrored into
Generate immediately. Generate rows use the same green highlight and blue marker
as the browse tabs.

Build the draft after selecting the desired scope. The generated ATT&CK scope is:

```text
threat-derived techniques
UNION
manual MITRE selections
```

Tool coverage then determines which hunt methods can be rendered for that
scope.

### 5. Review The Hunt Pack

Open `05 Review` to inspect generated hunt packs.

Use Review to:

- expand or collapse ATT&CK technique groups
- enable or disable all steps in a group
- enable or disable individual steps
- persist enabled state back to the stored hunt pack
- delete old hunt packs
- export enabled steps to JSON
- export a DOCX report when Node.js, `docx`, and `jszip` are available

Review is the final analyst workspace before sharing or exporting a hunt pack.

---

## Search Grammar

Visible Qt search boxes use the restored HUNTER mini-query grammar.

Examples:

```text
id:T1001
"Exfiltration Over C2 Channel"
alias:"Search Unit"
indicator:evil.example
technique:T1041
platform:AWS method:"T1041 Hunt"
platform:Elastic -deprecated
```

Supported behavior:

- plain terms perform broad text search
- quoted phrases match exact phrases
- `+term` requires a term
- `-term` excludes a term
- `field:value` searches a specific field
- fielded quoted phrases are supported, for example `alias:"Peach Sandstorm"`

The Qt entity rails and Generate selection panels use the same search behavior.

---

## Threat And Tool Authoring

Threats and tools are authored through structured Qt dialogs. Raw JSON preview
is still available, but it is no longer the primary editing experience.

### Threat editor

Threat editor tabs:

- `ATT&CK Scope`: searchable available/selected technique selector
- `Intel`: aliases and IOC table
- `Notes`: extra hunt notes and references
- `Payload Preview`: capped read-only structured payload preview

Threat editing preserves unknown payload keys by merging structured edits back
into the original payload.

### Tool editor

Tool editor tabs:

- `Profile`: platform, execution surface, variant metadata, service examples,
  references
- `Defaults`: environment defaults and template values
- `Hunt Methods`: searchable method catalog with filters and detail tabs
- `Sigma`: Sigma translation and default families
- `Payload Preview`: capped read-only structured payload preview

The Hunt Methods editor includes:

- method list search
- filters for ATT&CK technique, method kind, strength, and IOC support
- Add/Remove method controls
- `Overview`, `Template`, `Mapping`, and `Guidance` detail tabs
- responsive split-pane layout so the catalog and detail pane stay usable when
  resized

### Save behavior

Threat and tool saves go through the existing authoring service and layered
entity service. Saving updates the local module JSON shape consumed by the rest
of the application.

---

## Sync And Settings

The gear button opens `Settings / Sync`.

Available sources:

1. `MITRE ATT&CK Enterprise`
2. `Layered Local Modules`
3. `SigmaHQ Rules`

### MITRE sync

MITRE sync is authoritative for ATT&CK technique metadata. It populates the
local database with IDs, names, descriptions, detection notes, tactics,
platforms, data sources, permissions, references, and hierarchy metadata.
Online sync uses `bundle_url`; offline sync can use `bundle_file` or
`bundle_path` pointing at a repo-relative STIX JSON file.

### Layered local modules

Layered sync loads local JSON files from:

- `modules/threats/*.json`
- `modules/tools/*.json`
- optional `modules/mitre/*.json` overlays if maintained locally

Malformed files are kept in the layered index with warning state so they can be
fixed and retried later.

### SigmaHQ rules

Sigma sync loads rules into the local database. Detail panes and generation
summaries use Sigma overlap where configured.
Online sync uses remote ZIP URLs. Offline sync should use `rules_dir`,
`rules_file`, or `archive_path` under `modules/SIGMA`.

---

## Hunt Generation, Review, And Export

### Generation inputs

Generate accepts:

- one or more threats
- one or more tools
- optional manual MITRE techniques
- optional Sigma family scope

### Generated output

Generated hunt packs include:

- selected threat profiles
- selected tool packs
- selected manual MITRE techniques
- resolved ATT&CK scope
- rendered hunt steps
- execution surface metadata
- enabled/disabled review state

### JSON export

JSON export is machine-readable and portable. By default it exports enabled
steps only.

### DOCX export

DOCX export uses:

- `export_docx.js`
- local Node.js
- local `node_modules/docx`
- local `node_modules/jszip`

If these packages are missing, HUNTER can offer to run `npm ci` from the
project root. The install uses the committed `package.json` and
`package-lock.json`; `node_modules/` is local generated state and is not tracked
in git.

The DOCX report includes:

- cover page
- mission summary
- threat/tool selection summary
- ATT&CK coverage summary
- rendered query and workflow sections
- execution surface metadata

---

## Project Layout

```text
Project/
|-- main.py
|-- export_docx.js
|-- README.md
|-- data/
|   |-- hunter_v2.sqlite3
|   |-- exports/
|   |-- imports/
|   `-- snapshots/
|-- modules/
|   |-- mitre/
|   |-- threats/
|   `-- tools/
|-- hunter/
|   |-- qt_app.py
|   |-- runtime_paths.py
|   |-- vendor_runtime.py
|   |-- controllers/
|   |-- models/
|   |-- qt/
|   |-- services/
|   `-- search_query.py
|-- tests/
`-- vendor/
```

Important current runtime files:

| Path | Purpose |
|---|---|
| `main.py` | Desktop entry point |
| `hunter/qt_app.py` | Builds and runs the Qt application |
| `hunter/qt/main_window.py` | Five-step shell/composition root |
| `hunter/qt/entity_browser.py` | MITRE, Threat, and Tool browse rails |
| `hunter/qt/entity_dialogs.py` | Entity editor and Sigma scope dialogs |
| `hunter/qt/generate_page.py` | Generate workflow and selection state |
| `hunter/qt/review_page.py` | Review workflow and JSON/DOCX export actions |
| `hunter/qt/settings_sync.py` | Settings, sync actions, and Sigma source forms |
| `hunter/qt/models.py` | Qt list/table models and search proxy |
| `hunter/qt/formatting.py` | Shared Qt text/JSON preview formatting |
| `hunter/qt/detail_renderers.py` | Readable HTML detail rendering |
| `hunter/qt/entity_editors.py` | Structured Threat and Tool editors |
| `hunter/qt/theme.py` | Qt stylesheet |
| `hunter/search_query.py` | Mini-query parser and matcher |
| `hunter/search_documents.py` | Shared entity search document builder |
| `hunter/services/authoring_service.py` | Threat/tool authoring persistence |
| `hunter/services/sigma_service.py` | Sigma rule lookup and summaries |

---

## Architecture

HUNTER v2.1 uses a Qt shell plus backend facade model.

Runtime flow:

```text
main.py
  -> hunter.qt_app.run()
    -> HunterMainWindow
      -> KnowledgeStore
      -> SyncService
      -> HuntGenerator
      -> SigmaRuleService
      -> AuthoringService
      -> Qt renderers and structured editors under hunter/qt/
```

Backend responsibilities:

- `KnowledgeStore`: SQLite persistence facade
- `SyncService`: source synchronization facade
- `LayeredEntityService`: local layered module read/write support
- `AuthoringService`: create, update, delete, and branch-style entity helpers
- `HuntGenerator`: hunt pack generation
- `SigmaRuleService`: Sigma matching and coverage summaries

The old pre-Qt UI packages have been removed from the active runtime.

---

## Data And Portability

HUNTER is designed so the repository can be copied to another machine or folder
without manually repairing the database.

Portable identity model:

- local module identity: `source_ref`
- layered index identity: `relative_path`
- runtime filesystem path: derived from the current project root
- remote source identity: `source_url`

Examples:

- threat module: `threats/apt33.json`
- tool module: `tools/kibana.json`

On startup, HUNTER reconciles stale absolute local paths back to repo-relative
refs and refreshes cached absolute paths for the current machine.

Local-only generated artifacts:

- `node_modules/`: DOCX export dependencies installed by `npm ci`
- `data/hunter_v2.sqlite3`: runtime SQLite database
- `data/snapshots/`: sync preview/apply/rollback snapshots
- `data/exports/` and `data/imports/`: offline knowledge bundle scratch folders
- `generated_hunt_pack_report.docx`: sample/exported report output
- `vendor/python/`: repaired Python vendor packages
- `dist/`: generated offline release bundles

These paths are ignored by git. Keep source-of-truth changes in `modules/`,
Python/JavaScript source files, package manifests, and tests.

---

## Development And Tests

For development dependencies, install from `requirements-dev.txt` in the same
Python environment used to run HUNTER.

Recommended focused test groups:

```bash
python -m pytest tests/test_qt_models.py tests/test_qt_entity_editors.py tests/test_qt_detail_renderers.py -q
python -m pytest tests/test_qt_shell_smoke.py tests/test_qt_generate_page.py tests/test_qt_review_page.py tests/test_qt_settings_dialog.py -q
python -m pytest tests/test_qt_detail_renderers.py tests/test_search_query.py tests/test_entity_search.py -q
python -m pytest tests/test_repo_integrity.py tests/test_vendor_runtime.py -q
```

Other useful coverage:

```bash
python -m pytest tests/test_hunt_service.py tests/test_export_controller.py -q
python -m pytest tests/test_sync_layered_modules.py tests/test_tool_catalog_compiler.py -q
```

Repository hygiene expectations:

- no tracked `*.pyc` or `__pycache__` artifacts
- no active imports of Tkinter
- no current docs pointing to removed old UI paths
- current UI code lives under `hunter/qt/`

---

## Troubleshooting

### The app opens but threats or tools are missing

Open `Settings / Sync` from the gear button, then run:

- MITRE sync if ATT&CK is missing
- `Load Layered Modules` if local threats/tools have not been loaded

### The project was moved and edits or deletes stopped working

Restart HUNTER once. Startup reconciliation should repair layered source config
and local module refs for the current project root.

### Search does not find what you expect

Try a fielded query or quoted phrase:

```text
id:T1041
technique:T1041
alias:"Peach Sandstorm"
indicator:evil.example
platform:Elastic -deprecated
```

### A threat or tool save feels slow

The common causes are:

- very large structured payloads
- file permission issues
- malformed module data triggering validation or file retry behavior

### DOCX export fails

Check:

1. Node.js is installed and available on `PATH`.
2. `export_docx.js` exists in the project root.
3. `node_modules/docx` and `node_modules/jszip` exist, or allow HUNTER to install them.

### Sigma sync or translation says a Python dependency is missing

Check:

1. `vendor/requirements.txt` exists.
2. `vendor/python/` exists after vendor install completes.
3. Accept the startup install prompt or use
   `Settings / Sync -> Install/Repair Python Vendor Packages`.

### Layered sync shows warnings

Malformed files are kept in the layered index with warning state and retried on
later manual syncs. Fix the JSON shown in the warning detail and rerun layered
sync.

### A tool does not cover a technique

This is expected for `partial_specialist` tools when the technique is outside
the tool's declared applicability. Review the tool coverage metadata before
treating it as a bug.

---

## Historical Reference

Historical notes for earlier architectures may exist in archived copies, but
the maintained runtime documentation is this README.
