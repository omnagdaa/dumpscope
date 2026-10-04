# DumpScope

**A desktop workbench for Windows memory forensics, built on Volatility 3.**

DumpScope adds a guided interface and a case database to
[Volatility 3](https://github.com/volatilityfoundation/volatility3). You can work
through a memory image without remembering command-line syntax, and you can
come back to the same case days later with your results, notes and bookmarks
still there.

- **Stack:** Python 3.12+ (3.14 recommended) · PyQt6 · Volatility 3 · SQLite
- **Target:** Windows memory images (`.raw`, `.mem`, `.vmem`, `.dmp`, `.img`,
  `.bin`, crash dumps, hibernation files, VMware snapshots). Linux and macOS images are detected, and their
  plugins can be shown, but they are not the focus.
- **Project page:** <https://omnagdaa.github.io/projects/dumpscope/>

---

## Why

Volatility 3 is the standard tool for memory analysis, but it runs only from
the command line:

| Problem with the bare CLI | What DumpScope does |
| --- | --- |
| New analysts must learn commands and options first | Plugins are one click away on a categorised ribbon. Arguments come from a form built from the plugin's own requirements. |
| Output is plain text that isn't linked to a case | Results stream into sortable, filterable tables and are stored in a per-case SQLite database. |
| Wrong OS or symbols give failed or misleading output | The image is identified *before* analysis: header sniffing first, then `windows.info`, then a banner scan. |
| Long plugins freeze a naive GUI | Every vol3 run happens in a `QThread` worker that streams rows back through Qt signals. |
| Concurrent vol3 runs fight over the symbol cache | A run gate lets one vol3 process run at a time by default. Other runs queue and can be cancelled while they wait. |
| A corrupted symbol cache breaks every later run | The corruption is recognised on stderr and the run is retried once with `--clear-cache`. |
| Investigations span days | A case is a self-contained folder that you can reopen, move, archive or hand over. |

## Features

### Case management
- **Case launcher** lists recent cases. From it you can create a new case,
  open a case folder from disk, or start a **Quick Analysis** that saves
  nothing.
- **New Case wizard** records the case name and number, examiner details and
  notes, then takes the image by drag-and-drop or file picker.
- **Self-contained case folders:**
  ```
  <case>/
    case.json     portable metadata, readable without the app
    <name>.db     results, bookmarks, tags, extracted files, audit trail
    symbols/      ISF symbol tables scoped to this case
    yara/         YARA rules
    exports/      CSV/JSON exports
    dumps/        files carved out of the image
    reports/      generated reports
  ```
- **Multiple data sources per case,** each with MD5 and SHA-256 hashes.
- **Audit trail** of case opens, image loads, plugin runs, extractions and
  deletions.

### Analysis
- **Plugin ribbon** groups plugins into Processes, Network, Memory, Registry,
  System, Credentials and Malware categories. The ribbon shows only plugins
  that apply to the detected OS, and **Ctrl+P** searches every installed
  plugin.
- **Plugin argument dialog** is generated from the plugin's own requirements
  (int, string, list, boolean and so on). YARA scans pick up the case's rules
  automatically.
- **Streaming result tables** use vol3's CSV renderer, so values that contain
  commas, spaces or newlines survive intact. Columns can be sorted and filtered,
  rows can be bookmarked, and tables export to CSV, JSON or TSV.
- **Process extraction:** right-click a process row to dump its executable,
  DLLs or full memory into `dumps/`. Each written file is recorded and hashed
  as soon as it lands.
- **Credentials:** hashdump, lsadump and cachedump appear on the ribbon, and
  Tools → Extract Credentials runs all three. You can also dump LSASS memory
  for offline analysis with pypykatz.
- **Symbols & YARA manager:** download the official symbol packs into the
  case, and open the case's `symbols/` and `yara/` folders to add your own ISF
  files and rules.
- **Concurrency control:** Tools → *Parallel volatility3 Runs* sets how many
  vol3 processes may run at once (1–4, default 1). A waiting tab shows
  *Queued* instead of a frozen progress bar.

### Findings and reporting
- **Bookmarks and tags:** colour-coded tags (Suspicious, Malicious, Notable,
  Benign, Follow Up, or your own) with live counts in the sidebar.
- **Case report** in HTML or JSON, covering case details, data sources and
  hashes, plugin output (capped per plugin), findings by tag, extracted files
  and the audit log. All output from the suspect machine is HTML-escaped.
- **Email a report** over SMTP with STARTTLS, SSL or no encryption. The
  password is asked for at send time and never stored.

### Interface
- Dark and light themes (**Ctrl+T**), with a choice of interface and
  monospace fonts.
- **Command palette** (**Ctrl+Shift+P**) for every window action and plugin.
- Result tabs can be pinned. Pinned tabs have no close button and stay ahead
  of the others.
- In-window toast notifications, plus optional desktop notifications when a
  run or a batch of runs finishes.

## Install

Requires Python 3.12 or newer and [uv](https://docs.astral.sh/uv/)
(recommended) or pip.

```bash
git clone https://github.com/omnagdaa/dumpscope.git
cd dumpscope
uv sync                    # creates .venv with PyQt6, volatility3, pycryptodome
```

With pip:

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

> `pycryptodome` is a hard dependency. Without it, volatility3's credential
> plugins fail to import and vanish silently, with no error.

## Run

```bash
uv run python main.py                    # case launcher
uv run python main.py --case ~/cases/Op_Nightfall   # open a case directly
uv run python main.py --analysis         # Quick Analysis, nothing saved
uv run python main.py --log dumpscope.log         # also write a debug log
uv run python main.py --refresh-plugins  # re-inspect volatility3's plugin list
```

The first launch inspects volatility3 for its plugin list, which takes a few
seconds. The result is cached and rebuilt automatically when volatility3 is
upgraded.

### Typical workflow
1. **New Case:** fill in the case and examiner details, then drop in the
   memory image.
2. DumpScope **identifies the image**. The sidebar badge shows the OS, how
   sure it is, and the Windows build.
3. Optionally **Compute Hashes** to record MD5 and SHA-256 of the evidence.
4. **Run plugins** from the ribbon. Rows stream into a tab per plugin and are
   saved to the case when the run finishes.
5. **Bookmark and tag** rows of interest, and **extract** suspicious processes
   for sandbox or static analysis.
6. **Generate a report** (**Ctrl+R**) and optionally email it.
7. Close the case and reopen it from the launcher later. Everything is still
   there.

### Keyboard shortcuts

| Shortcut | Action |
| --- | --- |
| Ctrl+O | Open image |
| Ctrl+P | Search plugins |
| Ctrl+Shift+P | Command palette |
| Ctrl+E | Export current results |
| Ctrl+R | Generate case report |
| Ctrl+T | Toggle dark/light theme |
| Ctrl+W | Close case (back to the launcher) |
| Ctrl+Q | Quit |

## Where things are stored

| What | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Settings, recent cases | `$XDG_CONFIG_HOME/dumpscope` (`~/.config/dumpscope`) | `~/Library/Application Support/dumpscope` | `%APPDATA%\dumpscope` |
| Plugin registry cache | `$XDG_CACHE_HOME/dumpscope` | `~/Library/Caches/dumpscope` | `%LOCALAPPDATA%\dumpscope` |
| Case data | the case folder you chose | | |

`settings.json` is validated when it is loaded. A value of the wrong type or
out of range, such as `"font_size": "big"`, falls back to its default and does
not crash the app.

## Architecture

```
main.py                 entry point: logging, plugin registry, case loop
core/                   no widgets; everything here is unit-testable
  case.py               case folders, case.json, the recent-case list
  database.py           per-case SQLite (results, sources, tags, bookmarks, audit)
  vol_runner.py         VolatilityRunner (QThread), RunSpec, RunGate, cache recovery
  os_detect.py          header sniffing + windows.info / banners probe
  plugins.py            plugin introspection, curated catalog, argument building
  symbol_downloader.py  symbol-pack download and safe extraction
  hash_worker.py        MD5/SHA-256 hashing off the GUI thread
  report.py             HTML / JSON case reports
  mailer.py             SMTP delivery
  settings.py, paths.py user preferences and per-platform directories
ui/                     PyQt6 windows, dialogs and widgets
tests/                  pytest suite (runs headless)
```

**How a plugin run works.** The UI builds a `RunSpec` and starts a
`VolatilityRunner`. The runner waits for a slot on the shared `RunGate`, then
launches vol3 as a subprocess using the CSV renderer. It parses stdout with
`csv.reader` straight off the pipe, so multi-line fields survive. A dedicated
thread drains stderr, which prevents the classic full-pipe deadlock and turns
vol3's `\r` progress lines into progress signals. Rows reach the UI in batches
of 250 rows or 100 ms, whichever comes first.

If a run fails with a corrupted-cache signature (`database disk image is
malformed`, `JSONDecodeError`, `LZMAError` and similar) before producing any
rows, it is retried once with `--clear-cache`. If the retry fails too, the error
message names the cache folder to delete.

## Testing

The suite runs headless on Qt's offscreen platform. `tests/conftest.py` sets
that platform and gives every test its own config directory, so running the
suite never touches your real settings or recent-case list.

```bash
uv run pytest                 # whole suite (about 370 tests, about a minute)
uv run pytest -q tests/test_runner_crashes.py   # one file
uv run pytest -k "gate or corrupt"              # by keyword
```

`tests/stub_vol.py` stands in for vol3. It emits the awkward output shapes the
real CLI can produce: embedded commas and newlines, megabytes of stderr,
invalid UTF-8, ragged rows, corrupted-cache failures, and floods larger than a
pipe buffer.

| Area | Files |
| --- | --- |
| Runner streaming and process handling | `test_vol_runner.py` |
| Crash and hang detection (bad output, missing vol3, cache corruption, cancel races) | `test_runner_crashes.py` |
| Run gate: serialisation, queueing, cancel while queued, slot release on crash | `test_run_gate.py` |
| Damaged files, hostile input and boundary values across `core/` | `test_edge_cases_core.py` |
| Windows under bad conditions (no image, deleted image, corrupt DB or settings) | `test_ui_edge_cases.py` |
| Cases, database, reports, mailer, OS detection, settings | `test_case*.py`, `test_database.py`, `test_report*.py`, `test_mailer.py`, `test_os_detect.py`, `test_settings_and_notifications.py` |
| Widgets: smoke construction, theme, ribbon, tabs, palette, result model | `test_ui_smoke.py`, `test_theme.py`, `test_plugin_ribbon.py`, `test_result_*.py`, `test_command_palette.py` |

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| *"symbol table … not found"* | Open Tools → Symbols & YARA and download the Windows pack, or copy the ISF for that build into the case's `symbols/` folder. |
| Credential plugins missing | Install `pycryptodome` (`uv sync` does this), then Tools → Refresh Plugin List. |
| *"cache appears to be corrupted … clearing it did not help"* | Delete the folder named in the message (usually `~/.cache/volatility3`) and run the plugin again. |
| A plugin tab says *Queued* | Another vol3 run is in progress. Wait, cancel it, or raise Tools → Parallel volatility3 Runs. |
| Windows: *"uv trampoline failed to canonicalize script path"* | Already handled: DumpScope calls volatility3 through the interpreter, not the `vol.exe` script. Make sure you launch with the venv's `python.exe`. |

## Background

DumpScope grew out of an earlier prototype named *memfor*, a simpler wizard
interface built with Qt Designer for the same Windows forensics scope. Its
worker-and-signal architecture was later reused as the basis for a separate
Linux memory forensics tool.

## Author

Om Nagda
