# DumpScope

**A desktop workbench for Windows memory forensics, built on Volatility 3.**

DumpScope adds a guided interface and a case database to
[Volatility 3](https://github.com/volatilityfoundation/volatility3). You can work
through a memory image without remembering command-line syntax, and you can
come back to the same case days later with your results, notes and bookmarks
still there.

- **Stack:** Python 3.12+ (3.14 recommended) · PyQt6 6.7+ · Volatility 3 · SQLite
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
| Downloaded symbols land in a cache shared by every investigation | Each case keeps its own symbols and identifier cache. PDBs that vol3 downloads for an image are written into that case. |
| Each plugin shows only its own slice of the story | An incident timeline merges the timestamps from every plugin, and an insights engine flags what an examiner would look for first. |
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
    symbols/      ISF symbol tables for this case's images (incl. downloaded PDBs)
    cache/        volatility3's identifier cache for this case
    yara/         YARA rules
    exports/      CSV/JSON exports
    dumps/        files carved out of the image
    reports/      one folder per generated report
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
- **Per-case symbols:** every vol3 run reads its symbols from the case's
  `symbols/` folder and keeps its identifier cache in `cache/`. vol3's shared
  per-user cache (`~/.cache/volatility3`) is hidden from it. When vol3
  downloads a kernel PDB from Microsoft's symbol server and converts it, the
  result is written into the case, so a case folder carries every symbol
  table its results depended on. Tools → Symbols & YARA → **Fetch Symbols for
  This Image** fetches just what the loaded image needs, usually a few MB.
  The full offline packs (gigabytes) remain available.
- **Concurrency control:** Tools → *Parallel volatility3 Runs* sets how many
  vol3 processes may run at once (1–4, default 1). A waiting tab shows
  *Queued* instead of a frozen progress bar.

### Incident timeline
An Autopsy-style **Timeline** tab merges the timestamps from every plugin run on
the image into one chronology:

| Event | From |
| --- | --- |
| Process created / exited | pslist, psscan, pstree |
| DLL loaded | dlllist |
| Network connection or listener | netscan, netstat |
| Thread created | thrdscan, threads |
| Logon session | sessions |
| Program executed | UserAssist, ShimCache |
| File created / modified | mftscan |
| Driver unloaded | unloadedmodules |
| Anything else | timeliner, and any column that holds a time |

The tab shows a stacked histogram by event type above a filterable event
list. You can:
- **Drag** across the chart to zoom into a span.
- **Click** a bar to list just its events.
- **Scroll** to zoom around the cursor.
- **Double-click** to reset the zoom.
- **Toggle** event types from the legend.
- **Pick a time range** from the range button, Kibana-style:
  - *Quick select:* the first or last 5 minutes, 15 minutes, hour or 24 hours,
    or the whole capture. Ranges are relative to the image's own first and
    last events, not to today, because a memory image is frozen at the
    moment it was acquired.
  - *Absolute range:* From and To fields with calendar pop-ups, limited to
    the days the capture covers. The To second is included in full.
- **Search** across process, PID, path and address.
- **Export** the visible events to CSV.

Events reported by several plugins are de-duplicated. Command lines from
`cmdline` annotate process and network events. **Collect Timeline Data** runs
whichever source plugins haven't been run yet; they queue one at a time and
the view updates as each finishes. Quick Analysis builds the timeline from the
open result tabs.

### Insights
The **Insights** tab triages the stored output automatically. Each finding
has a severity, an explanation, the evidence behind it, and the plugin it came
from:

| Rule | Example |
| --- | --- |
| Hidden process | in psscan but not in pslist while still running (DKOM) |
| Unexpected parent | `lsass.exe` started by anything but `wininit.exe` |
| Duplicate system process | two running `lsass.exe` |
| Masquerading name | `scvhost.exe`, `lsas.exe` (one edit, including swapped letters) |
| System binary in the wrong place | `svchost.exe` running outside System32 |
| Suspicious location | executables in Temp, AppData, Public, the Recycle Bin |
| Suspicious command line | encoded PowerShell, download cradles, certutil/bitsadmin/mshta/regsvr32 abuse, shadow-copy deletion, credential dumping |
| Unusual network activity | Office, script hosts or LOLBins holding connections, high severity to public IPs |
| Suspicious port | 4444, 1337, 31337, Tor, IRC |
| Code injection | malfind regions with an MZ header or RWX pages |
| Suspicious service | service binaries in temp folders or launching script hosts |
| Credential material | hashdump, lsadump, cachedump results present |

The rules are written to stay quiet on a clean host. Parents that have exited
(normal for `csrss.exe` and `explorer.exe`), System32 paths in any spelling,
private-network traffic and listening sockets are not flagged. **Bookmark as
Finding** files the selected insight as a tagged bookmark, so it appears in
the report.

### Findings and reporting
- **Bookmarks and tags:** colour-coded tags (Suspicious, Malicious, Notable,
  Benign, Follow Up, or your own) with live counts in the sidebar.
- **Generate Report** (**Ctrl+R**) writes a self-contained folder inside the
  case. The work runs on a background thread with progress and cancel; a
  cancelled or failed report leaves nothing behind.
  ```
  <case>/reports/<Case_Name>_<YYYYmmdd-HHMMSS>/
    index.html           summary cards, insights, timeline chart, findings,
                         extracted files, analysis output, audit trail
    report.json          the same, machine-readable
    analysis/            every stored plugin run, in full, as CSV
    timeline/            the incident timeline per data source, as CSV
    insights.csv  bookmarks.csv  extracted_files.csv  audit_log.csv
    dumps/               the carved files (hard-linked, or copied)
    README.txt           what is in the folder, how to verify it
    SHA256SUMS           SHA-256 of every file (sha256sum -c compatible)
  ```
  `index.html` needs no network or JavaScript, and its chart is inline SVG,
  so it renders and prints anywhere. Every table links to its full CSV. All
  output from the suspect machine is HTML-escaped. Dumps are hard-linked when
  the filesystem allows it, so including gigabytes of process memory costs no
  extra space. You can also choose to always copy them or to leave them out.

### Interface
- **A neutral, instrument-style design.** The interface chrome is grey, and
  colour is reserved for what it means: severity, tags, timeline event types
  and plugin categories. One steel-blue accent marks focus, selection and the
  primary action. Each platform's own UI font is used (Segoe UI, the macOS
  system font, IBM Plex Sans or Noto Sans on Linux), and monospace is kept
  for evidence values such as PIDs, offsets and hashes.
- **Accessible in both themes.** Text meets WCAG AA contrast (4.5:1). Data
  colours tuned for the dark theme are darkened automatically in the light
  theme, keeping their hue, and a test enforces it. The window fits a
  1366 px laptop screen.
- Dark and light themes (**Ctrl+T**), with a choice of interface and
  monospace fonts.
- **Collapsible sidebar** (**Ctrl+B**, View → Sidebar, or the sidebar button
  at the left of the ribbon) gives the results the full width. The choice is
  remembered between sessions. The sidebar can also be dragged to the right
  or floated.
- **Many open tabs.** The button at the right end of the tab bar lists every
  open tab, pinned ones first, and can close all unpinned results.
  **Ctrl+Tab** / **Ctrl+Shift+Tab** (or **Ctrl+PgDn** / **Ctrl+PgUp**) cycle
  through tabs. Long plugin names are elided, so more tabs fit before the bar
  scrolls.
- **Command palette** (**Ctrl+Shift+P**) for every window action and plugin.
- Result tabs can be pinned. Pinned tabs have no close button and stay ahead
  of the others.
- The plugin ribbon scrolls sideways with the mouse wheel.
- In-window toast notifications, plus optional desktop notifications. A batch
  of runs is announced once when it finishes, not once per plugin.

### Reliability
- **A bug never takes the session down.** An unexpected error is logged with
  its traceback and reported in a dialog, and the window carries on; the case
  data is untouched. (PyQt6's default is to abort the whole process.)
  `faulthandler` records a traceback even for a hard interpreter crash.
- **Plugin output of any size.** Fields beyond the CSV module's 128 KB
  default, such as long malfind hexdumps and command lines, are read in full.
  If parsing fails partway, the vol3 process is stopped rather than left
  blocked on its pipe.
- **No handle leaks.** Every run closes its pipes, so a long session can run
  hundreds of plugins without hitting the open-file limit.
- **Damaged data degrades, it does not crash.** An unreadable stored result
  opens as "could not be read" and is listed as a warning in reports. Case,
  settings and recent-case files are written atomically.

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
6. Open **Insights** and **Timeline**. **Collect** fills in whatever plugins
   they still need. Bookmark the insights that hold up.
7. **Generate a report** (**Ctrl+R**). The folder in `reports/` is the
   deliverable: zip it, hand it over, and verify it with `sha256sum -c SHA256SUMS`.
8. Close the case and reopen it from the launcher later. Everything is still
   there.

### Keyboard shortcuts

| Shortcut | Action |
| --- | --- |
| Ctrl+O | Open image |
| Ctrl+B | Show or hide the sidebar |
| Ctrl+Tab / Ctrl+Shift+Tab | Next / previous tab (also Ctrl+PgDn / Ctrl+PgUp) |
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
| Case data, symbols, vol3 cache, reports | the case folder you chose | | |

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
  symbol_downloader.py  per-image PDB fetch into the case, symbol packs
  timeline.py           event extraction from plugin output, histogram
  insights.py           triage rules over plugin output
  report_bundle.py      the report folder: CSVs, dumps, manifest
  hash_worker.py        MD5/SHA-256 hashing off the GUI thread
  report.py             HTML / JSON case reports
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
that platform, gives every test its own config directory and a fresh run gate,
and destroys the windows each test leaves behind. Running the suite never
touches your real settings or recent-case list.

```bash
uv run pytest                 # whole suite (about 555 tests, under a minute)
uv run pytest -q tests/test_runner_crashes.py   # one file
uv run pytest -k "gate or corrupt"              # by keyword
```

`tests/stub_vol.py` stands in for vol3. It emits the awkward output shapes the
real CLI can produce: embedded commas and newlines, megabytes of stderr,
invalid UTF-8, ragged rows, corrupted-cache failures, and floods larger than a
pipe buffer. With `STUB_VOL_FIXTURES=1` it answers each plugin with realistic
output from `tests/vol_fixtures.py`. That fixture is a compromised host:
encoded PowerShell, a lookalike `scvhost.exe`, an injected explorer, a rogue
`lsass.exe` and an unlinked process. The end-to-end tests drive the real
window through collect → timeline → insights → report against it.

| Area | Files |
| --- | --- |
| Runner streaming and process handling | `test_vol_runner.py` |
| Crash and hang detection (bad output, missing vol3, cache corruption, cancel races) | `test_runner_crashes.py` |
| Run gate: serialisation, queueing, cancel while queued, slot release on crash | `test_run_gate.py` |
| Damaged files, hostile input and boundary values across `core/` | `test_edge_cases_core.py` |
| Windows under bad conditions (no image, deleted image, corrupt DB or settings) | `test_ui_edge_cases.py` |
| Timeline: timestamp formats, every extractor, de-duplication, histogram edges, 100k-event performance | `test_timeline.py` |
| Insights: every rule fires on the compromised host and stays quiet on a clean one | `test_insights.py` |
| Report folder: layout, manifest verification, links, hard-link/copy fallback, cancel and crash cleanup | `test_report_bundle.py` |
| Per-case symbols: CLI arguments, real vol3 path isolation, PDB fetch, no home-folder writes | `test_case_symbols.py` |
| Timeline/Insights/Report UI and the end-to-end window flow | `test_ui_analysis.py` |
| Timeline range picker: quick ranges, absolute From/To, inverted ranges | `test_time_range.py` |
| Tab overflow list, tab cycling, collapsible sidebar | `test_tab_overflow.py` |
| Crash regressions found by fuzzing (unicode PIDs, unreadable results, huge fields) | `test_hardening.py` |
| Cases, database, reports, OS detection, settings | `test_case*.py`, `test_database.py`, `test_report*.py`, `test_os_detect.py`, `test_settings_and_notifications.py` |
| Widgets: smoke construction, theme, ribbon, tabs, palette, result model | `test_ui_smoke.py`, `test_theme.py`, `test_plugin_ribbon.py`, `test_result_*.py`, `test_command_palette.py` |

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| *"symbol table … not found"* | Open Tools → Symbols & YARA → **Fetch Symbols for This Image** (needs access to `msdl.microsoft.com`). Offline: download the Windows pack, or copy the ISF for that build into the case's `symbols/` folder. |
| A case created before per-case symbols has no `cache/` folder | Nothing to do: it is created on the first run. Symbols previously downloaded to `~/.cache/volatility3/symbols` are no longer used by cases; fetch them again into the case, or copy them into its `symbols/` folder. |
| Timeline or Insights is empty | Use their **Collect** button. Both read stored results, so plugins have to have run on the *active* data source. |
| Credential plugins missing | Install `pycryptodome` (`uv sync` does this), then Tools → Refresh Plugin List. |
| *"cache appears to be corrupted … clearing it did not help"* | Delete the folder named in the message (the case's `cache/` folder) and run the plugin again. |
| A plugin tab says *Queued* | Another vol3 run is in progress. Wait, cancel it, or raise Tools → Parallel volatility3 Runs. |
| Windows: *"uv trampoline failed to canonicalize script path"* | Already handled: DumpScope calls volatility3 through the interpreter, not the `vol.exe` script. Make sure you launch with the venv's `python.exe`. |

## Roadmap

What is planned next, and why, is in [ROADMAP.md](ROADMAP.md).

## Background

DumpScope grew out of an earlier prototype named *memfor*, a simpler wizard
interface built with Qt Designer for the same Windows forensics scope. Its
worker-and-signal architecture was later reused as the basis for a separate
Linux memory forensics tool.

## Author

Om Nagda
