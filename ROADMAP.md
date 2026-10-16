# DumpScope Roadmap

What comes next, roughly in order. Each item says what problem it solves for
an examiner, not just what it adds. Sizes are rough: **S** is days, **M** is a
week or two, **L** is longer.

Nothing here has a date. Order changes as real cases show what hurts most.

## Principles that every item has to respect

- **Offline first.** A lab machine is often air-gapped. Anything that talks to
  the network (symbol downloads, hash lookups) is opt-in, says exactly what it
  sends, and has an offline path.
- **Evidence integrity.** The image is never written to. Every derived file is
  hashed when it is created, and every action lands in the audit trail.
- **No telemetry.** DumpScope reports nothing about its users or their cases.
- **Readable by a court.** Whatever DumpScope concludes has to be traceable to
  the plugin output it came from.

---

## Next: making a case faster to work

### Pivot on a process — M
Right-click any PID, in any table, the timeline or an insight, and choose
**Everything about PID 2520**. One view shows its command line, parent chain,
DLLs, handles, network connections, injected regions, services and timeline
events. Today that means opening six tabs and filtering each one by hand, and
it is the move an examiner makes most.

### Process tree view — S
`pstree` output shown as an actual expandable tree, with exited parents
greyed and processes named in insights highlighted. Wrong parentage is far
easier to see in a tree than in a flat table with a depth column.

### Run queue panel — S
A small panel listing every queued and running plugin, with progress, and the
ability to cancel or reorder. Running a dozen plugins at once currently means
finding each one's tab to see where it is.

### Triage playbooks — S
One click runs a named set of plugins, such as *Initial triage*, *Network*,
*Persistence* or *Credential access*, through the run gate. Playbooks are
plain JSON files in the case or user folder, so a lab can share its own.

### Case-wide search — M
Search every stored result in the case at once, such as an IP, a hash or a
file name, and jump to the matching rows. Built on SQLite FTS5, so it stays
fast on large cases and needs no extra service.

### Saved timeline views — S
Name and save a timeline range, event-type selection and search, so
"09:41 to 09:43, network and process only" can be reopened later and put in
the report as is.

---

## Then: detection that goes further

### IOC import and matching — M
Import a list of indicators (IPs, domains, hashes, file names, mutexes) from
CSV or STIX 2.1. DumpScope matches them across every stored result and raises
each hit as an insight that links to its evidence rows.

### MITRE ATT&CK mapping — S
Tag each insight rule with its ATT&CK technique, for example T1055 Process
Injection or T1036 Masquerading. Show the techniques in the Insights tab and
the report, so a finding reads in the vocabulary incident responders already
use.

### User-defined insight rules — M
Rules written in a small YAML format (match a plugin's columns, set a
severity, explain why) alongside the built-in ones. A lab can encode what it
has learned without changing the code. Rules are validated when loaded, and
a broken rule is reported rather than silently skipped.

### YARA workflow — M
Manage rule files from the UI, run them against processes or the whole image,
and show matches as insights with the matching bytes. The case `yara/` folder
already exists; this makes it first class.

### Known-good filtering — M
Mark files and processes that match an NSRL or local known-good hash set, and
optionally hide them, so the examiner reads what is unusual first.

### Hash reputation lookup — S (opt-in)
For extracted files, look up their SHA-256 (the hash only, never the file) in
MalwareBazaar or VirusTotal with the examiner's own API key. Results are
cached in the case so the lookup is recorded and not repeated.

### Baseline comparison — L
Compare an image against a known-clean image of the same build, or against an
earlier image of the same host: new processes, new services, new drivers, new
listening ports. "What changed" is often the fastest route to the intrusion.

---

## Reporting and evidence handling

### Signed reports — S
Sign `SHA256SUMS` with the examiner's key (minisign or GPG), so a recipient
can verify not only that the report is intact but who produced it.

### Timesketch and Plaso export — S
Export the incident timeline in the CSV and JSONL shapes Timesketch imports,
so memory events can be merged with disk and log timelines.

### Read-only case mode — S
Open a case for review without being able to change it, for a second examiner
or a supervisor checking the work.

### Examiner notes on rows — S
A free-text note on any row or finding, kept in the audit trail and included
in the report beside the evidence it describes.

---

## Scale and platform

### Results stored as rows, not blobs — M
Each stored run is currently one JSON blob. A `filescan` or `handles` run with
a million rows has to be decoded whole to show one page. Storing rows in their
own table, with paging, keeps large cases fast and makes case-wide search
straightforward.

### Installers and CI — M
- Signed Windows installer and a Linux AppImage or Flatpak, so examiners do
  not need Python.
- CI on GitHub Actions runs the headless test suite on Windows, Linux and
  macOS for every change.

### Linux and macOS image support — L
The detection, ribbon and runner already handle Linux and macOS images. The
timeline extractors and insight rules are Windows-only today and need their
own equivalents: bash history, `lsof`, kernel modules and the macOS process
list.

### Accessibility — M
- Full keyboard navigation of the ribbon.
- Accessible names on every control, for screen readers.
- A high-contrast theme.
- A UI scale setting beyond font size.

---

## Known limitations being tracked

- **Parallel runs and a second kernel:** while a case has no symbols yet,
  vol3 runs go one at a time, so two runs cannot race the first PDB download.
  A second image with a *different* kernel in the same case can still race
  on its own PDB. The fix is to gate per PDB GUID (`core/vol_runner.py`,
  `awaiting_case_symbols`).
- **Quick Analysis** keeps results only in open tabs. Closing a tab loses that
  run, by design, since nothing is saved in that mode.

---

## Under consideration

Ideas worth having but not yet clearly worth their cost:

- An optional, offline, local-model summary of the findings for the report's
  executive section. It would always show the evidence each sentence rests on.
- Multi-examiner cases, with merged bookmarks and per-examiner audit trails.
- Live acquisition through WinPmem, from the same window.
- Translation of the interface.

Suggestions are welcome as GitHub issues. The most useful ones describe the
case where DumpScope got in the way.
