"""
The case report as a folder.

Generating a report writes one self-contained folder inside the case:

    <case>/reports/<Case_Name>_<YYYYmmdd-HHMMSS>/
        index.html              the report: summary, insights, timeline, output
        report.json             the same, machine-readable
        README.txt              what is in the folder and how to verify it
        analysis/               every stored plugin run, in full, as CSV
        timeline/               the incident timeline per data source, as CSV
        insights.csv            automatic triage leads
        bookmarks.csv           findings the examiner tagged
        extracted_files.csv     what was carved out of the image, with hashes
        audit_log.csv           everything done to the case
        dumps/                  the carved files themselves
        SHA256SUMS              a hash of every file above (sha256sum -c format)

The folder is the deliverable: it can be zipped, handed over or archived and
still be read without DumpScope. Dumps are hard-linked when the filesystem
allows it, so including multi-gigabyte process memory costs no extra space;
otherwise they are copied.
"""

from __future__ import annotations

import csv
import hashlib
import logging
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from core import insights as insight_rules
from core import timeline as timeline_rules
from core.report import DEFAULT_MAX_ROWS, build_html, build_json

log = logging.getLogger("dumpscope.report_bundle")

DUMP_MODES = ("link", "copy", "none")
MANIFEST = "SHA256SUMS"
_CHUNK = 1024 * 1024 * 8


class BundleCancelled(Exception):
    """The examiner stopped the report; the partial folder has been removed."""


@dataclass
class BundleOptions:
    dump_mode: str = "link"            # link | copy | none
    include_output: bool = True        # analysis output inline in index.html
    include_audit: bool = True
    max_rows: int = DEFAULT_MAX_ROWS


@dataclass
class BundleResult:
    path: str
    files: int = 0
    dumps_linked: int = 0
    dumps_copied: int = 0
    dumps_missing: list[str] = field(default_factory=list)
    insights: int = 0
    events: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def index(self) -> str:
        return os.path.join(self.path, "index.html")


def _safe(name: str, fallback: str = "item") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(name or "")).strip("._-")
    return cleaned[:80] or fallback


def bundle_dirname(case_name: str, when: datetime | None = None) -> str:
    when = when or datetime.now()
    return f"{_safe(case_name, 'case')}_{when.strftime('%Y%m%d-%H%M%S')}"


def _unique_dir(parent: str, name: str) -> str:
    """Create and return parent/name, adding -2, -3… if it already exists."""
    os.makedirs(parent, exist_ok=True)
    candidate, n = os.path.join(parent, name), 1
    while True:
        try:
            os.mkdir(candidate)
            return candidate
        except FileExistsError:
            n += 1
            candidate = os.path.join(parent, f"{name}-{n}")


def _write_csv(path: str, header: list[str], rows) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # utf-8-sig so Excel opens non-ASCII process names correctly.
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        for row in rows:
            writer.writerow(["" if c is None else str(c) for c in row])


def sha256_file(path: str, cancelled: Callable[[], bool] = lambda: False) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            if cancelled():
                raise BundleCancelled()
            block = handle.read(_CHUNK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _place_file(source: str, target: str, mode: str) -> str:
    """Link or copy one file. Returns "linked" or "copied"."""
    os.makedirs(os.path.dirname(target), exist_ok=True)
    if mode == "link":
        try:
            os.link(source, target)
            return "linked"
        except OSError:
            pass                        # another filesystem, FAT, no permission
    shutil.copy2(source, target)
    return "copied"


def _source_label(source: dict | None) -> str:
    if not source:
        return "Unassigned results"
    return source.get("display_name") or os.path.basename(source.get("path", "")) \
        or f"Source {source.get('id')}"


def _latest_by_source(results: list[dict]) -> dict:
    """{source id or None: {plugin: result}} keeping the newest run of each."""
    groups: dict = {}
    for result in results:          # get_results() is newest first
        groups.setdefault(result.get("source_id"), {}).setdefault(
            result["plugin"], result)
    return groups


def build_bundle(case, db, reports_root: str | None = None,
                 options: BundleOptions | None = None,
                 progress: Callable[[int, str], None] | None = None,
                 cancelled: Callable[[], bool] | None = None) -> BundleResult:
    """
    Write the report folder for `case` from `db` and return what was written.

    `progress(percent, message)` is called as work proceeds; `cancelled()` is
    polled, and when it returns True the partial folder is removed and
    BundleCancelled is raised.
    """
    options = options or BundleOptions()
    if options.dump_mode not in DUMP_MODES:
        raise ValueError(f"Unknown dump mode: {options.dump_mode}")
    report = progress or (lambda pct, msg: None)
    stop = cancelled or (lambda: False)

    root = reports_root or os.path.join(case.directory, "reports")
    folder = _unique_dir(root, bundle_dirname(case.case_name))
    result = BundleResult(path=folder)
    try:
        _build(case, db, folder, options, result, report, stop)
    except BundleCancelled:
        shutil.rmtree(folder, ignore_errors=True)
        raise
    except Exception:
        # A half-written report is worse than none: it looks complete.
        shutil.rmtree(folder, ignore_errors=True)
        raise
    return result


def _check(stop):
    if stop():
        raise BundleCancelled()


def _build(case, db, folder, options, result, report, stop):
    report(2, "Reading the case database…")
    sources = db.get_data_sources()
    results = db.get_results()
    bookmarks = db.get_bookmarks()
    audit = db.get_audit_log()
    extractions = db.get_extractions()
    by_id = {s["id"]: s for s in sources}
    files: dict[str, str] = {}

    # ── Every stored run, in full ────────────────────────────────────────────
    outputs: dict[int, dict] = {}
    result_links: dict[int, str] = {}
    used_names: set[str] = set()
    for n, item in enumerate(results, start=1):
        _check(stop)
        report(5 + int(25 * n / max(len(results), 1)),
               f"Exporting {item['plugin']} ({n}/{len(results)})…")
        try:
            payload = db.load_result(item["id"])
        except (ValueError, TypeError) as exc:
            result.warnings.append(f"Result {item['id']} could not be read: {exc}")
            continue
        if not payload:
            continue
        outputs[item["id"]] = payload
        name = f"{_safe(item['plugin'].rsplit('.', 1)[-1], 'plugin')}_{item['id']}.csv"
        while name in used_names:
            name = "_" + name
        used_names.add(name)
        relative = os.path.join("analysis", name)
        columns = payload.get("columns") or []
        rows = [r for r in payload.get("rows") or [] if isinstance(r, (list, tuple))]
        _write_csv(os.path.join(folder, relative), columns or ["value"], rows)
        result_links[item["id"]] = relative
        files[relative] = f"{item['plugin']} run {item['id']}"

    # ── Timeline and insights, per data source ───────────────────────────────
    _check(stop)
    report(32, "Building the incident timeline…")
    timelines: list[tuple[str, list]] = []
    timeline_links: dict[str, str] = {}
    findings_all = []
    for source_id, latest in _latest_by_source(results).items():
        label = _source_label(by_id.get(source_id))
        payloads = []
        for run in latest.values():
            payload = outputs.get(run["id"])
            if payload:
                payloads.append(dict(payload, plugin=run["plugin"]))
        events = timeline_rules.build_events(payloads)
        if events:
            relative = os.path.join("timeline", f"{_safe(label, 'source')}.csv")
            while os.path.exists(os.path.join(folder, relative)):
                relative = relative[:-4] + "_.csv"
            _write_csv(os.path.join(folder, relative),
                       timeline_rules.EVENT_COLUMNS + ["Detail"],
                       (e.as_row() + [e.detail] for e in events))
            timelines.append((label, events))
            timeline_links[label] = relative
            files[relative] = f"Timeline for {label}"
            result.events += len(events)
        for finding in insight_rules.analyse(payloads):
            findings_all.append(finding)
    result.insights = len(findings_all)

    insights_rel = ""
    if findings_all:
        insights_rel = "insights.csv"
        _write_csv(os.path.join(folder, insights_rel), insight_rules.FINDING_COLUMNS,
                   (f.as_row() for f in findings_all))
        files[insights_rel] = "Automatic triage findings"

    # ── Tables of record ─────────────────────────────────────────────────────
    _check(stop)
    report(40, "Writing bookmarks, extracted files and audit log…")
    _write_csv(os.path.join(folder, "bookmarks.csv"),
               ["Label", "Tag", "Plugin", "Source", "Notes", "Detail", "Added"],
               ([b.get("label"), b.get("tag"), b.get("artifact_type"),
                 b.get("source_name"), b.get("notes"), b.get("description"),
                 b.get("created_at")] for b in bookmarks))
    _write_csv(os.path.join(folder, "audit_log.csv"),
               ["Timestamp", "Action", "Detail", "Examiner"],
               ([a.get("created_at"), a.get("action"), a.get("detail"),
                 a.get("examiner")] for a in audit))
    files["bookmarks.csv"] = "Bookmarked findings"
    files["audit_log.csv"] = "Audit trail"

    # ── Dumps ────────────────────────────────────────────────────────────────
    extraction_links: dict[str, str] = {}
    if options.dump_mode != "none":
        _place_dumps(case, folder, extractions, options.dump_mode, result,
                     extraction_links, report, stop)
    _write_csv(os.path.join(folder, "extracted_files.csv"),
               ["File in bundle", "Original path", "Contents", "PID", "Process",
                "Plugin", "Size", "SHA-256 at extraction", "Extracted"],
               ([extraction_links.get(e["path"], ""), e["path"], e.get("kind"),
                 e.get("pid"), e.get("process"), e.get("plugin"),
                 e.get("size_bytes"), e.get("sha256"), e.get("created_at")]
                for e in extractions))
    files["extracted_files.csv"] = "Extracted files and their hashes"

    # ── The report itself ────────────────────────────────────────────────────
    _check(stop)
    report(75, "Rendering the report…")
    links = {
        "results": result_links,
        "extractions": extraction_links,
        "timeline": timeline_links,
        "insights": insights_rel,
        "footer": "Every table in this report is available in full as CSV in this "
                  "folder; SHA256SUMS lists a hash of every file.",
    }
    html = build_html(
        case, sources, results, bookmarks, audit,
        include_audit=options.include_audit, extractions=extractions,
        outputs=outputs if options.include_output else None,
        max_rows=options.max_rows, insights=findings_all, timelines=timelines,
        links=links,
    )
    with open(os.path.join(folder, "index.html"), "w", encoding="utf-8") as handle:
        handle.write(html)
    with open(os.path.join(folder, "report.json"), "w", encoding="utf-8") as handle:
        handle.write(build_json(case, sources, results, bookmarks, audit,
                                extractions=extractions, insights=findings_all,
                                timelines=timelines,
                                files={k.replace(os.sep, "/"): v for k, v in files.items()}))
    with open(os.path.join(folder, "README.txt"), "w", encoding="utf-8") as handle:
        handle.write(_readme(case, result))

    # ── Manifest ─────────────────────────────────────────────────────────────
    _write_manifest(folder, result, report, stop)
    report(100, "Report complete.")


def _place_dumps(case, folder, extractions, mode, result, links, report, stop):
    """Mirror the case's dumps folder, plus any recorded extraction outside it."""
    dumps_root = os.path.join(case.directory, "dumps")
    sources: list[tuple[str, str]] = []           # (absolute source, bundle-relative)
    if os.path.isdir(dumps_root):
        for base, _dirs, names in os.walk(dumps_root):
            for name in sorted(names):
                path = os.path.join(base, name)
                sources.append((path, os.path.join(
                    "dumps", os.path.relpath(path, dumps_root))))
    covered = {os.path.normcase(os.path.abspath(p)) for p, _ in sources}
    for item in extractions:
        path = item.get("path") or ""
        if item.get("missing") or not path:
            result.dumps_missing.append(path)
            continue
        if os.path.normcase(os.path.abspath(path)) not in covered:
            sources.append((path, os.path.join("dumps", "external",
                                               _safe(os.path.basename(path), "file"))))

    for n, (path, relative) in enumerate(sources, start=1):
        _check(stop)
        report(42 + int(30 * n / max(len(sources), 1)),
               f"Adding dumps ({n}/{len(sources)})…")
        try:
            how = _place_file(path, os.path.join(folder, relative), mode)
        except OSError as exc:
            result.warnings.append(f"Could not include {path}: {exc}")
            continue
        if how == "linked":
            result.dumps_linked += 1
        else:
            result.dumps_copied += 1
        links[path] = relative


def _write_manifest(folder, result, report, stop):
    entries = []
    for base, _dirs, names in os.walk(folder):
        for name in names:
            path = os.path.join(base, name)
            relative = os.path.relpath(path, folder)
            if relative != MANIFEST:
                entries.append((relative.replace(os.sep, "/"), path))
    entries.sort()
    lines = []
    total = max(len(entries), 1)
    for n, (relative, path) in enumerate(entries, start=1):
        report(80 + int(19 * n / total), f"Hashing {relative}…")
        lines.append(f"{sha256_file(path, stop)}  {relative}")
    with open(os.path.join(folder, MANIFEST), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + ("\n" if lines else ""))
    result.files = len(entries) + 1


def _readme(case, result: BundleResult) -> str:
    return f"""DumpScope case report — {case.case_name}
{'=' * (26 + len(case.case_name))}

Open index.html in any browser. It needs no network and no other software.

  index.html           the report: summary, insights, incident timeline,
                       findings, extracted files, analysis output, audit trail
  report.json          the same content, machine-readable
  analysis/            every stored plugin run, in full, as CSV
  timeline/            the incident timeline per data source, as CSV
  insights.csv         automatic triage leads ({result.insights})
  bookmarks.csv        findings tagged by the examiner
  extracted_files.csv  files carved out of the image, with the SHA-256
                       recorded at the moment of extraction
  audit_log.csv        every action taken in the case
  dumps/               the carved files ({result.dumps_linked + result.dumps_copied})
  SHA256SUMS           SHA-256 of every file in this folder

Verify the folder has not changed since it was generated:

  Linux/macOS:  sha256sum -c SHA256SUMS      (macOS: shasum -a 256 -c SHA256SUMS)
  Windows:      Get-FileHash -Algorithm SHA256 <file>   and compare

WARNING: files under dumps/ are process images and memory taken from the
examined machine. They may contain live malicious code. Handle them only in
an isolated analysis environment.
"""
