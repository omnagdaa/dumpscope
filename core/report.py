"""
Case reporting.

Produces a single self-contained HTML file: no external CSS, no fonts to fetch,
nothing that breaks when the report is copied, archived or filed. A forensic report has
to still render years later on a machine with no network, so everything is
inlined.

The report is a record of what was examined and what was found, not a dump of
every row: full result sets belong in the CSV/JSON exports beside it, which the
report links to by name.
"""

from __future__ import annotations

import html
import re
import json
import os
from datetime import datetime, UTC

# What each extraction actually contains, in words rather than in the plugin's
# vocabulary: "windows.memmap.Memmap" does not tell a reader what the file is.
_EXTRACT_KINDS = {
    "process": "Process executable",
    "memory": "Full process memory",
    "dlls": "Loaded modules",
}

REPORT_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body {
  margin: 0; padding: 40px;
  font: 14px/1.55 -apple-system, "Segoe UI", Roboto, Ubuntu, sans-serif;
  color: #1f2328; background: #ffffff;
}
.wrap { max-width: 1000px; margin: 0 auto; }
h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.2px; }
h3 {
  font-size: 13px; margin: 26px 0 8px; font-family: ui-monospace, Menlo, Consolas, monospace;
}
h3 .muted { font-family: inherit; font-weight: 400; }
h2 {
  font-size: 15px; text-transform: uppercase; letter-spacing: 1.2px;
  color: #57606a; margin: 38px 0 12px;
  border-bottom: 1px solid #d8dee4; padding-bottom: 6px;
}
.sub { color: #57606a; margin: 0 0 28px; }
table { border-collapse: collapse; width: 100%; margin: 0 0 10px; font-size: 13px; }
th, td {
  text-align: left; padding: 8px 10px; border-bottom: 1px solid #eaeef2;
  vertical-align: top;
}
th { color: #57606a; font-weight: 600; white-space: nowrap; }
td.mono, th.mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
/* A SHA-256 is 64 characters of unbreakable text: without this it pushes the
   table off the right edge of the page and out of the printed report. */
td.mono { word-break: break-all; }
.meta { display: grid; grid-template-columns: 180px 1fr; gap: 6px 16px; }
.meta dt { color: #57606a; }
.meta dd { margin: 0; }
.tag {
  display: inline-block; padding: 1px 8px; border-radius: 10px;
  font-size: 11px; font-weight: 700; color: #fff;
}
.muted { color: #6e7781; }
.note { white-space: pre-wrap; color: #24292f; }
footer {
  margin-top: 46px; padding-top: 14px; border-top: 1px solid #d8dee4;
  color: #6e7781; font-size: 12px;
}
.cards { display: flex; flex-wrap: wrap; gap: 12px; margin: 0 0 8px; }
.card {
  flex: 1 1 140px; border: 1px solid #d8dee4; border-radius: 8px;
  padding: 12px 14px; background: #f6f8fa;
}
.card .n { font-size: 24px; font-weight: 700; line-height: 1.1; }
.card .l { color: #57606a; font-size: 12px; text-transform: uppercase; letter-spacing: .8px; }
.sev {
  display: inline-block; padding: 1px 8px; border-radius: 10px;
  font-size: 11px; font-weight: 700; color: #fff; text-transform: uppercase;
}
.chart { width: 100%; height: auto; margin: 4px 0 6px; }
.toc { columns: 2; column-gap: 32px; padding-left: 18px; margin: 0 0 8px; }
.toc li { margin: 2px 0; }
.lead { font-size: 15px; line-height: 1.6; }
.exec li { margin: 4px 0; }
.rule {
  border: 1px solid #d8dee4; border-radius: 8px; padding: 12px 16px; margin: 0 0 14px;
}
.rule h3 { font-family: inherit; font-size: 14px; margin: 0 0 6px; }
.rule dl { display: grid; grid-template-columns: 170px 1fr; gap: 4px 14px; margin: 8px 0 0; }
.rule dt { color: #57606a; }
.rule dd { margin: 0; }
.alert { color: #cf222e; font-weight: 600; }
.ok { color: #1a7f37; }
.memmap { border-radius: 6px; }
.bar { display: inline-block; height: 8px; border-radius: 4px; background: #4f8fd9;
  vertical-align: middle; margin-right: 6px; }
a { color: #0969da; }
@media print {
  body { padding: 0; } h2 { break-after: avoid; } .rule { break-inside: avoid; }
}
"""


# Enough to show the shape of a result and the rows an examiner would cite,
# without producing a browser-defeating file from a plugin that emitted six
# figures of rows.
DEFAULT_MAX_ROWS = 200

# The report is built from the image's own strings. Everything is escaped, but
# should anything slip through, the page still cannot run script or load a
# single byte from anywhere: no network beacon, no UNC fetch. Links between the
# report's own files are navigation, which this does not restrict.
# Images may only be data: URIs, which is how the memory map embeds the
# programs' icons; nothing can be fetched.
_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
        "base-uri 'none'; form-action 'none'")


def _e(value) -> str:
    return html.escape("" if value is None else str(value))


_COLOR = re.compile(r"#[0-9A-Fa-f]{3,8}")


def _color(value, fallback: str = "#6e7781") -> str:
    """
    A tag colour safe to put in a style attribute.

    Escaping stops a value leaving the attribute, not CSS running inside it:
    a tag colour of ``url(//host/x)`` from a case someone else prepared would
    make the report fetch that address when opened. Only hex colours pass.
    """
    text = str(value or "").strip()
    return text if _COLOR.fullmatch(text) else fallback


def _format_size(count: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if count < 1024:
            return f"{count:.1f} {unit}"
        count /= 1024
    return f"{count:.1f} PB"


def _plural(count: int, noun: str) -> str:
    return f"{count:,} {noun}" + ("" if count == 1 else "s")


def _section(title: str, body: str, anchor: str = "") -> str:
    ident = f' id="{_e(anchor)}"' if anchor else ""
    return f"<h2{ident}>{_e(title)}</h2>\n{body}"


def tool_versions() -> dict[str, str]:
    """The versions that produced the report, for the methodology section."""
    from importlib.metadata import PackageNotFoundError, version
    out = {}
    for name, package in (("DumpScope", "dumpscope"), ("volatility3", "volatility3")):
        try:
            out[name] = version(package)
        except PackageNotFoundError:
            out[name] = "unknown"
    import platform
    out["Python"] = platform.python_version()
    return out


class _Raw(str):
    """Cell content that is already HTML and must not be escaped again."""


def _cell_html(value) -> str:
    return value if isinstance(value, _Raw) else _e(value)


def _href(path: str | None) -> str:
    """A relative bundle path as a URL path: forward slashes on every OS."""
    return (path or "").replace(os.sep, "/")


def _table(headers: list[str], rows: list[list[str]], mono_columns=()) -> str:
    if not rows:
        return '<p class="muted">Nothing recorded.</p>'
    head = "".join(
        f'<th class="mono">{_e(h)}</th>' if i in mono_columns else f"<th>{_e(h)}</th>"
        for i, h in enumerate(headers)
    )
    body = []
    for row in rows:
        cells = "".join(
            f'<td class="mono">{_cell_html(c)}</td>' if i in mono_columns
            else f"<td>{_cell_html(c)}</td>"
            for i, c in enumerate(row)
        )
        body.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def build_html(case, sources: list[dict], results: list[dict],
               bookmarks: list[dict], audit: list[dict],
               include_audit: bool = True, extractions: list[dict] | None = None,
               outputs: dict | None = None,
               max_rows: int = DEFAULT_MAX_ROWS,
               insights: list | None = None,
               timelines: list[tuple[str, list]] | None = None,
               links: dict | None = None,
               memory: list[tuple[str, list]] | None = None,
               moments: dict | None = None,
               versions: dict | None = None) -> str:
    """
    Render the case report. `case` is a core.case.Case.

    `memory` is (data source label, [core.memory_map.Program]) per source;
    `moments` maps a data source label to its core.timeline key moments;
    `versions` names the tools that produced the output (tool_versions()).

    `extractions` are the files plugins carved out of the image; `outputs`
    maps a result id to its full {columns, rows} payload, for the sections that
    reproduce the analysis output inline. Tables are capped at `max_rows` with
    the remainder pointed at the CSV export, because a report nobody can open
    is not a record of anything.

    `insights` are core.insights.Finding objects; `timelines` is a list of
    (data source label, [core.timeline.Event]) pairs. `links` maps parts of
    the report to files beside it in a report bundle: {"results": {result id:
    relative path}, "extractions": {absolute path: relative path},
    "timeline": {label: relative path}, "insights": relative path}.
    """
    extractions = extractions or []
    links = links or {}
    insights = insights or []
    timelines = [(label, events) for label, events in (timelines or []) if events]
    memory = [(label, programs) for label, programs in (memory or []) if programs]
    moments = moments or {}
    generated = datetime.now(UTC).astimezone().strftime("%Y-%m-%d %H:%M %Z")

    meta_rows = [
        ("Case Name", case.case_name),
        ("Case Number", case.case_number or "-"),
        ("Opened", case.date_time or case.created_at or "-"),
        ("Examiner", case.examiner_name or "-"),
        ("Examiner ID", case.examiner_id or "-"),
        ("Contact", " · ".join(p for p in (case.examiner_email, case.examiner_phone) if p) or "-"),
        ("Case Folder", case.directory),
    ]
    meta = "<dl class='meta'>" + "".join(
        f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in meta_rows
    ) + "</dl>"

    notes_block = (
        f"<h2 id='notes'>Case Notes</h2><p class='note'>{_e(case.notes)}</p>"
        if case.notes else ""
    )

    source_rows = [
        [
            source.get("display_name") or os.path.basename(source["path"]),
            source["path"],
            _format_size(source.get("size_bytes") or 0),
            source.get("os_hint") or "-",
            source.get("md5") or "not computed",
            source.get("sha256") or "not computed",
        ]
        for source in sources
    ]
    sources_table = _table(
        ["Name", "Path", "Size", "OS", "MD5", "SHA-256"],
        source_rows, mono_columns={1, 4, 5},
    )

    result_rows = [
        [
            result["plugin"],
            result.get("source_name") or "-",
            f"{result.get('row_count') or 0:,}",
            result.get("created_at") or "-",
        ]
        for result in results
    ]
    results_table = _table(
        ["Plugin", "Data Source", "Rows", "Run At"], result_rows, mono_columns={0}
    )

    bookmark_rows = []
    for bookmark in bookmarks:
        tag = bookmark.get("tag") or ""
        color = _color(bookmark.get("tag_color"))
        tag_html = (
            f'<span class="tag" style="background:{_e(color)}">{_e(tag)}</span>'
            if tag else '<span class="muted">-</span>'
        )
        bookmark_rows.append([
            bookmark.get("label") or "(unlabelled)",
            tag_html,
            bookmark.get("artifact_type") or "-",
            bookmark.get("source_name") or "-",
            bookmark.get("notes") or "",
            bookmark.get("description") or "",
            bookmark.get("created_at") or "",
        ])

    if bookmark_rows:
        head = ("<tr><th>Finding</th><th>Tag</th><th>Plugin</th><th>Source</th>"
                "<th>Notes</th><th>Detail</th><th>Added</th></tr>")
        body = "".join(
            "<tr>"
            f"<td>{_e(r[0])}</td><td>{r[1]}</td><td class='mono'>{_e(r[2])}</td>"
            f"<td>{_e(r[3])}</td><td class='note'>{_e(r[4])}</td>"
            f"<td class='note mono'>{_e(r[5])}</td><td>{_e(r[6])}</td>"
            "</tr>"
            for r in bookmark_rows
        )
        bookmarks_table = f"<table><thead>{head}</thead><tbody>{body}</tbody></table>"
    else:
        bookmarks_table = '<p class="muted">No findings were bookmarked.</p>'

    extraction_rows = []
    for item in extractions:
        label = item.get("filename") or os.path.basename(item.get("path", ""))
        if item.get("missing"):
            label += "  (no longer on disk)"
        target = links.get("extractions", {}).get(item.get("path", ""))
        label_html = (f'<a href="{_e(_href(target))}">{_e(label)}</a>'
                      if target else _e(label))
        extraction_rows.append([
            _Raw(label_html),
            _EXTRACT_KINDS.get(item.get("kind") or "", item.get("kind") or "-"),
            item.get("pid") or "-",
            item.get("process") or "-",
            _format_size(item.get("size_bytes") or 0),
            item.get("sha256") or "not computed",
            item.get("created_at") or "-",
        ])
    extraction_table = _table(
        ["File", "Contents", "PID", "Process", "Size", "SHA-256", "Extracted"],
        extraction_rows, mono_columns={0, 5},
    )
    extraction_note = (
        '<p class="muted">Files are stored in the case\'s <code>dumps</code> '
        "folder. Extracted process images and memory may contain live malicious "
        "code. Handle them in an isolated environment.</p>"
        if extraction_rows else ""
    )

    tag_counts: dict[str, int] = {}
    for bookmark in bookmarks:
        tag = bookmark.get("tag") or "(untagged)"
        tag_counts[tag] = tag_counts.get(tag, 0) + 1
    tag_summary = (
        _section("Findings by Tag", _table(["Tag", "Findings"],
               [[name, str(count)] for name, count in
                sorted(tag_counts.items(), key=lambda kv: (-kv[1], kv[0]))]))
        if tag_counts else ""
    )

    output_block = ""
    if outputs:
        blocks = []
        for result in results:
            payload = outputs.get(result.get("id"))
            if not payload:
                continue
            blocks.append(_result_block(result, payload, max_rows,
                                        links.get("results", {}).get(result.get("id"))))
        if blocks:
            output_block = _section("Analysis Output", "".join(blocks), "output")

    audit_block = ""
    if include_audit:
        audit_rows = [
            [entry.get("created_at") or "", entry.get("action") or "",
             entry.get("detail") or "", entry.get("examiner") or ""]
            for entry in audit
        ]
        audit_block = _section(
            "Audit Trail",
            _table(["Timestamp", "Action", "Detail", "Examiner"],
                   audit_rows, mono_columns={0, 2}),
            "audit",
        )

    sections = [
        ("summary", "Executive Summary", True),
        ("case", "Case Details", True),
        ("notes", "Case Notes", bool(case.notes)),
        ("insights", "Insights", bool(insights)),
        ("timeline", "Incident Timeline", bool(timelines)),
        ("memory", "Memory Usage", bool(memory)),
        ("sources", "Data Sources", True),
        ("analysis", "Analysis Performed", True),
        ("findings", "Bookmarked Findings", True),
        ("extracted", "Extracted Files", True),
        ("output", "Analysis Output", bool(output_block)),
        ("method", "Methodology", True),
        ("audit", "Audit Trail", bool(audit_block)),
    ]
    toc = ("<ol class='toc'>" + "".join(
        f"<li><a href='#{anchor}'>{_e(title)}</a></li>"
        for anchor, title, shown in sections if shown) + "</ol>")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{_CSP}">
<title>{_e(case.case_name)} - DumpScope Case Report</title>
<style>{REPORT_CSS}</style>
</head><body><div class="wrap">
<h1>{_e(case.case_name)}</h1>
<p class="sub">DumpScope case report · generated {_e(generated)}</p>
{toc}
{_summary_block(case, sources, results, bookmarks, extractions, insights, timelines, memory)}
{_section("Case Details", meta, "case")}
{notes_block}
{_insights_block(insights, links.get("insights"))}
{_timeline_block(timelines, links.get("timeline", {}), max_rows, moments)}
{_memory_block(memory, insights)}
{_section(f"Data Sources ({len(sources)})", sources_table, "sources")}
{_section(f"Analysis Performed ({len(results)})", results_table, "analysis")}
{_section(f"Bookmarked Findings ({len(bookmarks)})", bookmarks_table, "findings")}
{tag_summary}
{_section(f"Extracted Files ({len(extraction_rows)})", extraction_table, "extracted")}
{extraction_note}
{output_block}
{_methodology_block(results, insights, versions)}
{audit_block}
<footer>
Generated by DumpScope. {_e(links.get("footer") or "Full result sets are exported separately as CSV/JSON alongside this report.")}
</footer>
</div></body></html>"""


def _result_block(result: dict, payload: dict, max_rows: int,
                  csv_path: str | None = None) -> str:
    """One plugin's output, capped, under a heading naming the run."""
    columns = payload.get("columns") or []
    rows = payload.get("rows") or []
    shown = rows[:max_rows]
    # DumpScope's memory plugin carries each program's icon as base64: it is
    # drawn in the Memory Usage section, not printed as kilobytes of text.
    if "Icon" in columns and str(result.get("plugin") or "").startswith("dumpscope."):
        keep = [i for i, c in enumerate(columns) if c != "Icon"]
        columns = [columns[i] for i in keep]
        shown = [[row[i] for i in keep if i < len(row)] for row in shown]
    link = f" · <a href='{_e(_href(csv_path))}'>full CSV</a>" if csv_path else ""
    heading = (
        f"<h3>{_e(result.get('plugin'))} "
        f"<span class='muted'>· {_plural(len(rows), 'row')} · "
        f"{_e(result.get('created_at') or '')}{link}</span></h3>"
    )
    more = (
        f'<p class="muted">Showing the first {len(shown):,} of {len(rows):,} '
        "rows; the full set is in the CSV export.</p>"
        if len(rows) > len(shown) else ""
    )
    return heading + _table(columns, [[str(c) for c in row] for row in shown]) + more


def build_json(case, sources, results, bookmarks, audit,
               extractions: list[dict] | None = None,
               outputs: dict | None = None,
               insights: list | None = None,
               timelines: list[tuple[str, list]] | None = None,
               files: dict | None = None) -> str:
    """The same content as machine-readable JSON, for downstream tooling."""
    from dataclasses import asdict
    from core.timeline import format_time, summarise
    payload = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "case": case.to_dict(),
        "data_sources": sources,
        "results": results,
        "extracted_files": extractions or [],
        "bookmarks": bookmarks,
        "audit_log": audit,
    }
    if insights:
        payload["insights"] = [asdict(f) for f in insights]
    if timelines:
        payload["timeline"] = {
            label: {
                "summary": summarise(events),
                "events": [
                    {"time": format_time(e.time), "type": e.kind, "pid": e.pid,
                     "process": e.process, "description": e.summary,
                     "detail": e.detail, "plugin": e.plugin}
                    for e in events
                ],
            }
            for label, events in timelines
        }
    if files:
        payload["files"] = files
    if outputs:
        # Keyed by plugin rather than by row id: a JSON report is read by
        # something downstream, which knows plugins, not this case's ids.
        payload["output"] = {
            result["plugin"]: outputs[result["id"]]
            for result in results if result.get("id") in outputs
        }
    return json.dumps(payload, indent=2, default=str)


# ── Summary, insights and timeline ────────────────────────────────────────────

def _summary_block(case, sources, results, bookmarks, extractions, insights,
                   timelines, memory) -> str:
    from core.insights import counts
    tally = counts(insights)
    events = sum(len(events) for _, events in timelines)
    cards = [
        (len(sources), "Data sources"),
        (len(results), "Plugin runs"),
        (tally.get("high", 0), "High-severity insights"),
        (tally.get("medium", 0), "Medium insights"),
        (events, "Timeline events"),
        (len(bookmarks), "Bookmarked findings"),
        (len(extractions), "Extracted files"),
    ]
    body = "<div class='cards'>" + "".join(
        f"<div class='card'><div class='n'>{n:,}</div><div class='l'>{_e(label)}</div></div>"
        for n, label in cards
    ) + "</div>"
    return _section("Executive Summary",
                    executive_summary(case, sources, results, bookmarks, extractions,
                                      insights, timelines, memory) + body, "summary")


def executive_summary(case, sources, results, bookmarks, extractions, insights,
                      timelines, memory=()) -> str:
    """
    The opening paragraphs, written from the case's own numbers.

    Plain statements of what was examined and what came out of it, so a reader
    who stops after the first screen still knows the result.
    """
    from core.insights import counts
    from core.memory_map import DEFAULT_METRIC, METRIC_LABELS, format_bytes, ranked
    points = []
    names = ", ".join(s.get("display_name") or os.path.basename(s.get("path") or "")
                      for s in sources) or "no data source"
    plugins = len({r.get("plugin") for r in results})
    points.append(
        f"{_e(_plural(len(sources), 'memory image'))} examined ({_e(names)}) with "
        f"{_e(_plural(plugins, 'Volatility 3 plugin'))} "
        f"({_e(_plural(len(results), 'run'))}).")
    tally = counts(insights)
    if insights:
        serious = [f for f in insights if f.severity in ("high", "medium")]
        text = (f"Automatic triage raised {_e(_plural(len(insights), 'lead'))}: "
                f"{tally.get('high', 0)} high, {tally.get('medium', 0)} medium, "
                f"{tally.get('low', 0) + tally.get('info', 0)} low or informational.")
        if serious:
            top = "; ".join(
                _e(f.title + (f" ({f.process}, PID {f.pid})" if f.pid else ""))
                for f in serious[:3])
            text += f" <span class='alert'>Most significant: {top}.</span>"
        points.append(text)
    elif results:
        points.append("<span class='ok'>Automatic triage found nothing unusual</span> in "
                      "the output examined. That covers only the plugins that were run; "
                      "see Methodology.")
    for label, events in timelines:
        points.append(f"{_e(label)}: recorded activity from "
                      f"{_e(_fmt_time(events[0].time))} to {_e(_fmt_time(events[-1].time))} "
                      f"({len(events):,} timeline events).")
    for label, programs in memory:
        shown = ranked(programs, DEFAULT_METRIC)
        if not shown:
            continue
        total = sum(p.total(DEFAULT_METRIC) for p in shown)
        top = ", ".join(f"{_e(p.title)} ({format_bytes(p.total(DEFAULT_METRIC))})"
                        for p in shown[:3])
        points.append(f"{_e(label)}: {format_bytes(total)} of "
                      f"{_e(METRIC_LABELS[DEFAULT_METRIC].lower())} in use by "
                      f"{_plural(len(shown), 'program')}; the largest were {top}.")
    if bookmarks:
        tags = {}
        for b in bookmarks:
            tags[b.get("tag") or "untagged"] = tags.get(b.get("tag") or "untagged", 0) + 1
        tag_text = ", ".join(f"{n} {_e(t)}" for t, n in sorted(tags.items(), key=lambda kv: -kv[1]))
        points.append(f"The examiner bookmarked {_e(_plural(len(bookmarks), 'finding'))} "
                      f"({tag_text}).")
    else:
        points.append("No findings were bookmarked by the examiner.")
    if extractions:
        points.append(f"{_e(_plural(len(extractions), 'file'))} were extracted from the "
                      "image, each with a SHA-256 taken at extraction.")
    examiner = f" by {_e(case.examiner_name)}" if getattr(case, "examiner_name", "") else ""
    lead = (f"<p class='lead'>This report records the memory analysis carried out"
            f"{examiner} for case <b>{_e(case.case_name)}</b>"
            + (f" ({_e(case.case_number)})" if getattr(case, "case_number", "") else "")
            + ".</p>")
    return lead + "<ul class='exec'>" + "".join(f"<li>{p}</li>" for p in points) + "</ul>"


def _insights_block(insights, csv_path) -> str:
    if not insights:
        return ""
    from core.insights import SEVERITIES, SEVERITY_COLORS, rule_for
    rank = {name: i for i, name in enumerate(SEVERITIES)}
    rows = []
    for finding in insights:
        color = SEVERITY_COLORS.get(finding.severity, "#6e7781")
        rows.append([
            _Raw(f'<span class="sev" style="background:{color}">{_e(finding.severity)}</span>'),
            finding.category, finding.title, finding.pid or "-",
            finding.process or "-", finding.detail,
        ])
    link = (f"<p class='muted'>Also in <a href='{_e(_href(csv_path))}'>"
            f"{_e(os.path.basename(csv_path))}</a>.</p>" if csv_path else "")
    note = ("<p class='muted'>Leads from fixed triage rules applied to the stored "
            "plugin output (not machine learning, not a verdict). Each rule below says "
            "what it checks, why it matters, how to confirm the lead and what most "
            "often explains it innocently. The full list follows.</p>")

    # One card per rule that fired, most severe first.
    by_rule: dict[str, list] = {}
    rules = {}
    for finding in insights:
        rule = rule_for(finding)
        key = rule.id if rule else finding.category
        rules[key] = rule
        by_rule.setdefault(key, []).append(finding)
    order = sorted(by_rule, key=lambda k: min(rank.get(f.severity, 9) for f in by_rule[k]))
    cards = []
    for key in order:
        rule, items = rules[key], by_rule[key]
        name = rule.name if rule else key
        where = ", ".join(
            _e(f"{f.process} ({f.pid})" if f.pid else f.title) for f in items[:8])
        if len(items) > 8:
            where += f" and {len(items) - 8} more"
        body = f"<p><b>{_e(_plural(len(items), 'lead'))}</b>: {where}</p>"
        if rule:
            attack = ", ".join(f"{_e(i)} {_e(n)}" for i, n in rule.attack)
            body += ("<dl>"
                     f"<dt>What it checks</dt><dd>{_e(rule.checks)}</dd>"
                     f"<dt>Why it matters</dt><dd>{_e(rule.why)}</dd>"
                     f"<dt>How to confirm</dt><dd>{_e(rule.verify)}</dd>"
                     f"<dt>Innocent causes</dt><dd>{_e(rule.noise)}</dd>"
                     + (f"<dt>MITRE ATT&amp;CK</dt><dd>{attack}</dd>" if attack else "")
                     + "</dl>")
        cards.append(f"<div class='rule'><h3>{_e(name)}</h3>{body}</div>")
    return _section(f"Insights ({len(insights)})", note + "".join(cards)
                    + "<h3>All leads</h3>" + _table(
                        ["Severity", "Category", "Finding", "PID", "Process", "Detail"],
                        rows, mono_columns={5}) + link, "insights")


def _timeline_block(timelines, csv_links: dict, max_rows: int,
                    moments: dict | None = None) -> str:
    if not timelines:
        return ""
    from core.timeline import EVENT_COLUMNS
    moments = moments or {}
    parts = ["<p class='muted'>Every timestamp found in the plugin output (process "
             "start and exit, DLL loads, network connections, user sessions, program "
             "execution records), merged and sorted. Times are UTC as recorded by "
             "the machine. Key moments are the events worth reading first; red ones "
             "involve a process Insights flagged.</p>"]
    for label, events in timelines:
        csv_path = csv_links.get(label)
        shown = events[:max_rows]
        more = ""
        if len(events) > len(shown):
            more = (f"<p class='muted'>Showing the first {len(shown):,} of "
                    f"{len(events):,} events"
                    + (f"; all of them are in <a href='{_e(_href(csv_path))}'>"
                       f"{_e(os.path.basename(csv_path))}</a>" if csv_path else "")
                    + ".</p>")
        elif csv_path:
            more = (f"<p class='muted'>Also in <a href='{_e(_href(csv_path))}'>"
                    f"{_e(os.path.basename(csv_path))}</a>.</p>")
        key = moments.get(label) or []
        key_table = ""
        if key:
            key_rows = [[_fmt_time(m.time),
                         _Raw(f"<span class='alert'>{_e(m.title)}</span>"
                              if m.tone == "alert" else _e(m.title)),
                         m.detail] for m in key]
            key_table = ("<p><b>Key moments</b></p>"
                         + _table(["Time (UTC)", "Moment", "Detail"], key_rows,
                                  mono_columns={0}))
        parts.append(
            f"<h3>{_e(label)} <span class='muted'>· {_plural(len(events), 'event')}</span></h3>"
            + key_table
            + timeline_svg(events)
            + _table(EVENT_COLUMNS, [e.as_row() for e in shown], mono_columns={0})
            + more)
    return _section("Incident Timeline", "".join(parts), "timeline")


def _memory_block(memory, insights) -> str:
    """The memory map per data source, with the largest programs listed."""
    if not memory:
        return ""
    from core.memory_map import (DEFAULT_METRIC, METRICS, METRIC_LABELS, colour_for,
                                 format_bytes, ranked, treemap_svg)
    flagged = {f.pid for f in insights or () if f.pid}
    explanation = dict((k, e) for k, _, e in METRICS)[DEFAULT_METRIC]
    parts = [f"<p class='muted'>Each box is one process, its area proportional to its "
             f"{_e(METRIC_LABELS[DEFAULT_METRIC].lower())} ({_e(explanation)}). Boxes are "
             "grouped by program, with the program's icon recovered from the image where "
             "its pages were in memory. Hover a box in a browser for details; a red corner "
             "marks a process Insights flagged. Read from each process's EPROCESS "
             "counters by DumpScope's bundled plugin.</p>"]
    for label, programs in memory:
        shown = ranked(programs, DEFAULT_METRIC)
        if not shown:
            continue
        total = sum(p.total(DEFAULT_METRIC) for p in shown) or 1
        peak = shown[0].total(DEFAULT_METRIC) or 1
        rows = []
        for rank, program in enumerate(shown[:15]):
            amount = program.total(DEFAULT_METRIC)
            width = max(2, int(120 * amount / peak))
            rows.append([
                program.title, program.path or program.name,
                _Raw(f"<span class='bar' style='width:{width}px;background:"
                     f"{colour_for(rank)}'></span>{_e(format_bytes(amount))}"),
                f"{amount / total * 100:.1f}%", str(len(program.processes)),
            ])
        parts.append(
            f"<h3>{_e(label)} <span class='muted'>· {format_bytes(total)} across "
            f"{_plural(len(shown), 'program')}</span></h3>"
            + treemap_svg(programs, DEFAULT_METRIC, flagged_pids=flagged)
            + _table(["Program", "Path", METRIC_LABELS[DEFAULT_METRIC], "Share", "Processes"],
                     rows, mono_columns={1}))
    return _section("Memory Usage", "".join(parts), "memory")


def _methodology_block(results, insights, versions) -> str:
    """How the output was produced, and what the report cannot say."""
    from core.insights import rule_status
    versions = versions or {}
    have = {r.get("plugin") or "" for r in results}
    tools = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in versions.items())
    rule_rows = []
    for rule, ran, produced, missing in rule_status(have, insights or []):
        if ran:
            state = _Raw(f"<span class='alert'>{produced} lead(s)</span>" if produced
                         else "<span class='ok'>Ran, nothing flagged</span>")
        else:
            state = _Raw("<span class='muted'>Not run; needs "
                         + _e(", ".join(m.rsplit(".", 1)[-1] for m in missing)) + "</span>")
        rule_rows.append([rule.name, rule.checks, state])
    body = (
        "<p>Every result in this report comes from the Volatility 3 framework run "
        "against the memory image(s) listed under Data Sources, read-only. DumpScope "
        "runs each plugin as a separate process and stores its full output in the case "
        "database; the CSV files beside this report are those outputs, unmodified. The "
        "image is never written to; its hashes are recorded when it is added.</p>"
        + (f"<dl class='meta'>{tools}</dl>" if tools else "")
        + "<h3>Triage rules applied</h3>"
        + _table(["Rule", "What it checks", "Result"], rule_rows)
        + "<h3>Limitations</h3><ul>"
        "<li>Memory is a snapshot: anything that ended before the capture and whose "
        "structures were reused is not visible.</li>"
        "<li>The triage rules compare the output with how a normal Windows system "
        "looks. A lead is a place to look, not a conclusion, and no lead does not "
        "mean the system was clean; only the plugins listed were run.</li>"
        "<li>Timestamps are the machine's own clock. If it was wrong, they are "
        "wrong by the same amount.</li>"
        "<li>Memory figures are the counters Windows kept per process; shared pages "
        "are counted in every process that maps them.</li>"
        "<li>Malware with kernel access can alter the structures Volatility reads. "
        "Where two plugins disagree, both are reported.</li></ul>")
    return _section("Methodology", body, "method")


def _fmt_time(moment) -> str:
    from core.timeline import format_time
    return format_time(moment)


def timeline_svg(events: list, width: int = 960, height: int = 230,
                 buckets: int = 60) -> str:
    """
    A stacked histogram of events over time, as inline SVG.

    Inline rather than an image or a script so the report still renders with
    no network and no JavaScript, and prints.
    """
    from core.timeline import KINDS, KIND_COLORS, KIND_LABELS, histogram, format_time
    if not events:
        return ""
    start, end = events[0].time, events[-1].time
    bins = histogram(events, start, end, buckets)
    peak = max((sum(b.values()) for b in bins), default=0) or 1
    left, right, top, bottom = 44, 10, 10, 58
    plot_w, plot_h = width - left - right, height - top - bottom
    bar_w = plot_w / len(bins)
    order = [key for key, _, _ in KINDS]
    shapes = []
    for i, counter in enumerate(bins):
        y = top + plot_h
        for kind in order:
            n = counter.get(kind, 0)
            if not n:
                continue
            h = n / peak * plot_h
            y -= h
            shapes.append(
                f'<rect x="{left + i * bar_w + 0.5:.1f}" y="{y:.1f}" '
                f'width="{max(bar_w - 1, 1):.1f}" height="{h:.1f}" '
                f'fill="{KIND_COLORS[kind]}"><title>{_e(KIND_LABELS[kind])}: {n}</title></rect>')
    axis = (
        f'<line x1="{left}" y1="{top + plot_h}" x2="{width - right}" y2="{top + plot_h}" '
        'stroke="#8c959f"/>'
        f'<text x="{left - 6}" y="{top + 10}" text-anchor="end" font-size="11" fill="#57606a">{peak}</text>'
        f'<text x="{left - 6}" y="{top + plot_h}" text-anchor="end" font-size="11" fill="#57606a">0</text>'
        f'<text x="{left}" y="{top + plot_h + 16}" font-size="11" fill="#57606a">{_e(format_time(start))}</text>'
        f'<text x="{width - right}" y="{top + plot_h + 16}" text-anchor="end" font-size="11" '
        f'fill="#57606a">{_e(format_time(end))}</text>'
    )
    present = [key for key in order if any(b.get(key) for b in bins)]
    legend = []
    x = left
    for key in present:
        legend.append(
            f'<rect x="{x}" y="{height - 22}" width="10" height="10" fill="{KIND_COLORS[key]}"/>'
            f'<text x="{x + 14}" y="{height - 13}" font-size="11" fill="#57606a">{_e(KIND_LABELS[key])}</text>')
        x += 24 + 7 * len(KIND_LABELS[key])
    return (f'<svg class="chart" viewBox="0 0 {width} {height}" '
            f'xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Event timeline">'
            + "".join(shapes) + axis + "".join(legend) + "</svg>")
