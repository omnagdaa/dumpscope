"""
Case reporting.

Produces a single self-contained HTML file: no external CSS, no fonts to fetch,
nothing that breaks when the report is emailed or filed. A forensic report has
to still render years later on a machine with no network, so everything is
inlined.

The report is a record of what was examined and what was found, not a dump of
every row: full result sets belong in the CSV/JSON exports beside it, which the
report links to by name.
"""

from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone

# What each extraction actually contains, in words rather than in the plugin's
# vocabulary — "windows.memmap.Memmap" does not tell a reader what the file is.
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
@media print { body { padding: 0; } h2 { break-after: avoid; } }
"""


# Enough to show the shape of a result and the rows an examiner would cite,
# without producing a browser-defeating file from a plugin that emitted six
# figures of rows.
DEFAULT_MAX_ROWS = 200


def _e(value) -> str:
    return html.escape("" if value is None else str(value))


def _format_size(count: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if count < 1024:
            return f"{count:.1f} {unit}"
        count /= 1024
    return f"{count:.1f} PB"


def _plural(count: int, noun: str) -> str:
    return f"{count:,} {noun}" + ("" if count == 1 else "s")


def _section(title: str, body: str) -> str:
    return f"<h2>{_e(title)}</h2>\n{body}"


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
            f'<td class="mono">{_e(c)}</td>' if i in mono_columns else f"<td>{_e(c)}</td>"
            for i, c in enumerate(row)
        )
        body.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def build_html(case, sources: list[dict], results: list[dict],
               bookmarks: list[dict], audit: list[dict],
               include_audit: bool = True, extractions: list[dict] | None = None,
               outputs: dict | None = None,
               max_rows: int = DEFAULT_MAX_ROWS) -> str:
    """
    Render the case report. `case` is a core.case.Case.

    `extractions` are the files plugins carved out of the image; `outputs`
    maps a result id to its full {columns, rows} payload, for the sections that
    reproduce the analysis output inline. Tables are capped at `max_rows` with
    the remainder pointed at the CSV export, because a report nobody can open
    is not a record of anything.
    """
    extractions = extractions or []
    generated = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")

    meta_rows = [
        ("Case Name", case.case_name),
        ("Case Number", case.case_number or "—"),
        ("Opened", case.date_time or case.created_at or "—"),
        ("Examiner", case.examiner_name or "—"),
        ("Examiner ID", case.examiner_id or "—"),
        ("Contact", " · ".join(p for p in (case.examiner_email, case.examiner_phone) if p) or "—"),
        ("Case Folder", case.directory),
    ]
    meta = "<dl class='meta'>" + "".join(
        f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in meta_rows
    ) + "</dl>"

    notes_block = (
        f"<h2>Case Notes</h2><p class='note'>{_e(case.notes)}</p>"
        if case.notes else ""
    )

    source_rows = [
        [
            source.get("display_name") or os.path.basename(source["path"]),
            source["path"],
            _format_size(source.get("size_bytes") or 0),
            source.get("os_hint") or "—",
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
            result.get("source_name") or "—",
            f"{result.get('row_count') or 0:,}",
            result.get("created_at") or "—",
        ]
        for result in results
    ]
    results_table = _table(
        ["Plugin", "Data Source", "Rows", "Run At"], result_rows, mono_columns={0}
    )

    bookmark_rows = []
    for bookmark in bookmarks:
        tag = bookmark.get("tag") or ""
        color = bookmark.get("tag_color") or "#6e7781"
        tag_html = (
            f'<span class="tag" style="background:{_e(color)}">{_e(tag)}</span>'
            if tag else '<span class="muted">—</span>'
        )
        bookmark_rows.append([
            bookmark.get("label") or "(unlabelled)",
            tag_html,
            bookmark.get("artifact_type") or "—",
            bookmark.get("source_name") or "—",
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
        extraction_rows.append([
            label,
            _EXTRACT_KINDS.get(item.get("kind") or "", item.get("kind") or "—"),
            item.get("pid") or "—",
            item.get("process") or "—",
            _format_size(item.get("size_bytes") or 0),
            item.get("sha256") or "not computed",
            item.get("created_at") or "—",
        ])
    extraction_table = _table(
        ["File", "Contents", "PID", "Process", "Size", "SHA-256", "Extracted"],
        extraction_rows, mono_columns={0, 5},
    )
    extraction_note = (
        '<p class="muted">Files are stored in the case\'s <code>dumps</code> '
        "folder. Extracted process images and memory may contain live malicious "
        "code — handle them in an isolated environment.</p>"
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
            blocks.append(_result_block(result, payload, max_rows))
        if blocks:
            output_block = _section("Analysis Output", "".join(blocks))

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
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{_e(case.case_name)} — DumpScope Case Report</title>
<style>{REPORT_CSS}</style>
</head><body><div class="wrap">
<h1>{_e(case.case_name)}</h1>
<p class="sub">DumpScope case report · generated {_e(generated)}</p>
{_section("Case Details", meta)}
{notes_block}
{_section(f"Data Sources ({len(sources)})", sources_table)}
{_section(f"Analysis Performed ({len(results)})", results_table)}
{_section(f"Findings ({len(bookmarks)})", bookmarks_table)}
{tag_summary}
{_section(f"Extracted Files ({len(extraction_rows)})", extraction_table)}
{extraction_note}
{output_block}
{audit_block}
<footer>
Generated by DumpScope. Full result sets are exported separately as CSV/JSON
alongside this report in the case's exports folder.
</footer>
</div></body></html>"""


def _result_block(result: dict, payload: dict, max_rows: int) -> str:
    """One plugin's output, capped, under a heading naming the run."""
    columns = payload.get("columns") or []
    rows = payload.get("rows") or []
    shown = rows[:max_rows]
    heading = (
        f"<h3>{_e(result.get('plugin'))} "
        f"<span class='muted'>· {_plural(len(rows), 'row')} · "
        f"{_e(result.get('created_at') or '')}</span></h3>"
    )
    more = (
        f'<p class="muted">Showing the first {len(shown):,} of {len(rows):,} '
        "rows; the full set is in the CSV export.</p>"
        if len(rows) > len(shown) else ""
    )
    return heading + _table(columns, [[str(c) for c in row] for row in shown]) + more


def build_json(case, sources, results, bookmarks, audit,
               extractions: list[dict] | None = None,
               outputs: dict | None = None) -> str:
    """The same content as machine-readable JSON, for downstream tooling."""
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "case": case.to_dict(),
        "data_sources": sources,
        "results": results,
        "extracted_files": extractions or [],
        "bookmarks": bookmarks,
        "audit_log": audit,
    }
    if outputs:
        # Keyed by plugin rather than by row id: a JSON report is read by
        # something downstream, which knows plugins, not this case's ids.
        payload["output"] = {
            result["plugin"]: outputs[result["id"]]
            for result in results if result.get("id") in outputs
        }
    return json.dumps(payload, indent=2, default=str)


def write_report(path: str, case, sources, results, bookmarks, audit,
                 fmt: str = "html", include_audit: bool = True,
                 extractions: list[dict] | None = None,
                 outputs: dict | None = None,
                 max_rows: int = DEFAULT_MAX_ROWS) -> str:
    """Write the report and return the path it landed at."""
    content = (
        build_json(case, sources, results, bookmarks, audit,
                   extractions=extractions, outputs=outputs)
        if fmt == "json"
        else build_html(case, sources, results, bookmarks, audit, include_audit,
                        extractions=extractions, outputs=outputs,
                        max_rows=max_rows)
    )
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path
