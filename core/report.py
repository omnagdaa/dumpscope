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


def _e(value) -> str:
    return html.escape("" if value is None else str(value))


def _format_size(count: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if count < 1024:
            return f"{count:.1f} {unit}"
        count /= 1024
    return f"{count:.1f} PB"


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
               include_audit: bool = True) -> str:
    """Render the case report. `case` is a core.case.Case."""
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
{audit_block}
<footer>
Generated by DumpScope. Full result sets are exported separately as CSV/JSON
alongside this report in the case's exports folder.
</footer>
</div></body></html>"""


def build_json(case, sources, results, bookmarks, audit) -> str:
    """The same content as machine-readable JSON, for downstream tooling."""
    return json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "case": case.to_dict(),
        "data_sources": sources,
        "results": results,
        "bookmarks": bookmarks,
        "audit_log": audit,
    }, indent=2, default=str)


def write_report(path: str, case, sources, results, bookmarks, audit,
                 fmt: str = "html", include_audit: bool = True) -> str:
    """Write the report and return the path it landed at."""
    content = (
        build_json(case, sources, results, bookmarks, audit)
        if fmt == "json"
        else build_html(case, sources, results, bookmarks, audit, include_audit)
    )
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path
