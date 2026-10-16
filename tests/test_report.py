"""Case report generation."""
import json

import pytest

from core.case import Case
from core.database import Database
from core.report import build_html, build_json


@pytest.fixture
def populated(tmp_path):
    image = tmp_path / "host-a.raw"
    image.write_bytes(b"\0" * 2048)
    case = Case.create(str(tmp_path), "Op Nightfall", case_number="2026-014",
                       examiner_name="A. Nagda", notes="Suspected injection.",
                       image_path=str(image))
    db = Database(case.directory, case.case_name)
    db.attach_case(case.to_dict())
    source_id = db.get_data_sources()[0]["id"]
    db.save_analysis("windows.pstree.PsTree",
                     {"columns": ["PID", "Name"], "rows": [["4", "System"]]},
                     source_id=source_id)
    db.save_bookmark("svchost.exe", "PID: 820", "windows.pstree.PsTree",
                     tag="Suspicious", notes="Unexpected parent.",
                     source_id=source_id)
    return case, db


def _html(populated):
    case, db = populated
    return build_html(case, db.get_data_sources(), db.get_results(),
                      db.get_bookmarks(), db.get_audit_log())


def test_report_covers_case_sources_results_and_findings(populated):
    report = _html(populated)
    for needle in ("Op Nightfall", "2026-014", "A. Nagda", "Suspected injection.",
                   "host-a.raw", "windows.pstree.PsTree", "svchost.exe",
                   "Suspicious", "Unexpected parent."):
        assert needle in report


def test_report_includes_the_audit_trail(populated):
    report = _html(populated)
    assert "case_created" in report and "plugin_run" in report


def test_audit_trail_can_be_omitted(populated):
    case, db = populated
    report = build_html(case, db.get_data_sources(), db.get_results(),
                        db.get_bookmarks(), db.get_audit_log(), include_audit=False)
    assert "Audit Trail" not in report


def test_report_is_self_contained(populated):
    """
    A forensic report has to render years later on a machine with no network,
    so it must not reference anything external.
    """
    report = _html(populated)
    assert "http://" not in report
    assert "https://" not in report
    assert "<link" not in report
    assert "<script" not in report


def test_report_escapes_hostile_content(tmp_path):
    """Values come from memory images; they are never trusted as markup."""
    case = Case.create(str(tmp_path), "XSS Probe")
    db = Database(case.directory, case.case_name)
    db.attach_case(case.to_dict())
    db.save_bookmark("<script>alert(1)</script>", "<img src=x onerror=alert(2)>",
                     "windows.pslist.PsList", notes="</table><b>escaped?</b>")

    report = build_html(case, db.get_data_sources(), db.get_results(),
                        db.get_bookmarks(), db.get_audit_log())

    # The payloads must survive as visible text but never as live markup:
    # what matters is that no attacker-supplied tag is left unescaped.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report
    assert "&lt;img src=x onerror=alert(2)&gt;" in report
    assert "<script>alert(1)</script>" not in report
    assert "<img src=x" not in report
    assert "</table><b>escaped?</b>" not in report

    # The only tags in the document are the ones the generator itself wrote.
    import re
    tags = {t.lower() for t in re.findall(r"<\s*/?\s*([a-zA-Z][\w-]*)", report)}
    assert tags <= {
        "!doctype", "html", "head", "meta", "title", "style", "body", "div",
        "h1", "h2", "p", "dl", "dt", "dd", "table", "thead", "tbody", "tr",
        "th", "td", "span", "footer",
    }, tags


def test_json_report_round_trips(populated):
    case, db = populated
    payload = json.loads(build_json(case, db.get_data_sources(), db.get_results(),
                                    db.get_bookmarks(), db.get_audit_log()))

    assert payload["case"]["case_name"] == "Op Nightfall"
    assert len(payload["data_sources"]) == 1
    assert payload["bookmarks"][0]["tag"] == "Suspicious"


def test_empty_case_still_produces_a_report(tmp_path):
    case = Case.create(str(tmp_path), "Nothing Yet")
    report = build_html(case, [], [], [], [])

    assert "Nothing Yet" in report
    assert "Nothing recorded." in report
