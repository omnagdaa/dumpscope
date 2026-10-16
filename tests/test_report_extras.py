"""
What a report has to account for: the files carved out of the image, and the
analysis output itself.
"""

import json
import os

import pytest

from core.database import Database
from core.case import Case
from core.report import build_html, build_json


@pytest.fixture
def case_with_extractions(tmp_path):
    case = Case.create(str(tmp_path), "Op Seaward", case_number="2026-091",
                       examiner_name="A. Nagda")
    db = Database(case.directory, case.case_name)
    db.attach_case(case.to_dict())

    image = tmp_path / "host.raw"
    image.write_bytes(b"\0" * 2048)
    source_id = db.add_data_source(str(image))

    result_id = db.save_analysis(
        "windows.pslist.PsList",
        {"columns": ["PID", "ImageFileName"],
         "rows": [[str(p), f"proc{p}.exe"] for p in range(1, 12)]},
        source_id=source_id,
    )

    dumps = tmp_path / "Op_Seaward" / "dumps"
    dumps.mkdir(parents=True, exist_ok=True)
    carved = dumps / "pid.820.0x8a0000.dmp"
    carved.write_bytes(b"MZ" + b"\0" * 4094)
    db.record_extraction(str(carved), plugin="windows.pslist.PsList",
                         kind="process", pid="820", process="svchost.exe",
                         source_id=source_id)
    db.set_extraction_hash(str(carved), "a" * 64)
    return case, db, result_id, str(carved)


def _report(case, db, **kwargs):
    return build_html(case, db.get_data_sources(), db.get_results(),
                      db.get_bookmarks(), db.get_audit_log(),
                      extractions=db.get_extractions(), **kwargs)


# ── Extracted files ───────────────────────────────────────────────────────────

def test_extracted_files_are_named_hashed_and_attributed(case_with_extractions):
    case, db, _result_id, carved = case_with_extractions
    report = _report(case, db)
    assert "pid.820.0x8a0000.dmp" in report
    assert "a" * 64 in report, "the hash proves what was carved out"
    assert "svchost.exe" in report and "820" in report
    assert "Process executable" in report, "the plugin name is not a description"
    assert "malicious code" in report, "a dump is evidence, and a hazard"


def test_a_file_that_has_since_vanished_is_marked_as_such(case_with_extractions):
    case, db, _result_id, carved = case_with_extractions
    os.remove(carved)
    assert "no longer on disk" in _report(case, db)


def test_a_case_with_no_extractions_still_renders(tmp_path):
    case = Case.create(str(tmp_path), "Empty")
    report = build_html(case, [], [], [], [], extractions=[])
    assert "Extracted Files (0)" in report


# ── Analysis output ───────────────────────────────────────────────────────────

def test_output_is_included_and_capped(case_with_extractions):
    case, db, result_id, _carved = case_with_extractions
    outputs = {result_id: db.load_result(result_id)}
    report = _report(case, db, outputs=outputs, max_rows=5)
    assert "proc1.exe" in report
    assert "proc11.exe" not in report, "the cap has to actually cap"
    assert "first 5 of 11" in report


def test_output_is_omitted_when_not_asked_for(case_with_extractions):
    case, db, _result_id, _carved = case_with_extractions
    assert "proc1.exe" not in _report(case, db)


def test_findings_are_summarised_by_tag(case_with_extractions):
    case, db, _result_id, _carved = case_with_extractions
    db.save_bookmark("svchost.exe", "PID 820", "windows.pslist.PsList",
                     tag="Malicious")
    db.save_bookmark("rundll32.exe", "PID 912", "windows.pslist.PsList",
                     tag="Malicious")
    report = _report(case, db)
    assert "Malicious" in report


# ── JSON and writing ──────────────────────────────────────────────────────────

def test_json_carries_the_extractions_and_output(case_with_extractions):
    case, db, result_id, _carved = case_with_extractions
    payload = json.loads(build_json(
        case, db.get_data_sources(), db.get_results(), db.get_bookmarks(),
        db.get_audit_log(), extractions=db.get_extractions(),
        outputs={result_id: db.load_result(result_id)},
    ))
    assert payload["extracted_files"][0]["pid"] == "820"
    assert payload["output"]["windows.pslist.PsList"]["rows"][0] == ["1", "proc1.exe"]


