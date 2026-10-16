"""The report folder: layout, integrity manifest, dumps, failure handling."""
import csv
import hashlib
import json
import os
import re
import sqlite3
from contextlib import closing

import pytest

from core import report_bundle
from core.case import Case
from core.database import Database
from core.report_bundle import (
    MANIFEST, BundleCancelled, BundleOptions, build_bundle, bundle_dirname,
)
from tests.vol_fixtures import all_payloads, payload


@pytest.fixture
def case_db(tmp_path):
    image = tmp_path / "host.raw"
    image.write_bytes(b"\0" * 4096)
    case = Case.create(str(tmp_path), "Op Nightfall", case_number="2024-7",
                       examiner_name="A. Analyst", image_path=str(image))
    db = Database(case.directory, case.case_name)
    db.attach_case(case.to_dict())
    source_id = db.get_data_sources()[0]["id"]
    for p in all_payloads():
        db.save_analysis(p["plugin"], p, source_id=source_id)
    return case, db, source_id


def _add_dump(case, db, source_id, name="pid.2600/scvhost.exe.img", data=b"MZ" + b"\0" * 9000):
    path = os.path.join(case.directory, "dumps", name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    db.record_extraction(path, "windows.pslist.PsList", kind="process", pid="2600",
                         process="scvhost.exe", source_id=source_id)
    return path


def _manifest(folder):
    entries = {}
    for line in open(os.path.join(folder, MANIFEST), encoding="utf-8"):
        digest, relative = line.rstrip("\n").split("  ", 1)
        entries[relative] = digest
    return entries


def _sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


# ── Layout ────────────────────────────────────────────────────────────────────

def test_bundle_lands_in_the_case_reports_folder(case_db):
    case, db, _ = case_db
    result = build_bundle(case, db)
    assert os.path.dirname(result.path) == os.path.join(case.directory, "reports")
    assert re.fullmatch(r"Op_Nightfall_\d{8}-\d{6}(-\d+)?", os.path.basename(result.path))
    for name in ("index.html", "report.json", "README.txt", MANIFEST, "insights.csv",
                 "bookmarks.csv", "audit_log.csv", "extracted_files.csv"):
        assert os.path.isfile(os.path.join(result.path, name)), name
    analysis = os.listdir(os.path.join(result.path, "analysis"))
    assert len(analysis) == len(all_payloads())
    assert os.listdir(os.path.join(result.path, "timeline")) == ["host.raw.csv"]
    assert result.insights >= 10 and result.events == 25


def test_every_stored_run_is_exported_in_full(case_db):
    case, db, source_id = case_db
    big = {"plugin": "windows.handles.Handles", "columns": ["PID", "Name"],
           "rows": [[str(i), f"h{i}"] for i in range(5000)]}
    db.save_analysis(big["plugin"], big, source_id=source_id)
    result = build_bundle(case, db)
    handles = [n for n in os.listdir(os.path.join(result.path, "analysis"))
               if n.startswith("Handles")]
    with open(os.path.join(result.path, "analysis", handles[0]), encoding="utf-8-sig") as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["PID", "Name"] and len(rows) == 5001


def test_two_runs_of_one_plugin_get_two_files(case_db):
    case, db, source_id = case_db
    db.save_analysis("windows.pslist.PsList", payload("windows.pslist.PsList"),
                     source_id=source_id)
    result = build_bundle(case, db)
    pslists = [n for n in os.listdir(os.path.join(result.path, "analysis"))
               if n.startswith("PsList")]
    assert len(pslists) == 2


def test_manifest_covers_every_file_and_verifies(case_db):
    case, db, source_id = case_db
    _add_dump(case, db, source_id)
    result = build_bundle(case, db)
    entries = _manifest(result.path)
    on_disk = {
        os.path.relpath(os.path.join(base, n), result.path).replace(os.sep, "/")
        for base, _, names in os.walk(result.path) for n in names
    } - {MANIFEST}
    assert set(entries) == on_disk
    for relative, digest in entries.items():
        assert _sha(os.path.join(result.path, relative)) == digest, relative
    assert result.files == len(on_disk) + 1


def test_index_links_point_at_real_files(case_db):
    case, db, source_id = case_db
    _add_dump(case, db, source_id)
    result = build_bundle(case, db)
    html = open(result.index, encoding="utf-8").read()
    links = re.findall(r"href=['\"]([^'\"#]+)['\"]", html)
    assert any(l.startswith("analysis/") for l in links)
    assert any(l.startswith("dumps/") for l in links)
    assert "insights.csv" in links
    for link in links:
        assert os.path.exists(os.path.join(result.path, *link.split("/"))), link
    assert "\\" not in "".join(links), "links must use forward slashes"


def test_index_contains_insights_timeline_and_chart(case_db):
    case, db, _ = case_db
    html = open(build_bundle(case, db).index, encoding="utf-8").read()
    assert "Insights (" in html and "Incident Timeline" in html
    assert "<svg" in html and "scvhost.exe imitates svchost.exe" in html
    assert "<script" not in html.lower()


def test_report_json_is_complete(case_db):
    case, db, _ = case_db
    data = json.load(open(os.path.join(build_bundle(case, db).path, "report.json")))
    assert data["insights"] and data["timeline"]["host.raw"]["summary"]["events"] == 25
    assert any(k.startswith("analysis/") for k in data["files"])


def test_csvs_open_in_excel_with_unicode(case_db):
    case, db, source_id = case_db
    db.save_analysis("windows.x.Unicode", {"columns": ["Name"], "rows": [["процесс-😀"]]},
                     source_id=source_id)
    result = build_bundle(case, db)
    name = next(n for n in os.listdir(os.path.join(result.path, "analysis"))
                if n.startswith("Unicode"))
    raw = open(os.path.join(result.path, "analysis", name), "rb").read()
    assert raw.startswith(b"\xef\xbb\xbf")
    assert "процесс-😀" in raw.decode("utf-8-sig")


# ── Dumps ─────────────────────────────────────────────────────────────────────

def test_dumps_are_hard_linked_by_default(case_db):
    case, db, source_id = case_db
    original = _add_dump(case, db, source_id)
    result = build_bundle(case, db)
    copy = os.path.join(result.path, "dumps", "pid.2600", "scvhost.exe.img")
    assert result.dumps_linked == 1 and result.dumps_copied == 0
    assert os.path.samefile(original, copy)


def test_dumps_fall_back_to_copying_when_links_fail(case_db, monkeypatch):
    case, db, source_id = case_db
    original = _add_dump(case, db, source_id)
    def no_links(*a):
        raise OSError("cross-device link")
    monkeypatch.setattr(report_bundle.os, "link", no_links)
    result = build_bundle(case, db)
    copy = os.path.join(result.path, "dumps", "pid.2600", "scvhost.exe.img")
    assert result.dumps_copied == 1
    assert not os.path.samefile(original, copy) and _sha(original) == _sha(copy)


def test_copy_mode_always_copies(case_db):
    case, db, source_id = case_db
    original = _add_dump(case, db, source_id)
    result = build_bundle(case, db, options=BundleOptions(dump_mode="copy"))
    assert result.dumps_copied == 1
    assert not os.path.samefile(
        original, os.path.join(result.path, "dumps", "pid.2600", "scvhost.exe.img"))


def test_none_mode_leaves_dumps_out_but_lists_them(case_db):
    case, db, source_id = case_db
    _add_dump(case, db, source_id)
    result = build_bundle(case, db, options=BundleOptions(dump_mode="none"))
    assert not os.path.exists(os.path.join(result.path, "dumps"))
    listing = open(os.path.join(result.path, "extracted_files.csv"), encoding="utf-8-sig").read()
    assert "scvhost.exe" in listing


def test_unrecorded_files_in_dumps_are_included_too(case_db):
    case, db, _ = case_db
    loose = os.path.join(case.directory, "dumps", "manual", "notes.bin")
    os.makedirs(os.path.dirname(loose))
    open(loose, "wb").write(b"x")
    result = build_bundle(case, db)
    assert os.path.exists(os.path.join(result.path, "dumps", "manual", "notes.bin"))


def test_files_outside_the_case_are_never_bundled(case_db, tmp_path):
    # A handed-over case could carry a forged extraction row, or a symlink in
    # dumps/, pointing at the examiner's own files. Neither may leave with the report.
    case, db, source_id = case_db
    secret = tmp_path / "id_rsa"
    secret.write_bytes(b"PRIVATE KEY")
    db.record_extraction(str(secret), "p", source_id=source_id)
    os.symlink(secret, os.path.join(case.dumps_dir, "innocent.bin"))
    result = build_bundle(case, db)
    for base, _dirs, names in os.walk(result.path):
        for name in names:
            with open(os.path.join(base, name), "rb") as handle:
                assert b"PRIVATE KEY" not in handle.read()
    assert sum("outside the case folder" in w for w in result.warnings) == 2


def test_deleted_dump_is_reported_not_fatal(case_db):
    case, db, source_id = case_db
    path = _add_dump(case, db, source_id)
    os.unlink(path)
    result = build_bundle(case, db)
    assert result.dumps_missing == [path]


def test_unreadable_dump_becomes_a_warning(case_db, monkeypatch):
    case, db, source_id = case_db
    _add_dump(case, db, source_id)
    def refuse(*a, **k):
        raise PermissionError("denied")
    monkeypatch.setattr(report_bundle, "_place_file", refuse)
    result = build_bundle(case, db)
    assert any("denied" in w for w in result.warnings)


# ── Odd cases ─────────────────────────────────────────────────────────────────

def test_an_empty_case_still_produces_a_report(tmp_path):
    case = Case.create(str(tmp_path), "Empty")
    db = Database(case.directory, case.case_name)
    db.attach_case(case.to_dict())
    result = build_bundle(case, db)
    assert os.path.isfile(result.index)
    assert result.insights == 0 and result.events == 0
    assert not os.path.exists(os.path.join(result.path, "insights.csv"))


def test_two_reports_in_the_same_second_do_not_collide(case_db, monkeypatch):
    case, db, _ = case_db
    monkeypatch.setattr(report_bundle, "bundle_dirname", lambda *a, **k: "Fixed")
    first = build_bundle(case, db)
    second = build_bundle(case, db)
    assert first.path != second.path and second.path.endswith("Fixed-2")


@pytest.mark.parametrize("name, expected", [
    ("Op Nightfall", "Op_Nightfall"), ("../../etc", "etc"), ("名前", "case"),
    ("", "case"), ("a" * 300, "a" * 80),
])
def test_bundle_dirname_is_safe(name, expected):
    assert bundle_dirname(name).rsplit("_", 1)[0] == expected


def test_results_from_several_sources_get_separate_timelines(case_db, tmp_path):
    case, db, _ = case_db
    second = tmp_path / "second.raw"
    second.write_bytes(b"\0")
    other = db.add_data_source(str(second))
    db.save_analysis("windows.pslist.PsList", payload("windows.pslist.PsList"), source_id=other)
    result = build_bundle(case, db)
    assert sorted(os.listdir(os.path.join(result.path, "timeline"))) == [
        "host.raw.csv", "second.raw.csv"]


def test_corrupt_stored_result_is_a_warning(case_db):
    case, db, _ = case_db
    with closing(sqlite3.connect(db.db_path)) as conn, conn:
        conn.execute("UPDATE analysis_results SET result_json = '{broken' WHERE id = 1")
    result = build_bundle(case, db)
    assert any("could not be read" in w for w in result.warnings)
    assert os.path.isfile(result.index)


def test_cancelling_removes_the_partial_folder(case_db):
    case, db, _ = case_db
    calls = {"n": 0}
    def cancel_midway():
        calls["n"] += 1
        return calls["n"] > 3
    with pytest.raises(BundleCancelled):
        build_bundle(case, db, cancelled=cancel_midway)
    assert os.listdir(os.path.join(case.directory, "reports")) == []


def test_a_crash_removes_the_partial_folder(case_db, monkeypatch):
    case, db, _ = case_db
    def explode(*a, **k):
        raise RuntimeError("render failed")
    monkeypatch.setattr(report_bundle, "build_html", explode)
    with pytest.raises(RuntimeError):
        build_bundle(case, db)
    assert os.listdir(os.path.join(case.directory, "reports")) == []


def test_unknown_dump_mode_is_refused(case_db):
    case, db, _ = case_db
    with pytest.raises(ValueError):
        build_bundle(case, db, options=BundleOptions(dump_mode="zip"))


def test_progress_is_reported_and_ends_at_100(case_db):
    case, db, _ = case_db
    seen = []
    build_bundle(case, db, progress=lambda pct, msg: seen.append(pct))
    assert seen[-1] == 100 and all(0 <= p <= 100 for p in seen)
    assert seen == sorted(seen)


def test_hostile_output_is_escaped_in_the_bundle(case_db):
    case, db, source_id = case_db
    db.save_analysis("windows.cmdline.CmdLine", {
        "columns": ["TreeDepth", "PID", "Process", "Args"],
        "rows": [["0", "66", "<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]],
    }, source_id=source_id)
    html = open(build_bundle(case, db).index, encoding="utf-8").read()
    assert "<script>alert" not in html and "<img src=x" not in html
