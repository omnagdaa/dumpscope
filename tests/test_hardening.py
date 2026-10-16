"""
Crash regressions found by fuzzing and review: each of these used to raise
out of a slot or worker, which under PyQt6 aborts the whole application.
"""
from core import insights
from core.database import Database
from tests.test_runner_crashes import _run, _spec


def test_superscript_pid_does_not_break_insight_sorting():
    # "²".isdigit() is True but int("²") raises.
    payload = {"plugin": "windows.pslist.PsList",
               "columns": ["PID", "PPID", "ImageFileName"],
               "rows": [["²", "4", "lsas.exe"], ["7", "4", "scvhost.exe"]]}
    assert any(f.pid == "²" for f in insights.analyse([payload]))


def test_unreadable_stored_results_load_as_none(tmp_path):
    db = Database(str(tmp_path), "c")
    db.attach_case({"case_name": "c", "case_number": "1"})
    raw = db.save_analysis("windows.info.Info", "plain text, not JSON")
    assert db.load_result(raw) is None
    not_a_table = db.save_analysis("p", {"columns": [], "rows": []})
    with db._connect() as conn:
        conn.execute("UPDATE analysis_results SET result_json = '{\"a\": 1}' "
                     "WHERE id = ?", (not_a_table,))
    assert db.load_result(not_a_table) is None
    assert db.latest_payloads() == []


def test_field_over_csv_default_limit_streams(qapp, stub_vol):
    _, out = _run(_spec("bigfield"))
    assert out["exit"] == 0 and out["failed"] == []
    assert len(out["rows"][0][1]) == 400000


# ── Security: hostile strings from the image ─────────────────────────────────

HOSTILE = '<img src="\\\\attacker\\share\\x.png">evil.exe'


def test_hostile_text_never_reaches_a_tooltip_as_markup(qapp):
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QTextDocument
    from ui.result_model import ResultTableModel
    from ui.theme import plain

    tip = plain(HOSTILE)
    doc = QTextDocument()
    doc.setHtml(tip)
    assert doc.toPlainText() == HOSTILE            # shown literally, nothing fetched
    assert "<img" not in tip and len(plain("x" * 10**6)) < 2100

    model = ResultTableModel()
    model.set_columns(["Name"])
    model.append_rows([[HOSTILE * 10]])
    assert "<img" not in model.data(model.index(0, 0), Qt.ItemDataRole.ToolTipRole)


def test_huge_cells_are_capped_for_display_but_kept_whole(qapp):
    from ui.result_model import ResultTableModel
    model = ResultTableModel()
    model.set_columns(["Hexdump"])
    model.append_rows([["ab" * 10**6]])
    assert len(model.data(model.index(0, 0))) == model.DISPLAY_LIMIT + 1
    assert len(model.row_values(0)[0]) == 2 * 10**6


def test_csv_exports_defuse_spreadsheet_formulas(tmp_path):
    import csv as csvlib
    from core.report_bundle import csv_cell, write_csv
    assert csv_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert csv_cell("@SUM(A1)") == "'@SUM(A1)" and csv_cell("+1+1") == "'+1+1"
    assert csv_cell("-1") == "-1" and csv_cell("-2.5e3") == "-2.5e3"   # numbers kept
    assert csv_cell("svchost.exe") == "svchost.exe" and csv_cell(None) == ""
    path = tmp_path / "out.csv"
    write_csv(str(path), ["=H"], [["=1+1", "ok"]])
    with open(path, encoding="utf-8-sig", newline="") as handle:
        assert list(csvlib.reader(handle)) == [["'=H"], ["'=1+1", "ok"]]


def test_probe_survives_non_utf8_banner_output(tmp_path):
    import sys
    from core.os_detect import _run_vol
    script = "import sys; sys.stdout.buffer.write(b'Linux \\xff\\xfe banner')"
    code, out, _ = _run_vol([sys.executable, "-c", script], [], timeout=30)
    assert code == 0 and out.startswith("Linux") and "�" in out


# ── Hostile or damaged files handed to the app ────────────────────────────────

BOMB = "[" * 200000 + "]" * 200000            # json raises RecursionError, not ValueError


def test_nested_json_bombs_are_rejected_not_fatal(tmp_path):
    import os
    import pytest
    from core import case as casemod, settings
    from core.case import Case, CaseError

    os.makedirs(os.path.dirname(settings.settings_file()), exist_ok=True)
    with open(settings.settings_file(), "w") as handle:
        handle.write(BOMB)
    assert settings.load(refresh=True)["font_size"] == settings.DEFAULTS["font_size"]
    with open(casemod.recent_file(), "w") as handle:
        handle.write(BOMB)
    assert casemod.load_recent() == []

    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "case.json").write_text(BOMB)
    with pytest.raises(CaseError):
        Case.open(str(evil))

    db = Database(str(tmp_path), "c")
    db.attach_case({"case_name": "c"})
    result = db.save_analysis("p", {"columns": ["a"], "rows": []})
    db.save_bookmark("label", "", "")
    with db._connect() as conn:
        conn.execute("UPDATE analysis_results SET result_json = ?", (BOMB,))
        conn.execute("UPDATE bookmarks SET row_json = ?", (BOMB,))
    assert db.load_result(result) is None
    assert db.get_bookmarks()[0]["row"] == {}


def test_long_case_names_fit_the_filesystem_and_short_ones_are_unchanged(tmp_path):
    from core.case import Case, safe_dirname
    from core.database import db_filename
    long_name = "Операция " * 60                   # ~1 KB of UTF-8
    case = Case.create(str(tmp_path), long_name)
    Database(case.directory, case.case_name)       # the database file can be created too
    assert len(db_filename(long_name).encode()) <= 255
    assert safe_dirname("Op Nightfall") == "Op_Nightfall"
    assert db_filename("Op Nightfall") == "Op_Nightfall.db"


def test_a_planted_package_in_the_working_directory_is_not_imported(tmp_path, monkeypatch):
    # `python -c` puts the cwd first on sys.path; DumpScope started from inside
    # a handed-over folder must still run the real volatility3.
    import subprocess
    from core import vol_runner
    (tmp_path / "volatility3").mkdir()
    (tmp_path / "volatility3" / "__init__.py").write_text("raise SystemExit('HIJACKED')")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(vol_runner, "_COMMAND_CACHE", None)
    proc = subprocess.run(vol_runner.find_vol3_command() + ["-h"],
                          capture_output=True, text=True, timeout=120)
    assert "HIJACKED" not in proc.stdout + proc.stderr
    assert proc.returncode == 0


def test_case_folders_are_private(tmp_path):
    import os
    import stat
    import sys
    import pytest
    from core.case import Case
    if sys.platform == "win32":
        pytest.skip("Windows uses ACLs, not mode bits")
    case = Case.create(str(tmp_path), "Private")
    for path in (case.directory, case.dumps_dir, case.reports_dir):
        assert stat.S_IMODE(os.stat(path).st_mode) & 0o077 == 0, path
