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
