"""Case identity, result storage and v1 migration."""
import os
import sqlite3

from core.database import Database

CASE = {
    "case_name": "Op Nightfall", "case_number": "2026-014",
    "examiner_name": "A. Nagda", "notes": "initial triage",
}


def _case(base_dir):
    return dict(CASE, base_dir=str(base_dir))


def test_reopening_a_case_reuses_one_row(tmp_path):
    """
    Regression: the first version inserted a case row on every launch, so a
    case reopened three times became three cases and results scattered across
    them.
    """
    ids = []
    for _ in range(3):
        db = Database(str(tmp_path), CASE["case_name"])
        ids.append(db.attach_case(_case(tmp_path)))

    assert len(set(ids)) == 1
    assert len(db.get_cases()) == 1


def test_results_round_trip(tmp_path):
    db = Database(str(tmp_path), CASE["case_name"])
    db.attach_case(_case(tmp_path))

    result_id = db.save_analysis("windows.pslist.PsList", {
        "columns": ["PID", "Name"],
        "rows": [["4", "System"], ["820", "svchost.exe"]],
    })
    loaded = db.load_result(result_id)

    assert loaded["columns"] == ["PID", "Name"]
    assert loaded["rows"] == [["4", "System"], ["820", "svchost.exe"]]
    assert db.get_results()[0]["row_count"] == 2


def test_audit_log_records_case_and_plugin_activity(tmp_path):
    db = Database(str(tmp_path), CASE["case_name"])
    db.attach_case(_case(tmp_path))
    db.attach_case(_case(tmp_path))
    db.save_analysis("windows.info.Info", {"columns": [], "rows": []})

    actions = [entry["action"] for entry in db.get_audit_log()]
    assert actions.count("case_created") == 1
    assert actions.count("case_opened") == 1
    assert "plugin_run" in actions


def _build_v1_database(path):
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE cases (id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_name TEXT NOT NULL, case_number TEXT NOT NULL, date_time TEXT,
          base_dir TEXT, examiner_id TEXT, examiner_name TEXT,
          examiner_email TEXT, examiner_phone TEXT, notes TEXT, image_path TEXT,
          md5 TEXT, sha256 TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE analysis_results (id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id INTEGER, module TEXT NOT NULL, result_json TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE bookmarks (id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id INTEGER, label TEXT, description TEXT, artifact_type TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    for _ in range(3):
        conn.execute("INSERT INTO cases (case_name, case_number) VALUES ('Old','1')")
    for case_id, module in ((1, "pslist"), (2, "netscan"), (3, "malfind")):
        conn.execute(
            "INSERT INTO analysis_results (case_id, module, result_json) VALUES (?,?,?)",
            (case_id, module, "text"),
        )
    conn.execute("INSERT INTO bookmarks (case_id, label) VALUES (3, 'old bookmark')")
    conn.commit()
    conn.close()


def test_v1_migration_folds_duplicates_without_losing_data(tmp_path):
    _build_v1_database(os.path.join(str(tmp_path), "Old.db"))

    db = Database(str(tmp_path), "Old")
    assert len(db.get_cases()) == 1

    conn = sqlite3.connect(os.path.join(str(tmp_path), "Old.db"))
    conn.row_factory = sqlite3.Row
    results = conn.execute("SELECT plugin, case_id FROM analysis_results").fetchall()
    bookmarks = conn.execute("SELECT label, case_id FROM bookmarks").fetchall()
    conn.close()

    assert len(results) == 3, "no result may be discarded"
    assert {r["case_id"] for r in results} == {1}
    assert len(bookmarks) == 1 and bookmarks[0]["case_id"] == 1


def test_writes_work_after_migration(tmp_path):
    _build_v1_database(os.path.join(str(tmp_path), "Old.db"))
    db = Database(str(tmp_path), "Old")
    db.attach_case({"case_name": "Old", "case_number": "1", "base_dir": str(tmp_path)})

    result_id = db.save_analysis("windows.info.Info",
                                 {"columns": ["k"], "rows": [["v"]]})
    assert db.load_result(result_id)["rows"] == [["v"]]
    assert len(db.get_cases()) == 1
