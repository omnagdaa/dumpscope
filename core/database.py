import os
import sqlite3
from datetime import datetime


class Database:
    def __init__(self, base_dir: str, case_name: str):
        os.makedirs(base_dir, exist_ok=True)
        db_name = f"{case_name.replace(' ', '_')}.db"
        self.db_path = os.path.join(base_dir, db_name)
        self._init_db()

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_name TEXT NOT NULL,
                    case_number TEXT NOT NULL,
                    date_time TEXT,
                    base_dir TEXT,
                    examiner_id TEXT,
                    examiner_name TEXT,
                    examiner_email TEXT,
                    examiner_phone TEXT,
                    notes TEXT,
                    image_path TEXT,
                    md5 TEXT,
                    sha256 TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS analysis_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER,
                    module TEXT NOT NULL,
                    result_json TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS bookmarks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER,
                    label TEXT,
                    description TEXT,
                    artifact_type TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );
            """)

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def save_case(self, data: dict) -> int:
        with self._connect() as conn:
            cursor = conn.execute("""
                INSERT INTO cases (
                    case_name, case_number, date_time, base_dir,
                    examiner_id, examiner_name, examiner_email, examiner_phone,
                    notes, image_path, md5, sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data.get("case_name"),
                data.get("case_number"),
                data.get("date_time"),
                data.get("base_dir"),
                data.get("examiner_id"),
                data.get("examiner_name"),
                data.get("examiner_email"),
                data.get("examiner_phone"),
                data.get("notes"),
                data.get("image_path"),
                data.get("md5"),
                data.get("sha256"),
            ))
            self.case_id = cursor.lastrowid
            return self.case_id

    def save_analysis(self, module: str, result_json: str):
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO analysis_results (case_id, module, result_json)
                VALUES (?, ?, ?)
            """, (getattr(self, "case_id", None), module, result_json))

    def save_bookmark(self, label: str, description: str, artifact_type: str):
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO bookmarks (case_id, label, description, artifact_type)
                VALUES (?, ?, ?, ?)
            """, (getattr(self, "case_id", None), label, description, artifact_type))

    def get_cases(self):
        with self._connect() as conn:
            return conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
