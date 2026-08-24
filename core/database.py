"""
Per-case SQLite storage.

One database file per case, living inside the case directory so a case is
self-contained and can be moved or archived whole.

The important behavioural change from the first version: a case row is created
once and thereafter *reused*. Opening a case no longer inserts a duplicate, so
`case_id` is stable across sessions and stored results stay attached to the
case they were produced under.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone

log = logging.getLogger("dumpscope.database")

SCHEMA_VERSION = 4

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    case_name      TEXT NOT NULL,
    case_number    TEXT,
    date_time      TEXT,
    base_dir       TEXT,
    examiner_id    TEXT,
    examiner_name  TEXT,
    examiner_email TEXT,
    examiner_phone TEXT,
    notes          TEXT,
    image_path     TEXT,
    md5            TEXT,
    sha256         TEXT,
    created_at     TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (case_name, case_number)
);

-- A case holds many images. The single image_path on `cases` is kept as the
-- most recently selected one so older code and the overview stay meaningful,
-- but this table is the real record.
CREATE TABLE IF NOT EXISTS data_sources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    path        TEXT NOT NULL,
    display_name TEXT,
    size_bytes  INTEGER DEFAULT 0,
    md5         TEXT,
    sha256      TEXT,
    os_hint     TEXT,
    notes       TEXT,
    added_at    TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (case_id, path)
);
CREATE INDEX IF NOT EXISTS idx_sources_case ON data_sources (case_id);

CREATE TABLE IF NOT EXISTS analysis_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    source_id   INTEGER REFERENCES data_sources(id) ON DELETE SET NULL,
    plugin      TEXT NOT NULL,
    columns     TEXT,
    row_count   INTEGER DEFAULT 0,
    result_json TEXT,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_results_case_plugin
    ON analysis_results (case_id, plugin);

CREATE TABLE IF NOT EXISTS bookmarks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    source_id     INTEGER REFERENCES data_sources(id) ON DELETE SET NULL,
    label         TEXT,
    description   TEXT,
    artifact_type TEXT,
    tag           TEXT,
    notes         TEXT,
    -- v4: enough to navigate back to the row this was taken from. row_json is
    -- the whole {column: value} mapping, so the row can be found again after a
    -- re-run even though its index will have moved.
    row_json      TEXT,
    cell_column   TEXT,
    cell_value    TEXT,
    created_at    TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_bookmarks_case ON bookmarks (case_id);
CREATE INDEX IF NOT EXISTS idx_bookmarks_tag ON bookmarks (case_id, tag);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id    INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    action     TEXT NOT NULL,
    detail     TEXT,
    examiner   TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_log (case_id);

CREATE TABLE IF NOT EXISTS tags (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    name    TEXT NOT NULL,
    color   TEXT DEFAULT '#58a6ff',
    UNIQUE (case_id, name)
);
"""

# Tags every new case starts with, mirroring the vocabulary analysts reach for
# first. They are rows rather than constants so a case can add its own.
DEFAULT_TAGS = (
    ("Suspicious",  "#f85149"),
    ("Malicious",   "#da3633"),
    ("Notable",     "#e3b341"),
    ("Benign",      "#3fb950"),
    ("Follow Up",   "#58a6ff"),
)

_CASE_FIELDS = (
    "case_name", "case_number", "date_time", "base_dir",
    "examiner_id", "examiner_name", "examiner_email", "examiner_phone",
    "notes", "image_path", "md5", "sha256",
)


class Database:
    """Storage for one case. Not thread-safe; use it from the GUI thread."""

    def __init__(self, base_dir: str, case_name: str):
        os.makedirs(base_dir, exist_ok=True)
        safe_name = "".join(
            ch if ch.isalnum() or ch in "-_" else "_" for ch in case_name
        ).strip("_") or "case"
        self.db_path = os.path.join(base_dir, f"{safe_name}.db")
        self.case_id: int | None = None
        self._init_db()

    # ── Connection ────────────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        # WAL keeps a long-running read from blocking a result write.
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            # Column renames must happen before the schema script: its indexes
            # reference the current column names and would fail against a v1 table.
            self._migrate_columns(conn)
            conn.executescript(_SCHEMA)
            self._migrate_rows(conn)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def _needs_migration(self, conn: sqlite3.Connection) -> bool:
        return conn.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION

    def _migrate_columns(self, conn: sqlite3.Connection):
        """
        Reshape a v1 `analysis_results` table in place.

        v1 stored results as a `module`/`result_json` pair with no column list
        and no row count. A fresh database has no such table and skips this.
        """
        if not self._needs_migration(conn):
            return
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(analysis_results)")}
        if not columns:
            return
        if "module" in columns and "plugin" not in columns:
            log.info("Migrating analysis_results from the v1 layout")
            conn.execute("ALTER TABLE analysis_results RENAME COLUMN module TO plugin")

        # v3 adds data sources, so results and bookmarks gain a source link.
        # SQLite cannot add a column with a foreign key to an existing table, so
        # these are plain integers carrying the same meaning.
        additions = {
            "analysis_results": (
                ("columns", "TEXT"),
                ("row_count", "INTEGER DEFAULT 0"),
                ("source_id", "INTEGER"),
            ),
            "bookmarks": (
                ("source_id", "INTEGER"),
                ("tag", "TEXT"),
                ("notes", "TEXT"),
                # v4: what the tag was attached to, so it can be navigated back to.
                ("row_json", "TEXT"),
                ("cell_column", "TEXT"),
                ("cell_value", "TEXT"),
            ),
        }
        for table, wanted in additions.items():
            present = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
            if not present:
                continue
            for name, ddl in wanted:
                if name not in present:
                    try:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                    except sqlite3.OperationalError as exc:
                        log.debug("Could not add %s.%s: %s", table, name, exc)

    def _migrate_rows(self, conn: sqlite3.Connection):
        """
        Fold the duplicate case rows the old save-on-every-launch behaviour
        created into the earliest row. Results and bookmarks are repointed
        first, so nothing is lost — only the redundant case rows go.

        A migrated `cases` table keeps its original definition and so lacks the
        UNIQUE constraint a fresh one has; attach_case does not depend on it.
        """
        if not self._needs_migration(conn):
            return

        duplicates = conn.execute("""
            SELECT case_name, case_number, MIN(id) AS keep, COUNT(*) AS n
            FROM cases GROUP BY case_name, case_number HAVING n > 1
        """).fetchall()
        for row in duplicates:
            log.info(
                "Folding %d duplicate rows for case %s into id %d",
                row["n"] - 1, row["case_name"], row["keep"],
            )
            conn.execute(
                """UPDATE analysis_results SET case_id = ? WHERE case_id IN (
                       SELECT id FROM cases WHERE case_name IS ? AND case_number IS ?
                   )""",
                (row["keep"], row["case_name"], row["case_number"]),
            )
            conn.execute(
                """UPDATE bookmarks SET case_id = ? WHERE case_id IN (
                       SELECT id FROM cases WHERE case_name IS ? AND case_number IS ?
                   )""",
                (row["keep"], row["case_name"], row["case_number"]),
            )
            conn.execute(
                """DELETE FROM cases
                   WHERE case_name IS ? AND case_number IS ? AND id != ?""",
                (row["case_name"], row["case_number"], row["keep"]),
            )

    # ── Cases ─────────────────────────────────────────────────────────────────

    def attach_case(self, data: dict) -> int:
        """
        Bind this Database to the case described by `data`, creating the row on
        first use and updating it thereafter. Returns the stable case id.
        """
        name = data.get("case_name")
        number = data.get("case_number")
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT id FROM cases WHERE case_name IS ? AND case_number IS ?",
                (name, number),
            ).fetchone()

            if existing is None:
                cursor = conn.execute(
                    f"INSERT INTO cases ({','.join(_CASE_FIELDS)}) "
                    f"VALUES ({','.join('?' * len(_CASE_FIELDS))})",
                    tuple(data.get(field) for field in _CASE_FIELDS),
                )
                self.case_id = cursor.lastrowid
                action = "case_created"
            else:
                self.case_id = existing["id"]
                # Refresh the mutable fields; identity fields are the key.
                updatable = [f for f in _CASE_FIELDS
                             if f not in ("case_name", "case_number")]
                conn.execute(
                    f"UPDATE cases SET {','.join(f'{f}=?' for f in updatable)} "
                    "WHERE id = ?",
                    tuple(data.get(f) for f in updatable) + (self.case_id,),
                )
                action = "case_opened"

            self._seed_tags(conn)
            self._audit(conn, action, name, data.get("examiner_name"))

        # A case created before data sources existed, or one started from the
        # wizard with an image already chosen, still needs that image on record.
        image_path = data.get("image_path")
        if image_path:
            self.add_data_source(image_path, md5=data.get("md5") or "",
                                 sha256=data.get("sha256") or "")
        return self.case_id

    def _seed_tags(self, conn: sqlite3.Connection):
        for name, color in DEFAULT_TAGS:
            conn.execute(
                "INSERT OR IGNORE INTO tags (case_id, name, color) VALUES (?, ?, ?)",
                (self.case_id, name, color),
            )

    def update_case_image(self, image_path: str, md5: str = "", sha256: str = ""):
        if self.case_id is None:
            return
        with self._connect() as conn:
            conn.execute(
                "UPDATE cases SET image_path = ?, md5 = ?, sha256 = ? WHERE id = ?",
                (image_path, md5, sha256, self.case_id),
            )
            self._audit(conn, "image_loaded", image_path, None)

    def get_case(self) -> dict | None:
        if self.case_id is None:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM cases WHERE id = ?", (self.case_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_cases(self) -> list[dict]:
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM cases ORDER BY created_at DESC"
            )]

    # ── Results ───────────────────────────────────────────────────────────────

    def save_analysis(self, plugin: str, payload: dict | str,
                      source_id: int | None = None) -> int | None:
        """
        Store one plugin's results. `payload` is the panel's result payload
        ({plugin, columns, rows}); a plain string is accepted for callers that
        only have raw text.
        """
        if self.case_id is None:
            return None
        if isinstance(payload, str):
            columns, rows, blob = None, 0, payload
        else:
            columns = json.dumps(payload.get("columns", []))
            rows = len(payload.get("rows", []))
            blob = json.dumps(payload.get("rows", []))

        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO analysis_results
                       (case_id, source_id, plugin, columns, row_count, result_json)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (self.case_id, source_id, plugin, columns, rows, blob),
            )
            self._audit(conn, "plugin_run", f"{plugin} ({rows} rows)", None)
            return cursor.lastrowid

    def get_results(self, plugin: str | None = None,
                    source_id: int | None = None) -> list[dict]:
        """Stored runs, newest first, carrying the name of their data source."""
        query = ("SELECT r.id, r.plugin, r.columns, r.row_count, r.created_at, "
                 "       r.source_id, s.display_name AS source_name "
                 "FROM analysis_results r "
                 "LEFT JOIN data_sources s ON s.id = r.source_id "
                 "WHERE r.case_id = ?")
        params: tuple = (self.case_id,)
        if plugin:
            query += " AND r.plugin = ?"
            params += (plugin,)
        if source_id is not None:
            query += " AND r.source_id = ?"
            params += (source_id,)
        query += " ORDER BY r.created_at DESC, r.id DESC"
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(query, params)]

    def load_result(self, result_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM analysis_results WHERE id = ?", (result_id,)
            ).fetchone()
        if row is None:
            return None
        return {
            "plugin": row["plugin"],
            "columns": json.loads(row["columns"]) if row["columns"] else [],
            "rows": json.loads(row["result_json"]) if row["result_json"] else [],
            "created_at": row["created_at"],
        }

    def delete_result(self, result_id: int):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT plugin FROM analysis_results WHERE id = ?", (result_id,)
            ).fetchone()
            conn.execute("DELETE FROM analysis_results WHERE id = ?", (result_id,))
            self._audit(conn, "result_deleted", row["plugin"] if row else "", None)

    # ── Bookmarks ─────────────────────────────────────────────────────────────

    def save_bookmark(self, label: str, description: str, artifact_type: str,
                      tag: str = "", notes: str = "",
                      source_id: int | None = None,
                      row: dict | None = None,
                      cell_column: str = "", cell_value: str = "") -> int | None:
        """
        Record a tagged finding.

        `row` is the full {column: value} mapping of the output line it was
        taken from. Storing it — rather than a row index — is what lets the tag
        be followed back to its line after the plugin has been re-run against a
        different image, or after the table has been sorted.
        """
        if self.case_id is None:
            return None
        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO bookmarks
                       (case_id, source_id, label, description, artifact_type,
                        tag, notes, row_json, cell_column, cell_value)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (self.case_id, source_id, label, description, artifact_type,
                 tag, notes, json.dumps(row or {}), cell_column, cell_value),
            )
            self._audit(conn, "bookmark_added", f"{tag or 'untagged'}: {label}", None)
            return cursor.lastrowid

    @staticmethod
    def _decode_bookmark(record: dict) -> dict:
        """Turn the stored row_json back into a mapping the UI can navigate by."""
        raw = record.get("row_json")
        try:
            record["row"] = json.loads(raw) if raw else {}
        except (TypeError, ValueError):
            record["row"] = {}
        return record

    def get_bookmarks(self, tag: str | None = None) -> list[dict]:
        query = ("SELECT b.*, s.display_name AS source_name, t.color AS tag_color "
                 "FROM bookmarks b "
                 "LEFT JOIN data_sources s ON s.id = b.source_id "
                 "LEFT JOIN tags t ON t.case_id = b.case_id AND t.name = b.tag "
                 "WHERE b.case_id = ?")
        params: tuple = (self.case_id,)
        if tag:
            query += " AND b.tag = ?"
            params += (tag,)
        query += " ORDER BY b.created_at DESC, b.id DESC"
        with self._connect() as conn:
            return [self._decode_bookmark(dict(r)) for r in conn.execute(query, params)]

    # ── Data sources ──────────────────────────────────────────────────────────

    def add_data_source(self, path: str, display_name: str = "",
                        md5: str = "", sha256: str = "",
                        os_hint: str = "", notes: str = "") -> int | None:
        """
        Register an image against the case, or update what is already known
        about it. Returns the source id, which results and bookmarks reference.
        """
        if self.case_id is None:
            return None
        path = os.path.abspath(path)
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0

        with self._connect() as conn:
            existing = conn.execute(
                "SELECT id, md5, sha256, os_hint FROM data_sources "
                "WHERE case_id = ? AND path = ?",
                (self.case_id, path),
            ).fetchone()

            if existing is not None:
                # Only fill in blanks: a hash computed once must not be wiped
                # by a later call that does not carry one.
                conn.execute(
                    """UPDATE data_sources
                          SET md5 = COALESCE(NULLIF(?, ''), md5),
                              sha256 = COALESCE(NULLIF(?, ''), sha256),
                              os_hint = COALESCE(NULLIF(?, ''), os_hint),
                              size_bytes = ?
                        WHERE id = ?""",
                    (md5, sha256, os_hint, size, existing["id"]),
                )
                return existing["id"]

            cursor = conn.execute(
                """INSERT INTO data_sources
                       (case_id, path, display_name, size_bytes, md5, sha256,
                        os_hint, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (self.case_id, path, display_name or os.path.basename(path),
                 size, md5, sha256, os_hint, notes),
            )
            self._audit(conn, "source_added", path, None)
            return cursor.lastrowid

    def get_data_sources(self) -> list[dict]:
        if self.case_id is None:
            return []
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM data_sources WHERE case_id = ? ORDER BY added_at",
                (self.case_id,),
            )]

    def get_data_source(self, source_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM data_sources WHERE id = ?", (source_id,)
            ).fetchone()
        return dict(row) if row else None

    def find_data_source(self, path: str) -> dict | None:
        if self.case_id is None:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM data_sources WHERE case_id = ? AND path = ?",
                (self.case_id, os.path.abspath(path)),
            ).fetchone()
        return dict(row) if row else None

    def update_data_source_hashes(self, source_id: int, md5: str, sha256: str):
        with self._connect() as conn:
            conn.execute(
                "UPDATE data_sources SET md5 = ?, sha256 = ? WHERE id = ?",
                (md5, sha256, source_id),
            )
            self._audit(conn, "source_hashed", f"source {source_id}", None)

    def remove_data_source(self, source_id: int):
        """
        Detach an image from the case. Results and bookmarks produced from it
        are kept — deleting evidence of work already done is never the right
        default — and simply lose their source link.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT path FROM data_sources WHERE id = ?", (source_id,)
            ).fetchone()
            conn.execute("UPDATE analysis_results SET source_id = NULL "
                         "WHERE source_id = ?", (source_id,))
            conn.execute("UPDATE bookmarks SET source_id = NULL "
                         "WHERE source_id = ?", (source_id,))
            conn.execute("DELETE FROM data_sources WHERE id = ?", (source_id,))
            self._audit(conn, "source_removed", row["path"] if row else "", None)

    # ── Tags ──────────────────────────────────────────────────────────────────

    def get_tags(self) -> list[dict]:
        if self.case_id is None:
            return []
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM tags WHERE case_id = ? ORDER BY id", (self.case_id,)
            )]

    def tag_counts(self) -> dict[str, int]:
        """How many findings carry each tag, for the sidebar's counts."""
        if self.case_id is None:
            return {}
        with self._connect() as conn:
            return {
                r["tag"]: r["n"] for r in conn.execute(
                    "SELECT tag, COUNT(*) AS n FROM bookmarks "
                    "WHERE case_id = ? AND tag IS NOT NULL AND tag != '' "
                    "GROUP BY tag", (self.case_id,)
                )
            }

    def rename_tag(self, old_name: str, new_name: str) -> bool:
        """
        Rename a tag, carrying every finding that uses it along.

        Returns False if the new name is already taken — merging two tags is a
        different decision from renaming one, and silently doing it would lose
        the distinction the examiner drew.
        """
        new_name = new_name.strip()
        if self.case_id is None or not new_name or new_name == old_name:
            return False
        with self._connect() as conn:
            clash = conn.execute(
                "SELECT 1 FROM tags WHERE case_id = ? AND name = ?",
                (self.case_id, new_name),
            ).fetchone()
            if clash:
                return False
            conn.execute("UPDATE tags SET name = ? WHERE case_id = ? AND name = ?",
                         (new_name, self.case_id, old_name))
            conn.execute("UPDATE bookmarks SET tag = ? WHERE case_id = ? AND tag = ?",
                         (new_name, self.case_id, old_name))
            self._audit(conn, "tag_renamed", f"{old_name} -> {new_name}", None)
        return True

    def set_tag_color(self, name: str, color: str):
        if self.case_id is None:
            return
        with self._connect() as conn:
            conn.execute("UPDATE tags SET color = ? WHERE case_id = ? AND name = ?",
                         (color, self.case_id, name))

    def delete_tag(self, name: str, delete_findings: bool = False):
        """
        Remove a tag. By default the findings it was applied to are kept and
        simply become untagged — deleting an examiner's recorded observations
        as a side effect of tidying a label would be the wrong default.
        """
        if self.case_id is None:
            return
        with self._connect() as conn:
            if delete_findings:
                conn.execute("DELETE FROM bookmarks WHERE case_id = ? AND tag = ?",
                             (self.case_id, name))
            else:
                conn.execute("UPDATE bookmarks SET tag = '' WHERE case_id = ? AND tag = ?",
                             (self.case_id, name))
            conn.execute("DELETE FROM tags WHERE case_id = ? AND name = ?",
                         (self.case_id, name))
            self._audit(conn, "tag_deleted", name, None)

    def add_tag(self, name: str, color: str = "#58a6ff") -> int | None:
        if self.case_id is None or not name.strip():
            return None
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO tags (case_id, name, color) VALUES (?, ?, ?)",
                (self.case_id, name.strip(), color),
            )
            row = conn.execute(
                "SELECT id FROM tags WHERE case_id = ? AND name = ?",
                (self.case_id, name.strip()),
            ).fetchone()
            return row["id"] if row else None

    def delete_bookmark(self, bookmark_id: int):
        with self._connect() as conn:
            conn.execute("DELETE FROM bookmarks WHERE id = ?", (bookmark_id,))
            self._audit(conn, "bookmark_removed", str(bookmark_id), None)

    def update_bookmark(self, bookmark_id: int, label: str | None = None,
                        tag: str | None = None, notes: str | None = None):
        fields, values = [], []
        for column, value in (("label", label), ("tag", tag), ("notes", notes)):
            if value is not None:
                fields.append(f"{column} = ?")
                values.append(value)
        if not fields:
            return
        with self._connect() as conn:
            conn.execute(
                f"UPDATE bookmarks SET {', '.join(fields)} WHERE id = ?",
                (*values, bookmark_id),
            )

    # ── Audit ─────────────────────────────────────────────────────────────────

    def _audit(self, conn: sqlite3.Connection, action: str,
               detail: str | None, examiner: str | None):
        conn.execute(
            """INSERT INTO audit_log (case_id, action, detail, examiner, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (self.case_id, action, detail, examiner,
             datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )

    def log_action(self, action: str, detail: str = "", examiner: str = ""):
        with self._connect() as conn:
            self._audit(conn, action, detail, examiner)

    def get_audit_log(self) -> list[dict]:
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM audit_log WHERE case_id = ? ORDER BY id DESC",
                (self.case_id,),
            )]
