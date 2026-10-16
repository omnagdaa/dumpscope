"""
Cases as self-contained directories.

A case is a folder, not a loose collection of settings:

    <case dir>/
        case.json      portable metadata, readable without the app
        <name>.db      results, bookmarks, tags, audit trail
        symbols/       ISF tables scoped to this case, including the ones
                       volatility3 builds from PDBs it downloads for this image
        cache/         volatility3's identifier cache for this case
        yara/          rules
        exports/       CSV/JSON pulled out of result tables
        dumps/         files carved by plugins
        reports/       generated case reports
        logs/

Keeping `case.json` alongside the database means a case survives being moved,
copied to another machine, or archived — the folder is the unit of work. The
database holds everything queryable; the JSON holds the identity, so a case can
still be listed and opened even if the database is locked or damaged.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

from core.paths import config_dir

log = logging.getLogger("dumpscope.case")

CASE_FILE = "case.json"
# Owner-only: a case holds password hashes and LSASS memory. Applies to folders
# DumpScope creates; Windows ignores it and uses the parent folder's ACL.
PRIVATE = 0o700
CASE_SUBDIRS = ("symbols", "cache", "yara", "exports", "dumps", "reports", "logs")

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def fit_filename(name: str, limit: int = 250) -> str:
    """
    `name` cut to `limit` UTF-8 bytes, inside the 255-byte filename limit.

    Any name short enough to have worked before is returned unchanged, so an
    existing case still finds its folder and its database.
    """
    return name.encode("utf-8")[:limit].decode("utf-8", "ignore")


def safe_dirname(name: str) -> str:
    """A filesystem-safe folder name derived from a case name."""
    cleaned = fit_filename(_UNSAFE.sub("_", name)).strip("._-")
    return cleaned or "case"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CaseError(Exception):
    """Raised when a case cannot be created or opened."""


@dataclass
class Case:
    """One investigation. `directory` is the case folder; everything else lives inside."""

    directory: str
    case_name: str
    case_number: str = ""
    date_time: str = ""
    examiner_id: str = ""
    examiner_name: str = ""
    examiner_email: str = ""
    examiner_phone: str = ""
    notes: str = ""
    created_at: str = field(default_factory=_now)
    last_opened: str = ""
    # Convenience mirror of the most recently selected image; data_sources in
    # the database is the authoritative list.
    image_path: str = ""
    md5: str = ""
    sha256: str = ""
    is_dark: bool = True
    quick_mode: bool = False

    # ── Paths ─────────────────────────────────────────────────────────────────

    @property
    def case_file(self) -> str:
        return os.path.join(self.directory, CASE_FILE)

    @property
    def db_path(self) -> str:
        from core.database import db_filename
        return os.path.join(self.directory, db_filename(self.case_name))

    def subdir(self, name: str) -> str:
        path = os.path.join(self.directory, name)
        os.makedirs(path, mode=PRIVATE, exist_ok=True)
        return path

    @property
    def symbols_dir(self) -> str:
        return self.subdir("symbols")

    @property
    def vol_cache_dir(self) -> str:
        return self.subdir("cache")

    @property
    def dumps_dir(self) -> str:
        return self.subdir("dumps")

    @property
    def yara_dir(self) -> str:
        return self.subdir("yara")

    @property
    def exports_dir(self) -> str:
        return self.subdir("exports")

    @property
    def reports_dir(self) -> str:
        return self.subdir("reports")

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    @classmethod
    def create(cls, parent_dir: str, case_name: str, **fields) -> "Case":
        """
        Make a new case folder under `parent_dir`.

        Refuses to reuse a folder that already holds a case, so a typo in the
        name can never silently merge two investigations.
        """
        if not case_name.strip():
            raise CaseError("A case needs a name.")
        directory = os.path.join(os.path.abspath(parent_dir), safe_dirname(case_name))
        if os.path.exists(os.path.join(directory, CASE_FILE)):
            raise CaseError(
                f"A case already exists at:\n{directory}\n\n"
                "Open it instead, or choose a different name."
            )
        try:
            os.makedirs(directory, mode=PRIVATE, exist_ok=True)
        except OSError as exc:
            raise CaseError(f"Could not create the case folder:\n{exc}") from exc

        case = cls(directory=directory, case_name=case_name.strip(), **fields)
        if not case.date_time:
            case.date_time = _now()
        for sub in CASE_SUBDIRS:
            case.subdir(sub)
        case.save()
        log.info("Created case %s at %s", case.case_name, directory)
        return case

    @classmethod
    def open(cls, directory: str) -> "Case":
        """Load a case from its folder."""
        directory = os.path.abspath(directory)
        path = os.path.join(directory, CASE_FILE)
        if not os.path.isfile(path):
            raise CaseError(f"No case.json in:\n{directory}")
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError, RecursionError) as exc:   # incl. nested-JSON bomb
            raise CaseError(f"The case file could not be read:\n{exc}") from exc
        if not isinstance(data, dict):
            raise CaseError(f"The case file is not a case record:\n{path}")

        known = {f for f in cls.__dataclass_fields__}
        payload = {k: v for k, v in data.items() if k in known}
        # The folder is the source of truth for location: a case that has been
        # moved must still open, so the stored path is deliberately ignored.
        payload["directory"] = directory
        if not isinstance(payload.get("case_name"), str) or not payload["case_name"].strip():
            payload["case_name"] = os.path.basename(directory)
        # Hand-edited or damaged fields must not reach the UI as the wrong
        # type: every text field is coerced, every flag is made a bool.
        for name, spec in cls.__dataclass_fields__.items():
            if name in payload and spec.type in ("str", str):
                payload[name] = "" if payload[name] is None else str(payload[name])
            elif name in payload and spec.type in ("bool", bool):
                payload[name] = bool(payload[name])

        case = cls(**payload)
        case.last_opened = _now()
        case.save()
        return case

    @classmethod
    def quick(cls, directory: str | None = None) -> "Case":
        """A throwaway case for analysis with no record-keeping."""
        return cls(
            directory=directory or os.path.expanduser("~"),
            case_name="Quick Analysis",
            case_number="N/A",
            quick_mode=True,
        )

    def save(self):
        """Write case.json, atomically so an interrupted write cannot destroy it."""
        if self.quick_mode:
            return
        os.makedirs(self.directory, exist_ok=True)
        payload = asdict(self)
        payload["schema"] = 1
        temporary = self.case_file + ".tmp"
        try:
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
            os.replace(temporary, self.case_file)
        except OSError as exc:
            log.warning("Could not save %s: %s", self.case_file, exc)
            if os.path.exists(temporary):
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    # ── Interop ───────────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """
        The flat mapping the windows and the database layer consume.

        `base_dir` is the case directory; it is the key the rest of the app
        already uses to locate symbols, YARA rules and exports.
        """
        data = asdict(self)
        data["base_dir"] = self.directory
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Case":
        known = {f for f in cls.__dataclass_fields__}
        payload = {k: v for k, v in data.items() if k in known}
        payload["directory"] = data.get("directory") or data.get("base_dir") or "."
        return cls(**payload)

    @property
    def display_label(self) -> str:
        return (f"{self.case_name} [{self.case_number}]"
                if self.case_number and self.case_number != "N/A" else self.case_name)


# ── Recent cases ──────────────────────────────────────────────────────────────

def _config_dir() -> str:
    return config_dir()


def recent_file() -> str:
    return os.path.join(_config_dir(), "recent_cases.json")


MAX_RECENT = 12


def load_recent() -> list[dict]:
    """
    Recently opened cases, newest first.

    Entries whose folder has since disappeared are filtered out on read rather
    than being offered and failing on click. Each entry carries enough to render
    the list without touching the case folder at all, so a slow or unmounted
    network path cannot stall the launcher.
    """
    path = recent_file()
    if not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8") as handle:
            entries = json.load(handle)
    except (OSError, ValueError, RecursionError) as exc:
        log.warning("Could not read the recent-case list: %s", exc)
        return []
    if not isinstance(entries, list):
        return []
    return [
        entry for entry in entries
        if isinstance(entry, dict) and entry.get("directory")
        and os.path.isdir(entry["directory"])
    ]


def _write_recent(entries: list[dict]):
    path = recent_file()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        temporary = path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(entries[:MAX_RECENT], handle, indent=2)
        os.replace(temporary, path)
    except OSError as exc:
        log.warning("Could not update the recent-case list: %s", exc)


def remember_case(case: Case):
    """Push a case to the front of the recent list."""
    if case.quick_mode:
        return
    entry = {
        "directory": case.directory,
        "case_name": case.case_name,
        "case_number": case.case_number,
        "examiner_name": case.examiner_name,
        "last_opened": _now(),
    }
    remaining = [
        item for item in load_recent()
        if os.path.normcase(item.get("directory", "")) != os.path.normcase(case.directory)
    ]
    _write_recent([entry] + remaining)


def forget_case(directory: str):
    """Drop one case from the recent list; the case folder itself is untouched."""
    target = os.path.normcase(directory)
    _write_recent([
        item for item in load_recent()
        if os.path.normcase(item.get("directory", "")) != target
    ])
