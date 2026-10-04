"""
An incident timeline built from stored plugin output.

Volatility3 plugins each carry a few timestamps — when a process was created,
when a DLL was mapped, when a socket was opened — but each plugin reports only
its own. This module turns the output of every plugin that has been run into
one ordered list of events, the way Autopsy's timeline does for disk images, so
an examiner can see that a document was opened, a process spawned from it, a
DLL loaded into that process and a connection made, in that order.

Nothing here runs volatility3. It reads the {columns, rows} payloads already in
the case database, so the timeline reflects exactly what has been analysed and
can be rebuilt instantly whenever another plugin finishes.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# ── Event kinds ───────────────────────────────────────────────────────────────

# (key, label, colour). The order is the legend order and the stacking order.
KINDS: tuple[tuple[str, str, str], ...] = (
    ("process",      "Process created",   "#7fbfa6"),
    ("process_exit", "Process exited",    "#5f8f7c"),
    ("thread",       "Thread created",    "#9aa7b8"),
    ("dll",          "DLL loaded",        "#b39ddb"),
    ("network",      "Network activity",  "#6aa9e0"),
    ("session",      "Logon session",     "#d9c07a"),
    ("execution",    "Program executed",  "#e0a06a"),
    ("registry",     "Registry change",   "#c79ad9"),
    ("file",         "File activity",     "#8fbf7f"),
    ("driver",       "Driver activity",   "#e0796f"),
    ("other",        "Other",             "#95a09b"),
)
KIND_LABELS = {key: label for key, label, _ in KINDS}
KIND_COLORS = {key: color for key, _, color in KINDS}

# Plugins whose output feeds the timeline, in the order "Collect timeline
# data" runs them. The first three are cheap and give the backbone; the rest
# add colour and can be slower.
TIMELINE_PLUGINS: tuple[str, ...] = (
    "windows.pslist.PsList",
    "windows.psscan.PsScan",
    "windows.dlllist.DllList",
    "windows.netscan.NetScan",
    "windows.sessions.Sessions",
    "windows.registry.userassist.UserAssist",
    "windows.cmdline.CmdLine",            # no timestamps, but annotates processes
)


# ── Timestamps ────────────────────────────────────────────────────────────────

# vol3's CLI renders datetimes as "%Y-%m-%d %H:%M:%S.%f %Z", which for an
# aware UTC value reads "2019-12-09 17:39:51.000000 UTC". The JSON renderer and
# other tools use ISO 8601. Absent values come through as "N/A", "-" or "".
_TIME = re.compile(
    r"^\s*(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?"
    r"\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?\s*$",
    re.IGNORECASE,
)

# Windows FILETIME zero is 1601-01-01; unset UNIX times are 1970-01-01. Neither
# is an event, and nothing in a memory image of a running Windows machine
# predates its first release with a kernel volatility3 supports.
_EARLIEST = datetime(1990, 1, 1, tzinfo=timezone.utc)
_LATEST = datetime(2100, 1, 1, tzinfo=timezone.utc)


def parse_time(value) -> datetime | None:
    """A vol3 timestamp as an aware UTC datetime, or None when there is none."""
    if value is None:
        return None
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    else:
        match = _TIME.match(str(value))
        if not match:
            return None
        year, month, day, hour, minute, second, fraction, zone = match.groups()
        try:
            moment = datetime(
                int(year), int(month), int(day), int(hour), int(minute), int(second),
                int((fraction or "0")[:6].ljust(6, "0")), tzinfo=timezone.utc,
            )
        except ValueError:
            return None
        if zone and zone[0] in "+-":
            sign = 1 if zone[0] == "+" else -1
            digits = zone[1:].replace(":", "")
            offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
            moment -= sign * offset
    moment = moment.astimezone(timezone.utc)
    if not _EARLIEST <= moment < _LATEST:
        return None
    return moment


def format_time(moment: datetime | None) -> str:
    if moment is None:
        return ""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ── Events ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Event:
    time: datetime
    kind: str
    summary: str
    pid: str = ""
    process: str = ""
    plugin: str = ""
    detail: str = ""

    @property
    def label(self) -> str:
        return KIND_LABELS.get(self.kind, self.kind)

    def as_row(self) -> list[str]:
        return [format_time(self.time), self.label, self.pid, self.process,
                self.summary, self.plugin.rsplit(".", 1)[-1]]


EVENT_COLUMNS = ["Time (UTC)", "Type", "PID", "Process", "Description", "Source"]


def _suffix(plugin_id: str) -> str:
    """'windows.pslist.PsList' -> 'pslist.pslist'; robust to vol3 moving modules."""
    parts = plugin_id.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else plugin_id.lower()


def _index(columns: list[str]) -> dict[str, int]:
    return {name.strip(): i for i, name in enumerate(columns)}


def _cell(row: list, index: dict[str, int], *names: str) -> str:
    for name in names:
        position = index.get(name)
        if position is not None and position < len(row):
            value = row[position]
            text = "" if value is None else str(value).strip()
            if text and text not in ("N/A", "-"):
                return text
    return ""


@dataclass
class _Context:
    """Process facts gathered across plugins, used to annotate events."""
    names: dict[str, str] = field(default_factory=dict)        # pid -> image name
    cmdlines: dict[str, str] = field(default_factory=dict)     # pid -> command line


def _process_events(plugin, columns, rows, ctx) -> list[Event]:
    index = _index(columns)
    events = []
    for row in rows:
        pid = _cell(row, index, "PID")
        name = _cell(row, index, "ImageFileName", "Name")
        ppid = _cell(row, index, "PPID")
        if pid and name:
            ctx.names.setdefault(pid, name)
        created = parse_time(_cell(row, index, "CreateTime"))
        if created:
            events.append(Event(created, "process", f"{name or '?'} started"
                                + (f" by PPID {ppid}" if ppid else ""),
                                pid, name, plugin))
        exited = parse_time(_cell(row, index, "ExitTime"))
        if exited:
            events.append(Event(exited, "process_exit", f"{name or '?'} exited",
                                pid, name, plugin))
    return events


def _dll_events(plugin, columns, rows, ctx) -> list[Event]:
    index = _index(columns)
    events = []
    for row in rows:
        moment = parse_time(_cell(row, index, "LoadTime"))
        if not moment:
            continue
        pid = _cell(row, index, "PID")
        process = _cell(row, index, "Process") or ctx.names.get(pid, "")
        dll = _cell(row, index, "Name")
        path = _cell(row, index, "Path")
        events.append(Event(moment, "dll", f"{dll or path or '?'} loaded",
                            pid, process, plugin, path))
    return events


def _network_events(plugin, columns, rows, ctx) -> list[Event]:
    index = _index(columns)
    events = []
    for row in rows:
        moment = parse_time(_cell(row, index, "Created"))
        if not moment:
            continue
        pid = _cell(row, index, "PID")
        owner = _cell(row, index, "Owner") or ctx.names.get(pid, "")
        proto = _cell(row, index, "Proto")
        local = f"{_cell(row, index, 'LocalAddr')}:{_cell(row, index, 'LocalPort')}"
        foreign_addr = _cell(row, index, "ForeignAddr")
        foreign = f"{foreign_addr}:{_cell(row, index, 'ForeignPort')}"
        state = _cell(row, index, "State")
        if state.upper() == "LISTENING" or foreign_addr in ("", "*", "0.0.0.0", "::"):
            summary = f"{proto} listening on {local}"
        else:
            summary = f"{proto} {local} → {foreign}" + (f" ({state})" if state else "")
        events.append(Event(moment, "network", summary, pid, owner, plugin))
    return events


def _thread_events(plugin, columns, rows, ctx) -> list[Event]:
    index = _index(columns)
    events = []
    for row in rows:
        moment = parse_time(_cell(row, index, "CreateTime"))
        if not moment:
            continue
        pid = _cell(row, index, "PID")
        tid = _cell(row, index, "TID")
        start = _cell(row, index, "Win32StartPath", "StartPath")
        events.append(Event(moment, "thread",
                            f"Thread {tid} created" + (f" in {start}" if start else ""),
                            pid, ctx.names.get(pid, ""), plugin))
    return events


def _session_events(plugin, columns, rows, ctx) -> list[Event]:
    index = _index(columns)
    events = []
    for row in rows:
        moment = parse_time(_cell(row, index, "Create Time"))
        if not moment:
            continue
        user = _cell(row, index, "User Name")
        session = _cell(row, index, "Session ID")
        kind = _cell(row, index, "Session Type")
        pid = _cell(row, index, "Process ID")
        events.append(Event(moment, "session",
                            f"Session {session} {kind}".strip()
                            + (f" for {user}" if user else ""),
                            pid, _cell(row, index, "Process"), plugin))
    return events


def _userassist_events(plugin, columns, rows, ctx) -> list[Event]:
    index = _index(columns)
    events = []
    for row in rows:
        moment = parse_time(_cell(row, index, "Last Updated"))
        name = _cell(row, index, "Name")
        if moment and name:
            count = _cell(row, index, "Count")
            events.append(Event(moment, "execution",
                                f"{name} run" + (f" ({count}×)" if count else ""),
                                plugin=plugin, detail=_cell(row, index, "Path")))
    return events


def _shimcache_events(plugin, columns, rows, ctx) -> list[Event]:
    index = _index(columns)
    events = []
    for row in rows:
        moment = parse_time(_cell(row, index, "Last Modified"))
        path = _cell(row, index, "File Path")
        if moment and path:
            events.append(Event(moment, "execution", f"ShimCache: {path}", plugin=plugin))
    return events


def _mft_events(plugin, columns, rows, ctx) -> list[Event]:
    index = _index(columns)
    events = []
    for row in rows:
        name = _cell(row, index, "Filename")
        for column, verb in (("Created", "created"), ("Modified", "modified")):
            moment = parse_time(_cell(row, index, column))
            if moment and name:
                events.append(Event(moment, "file", f"{name} {verb}", plugin=plugin))
    return events


def _unloaded_events(plugin, columns, rows, ctx) -> list[Event]:
    index = _index(columns)
    events = []
    for row in rows:
        moment = parse_time(_cell(row, index, "Time"))
        name = _cell(row, index, "Name")
        if moment:
            events.append(Event(moment, "driver", f"{name or '?'} unloaded", plugin=plugin))
    return events


def _timeliner_events(plugin, columns, rows, ctx) -> list[Event]:
    index = _index(columns)
    events = []
    for row in rows:
        source = _cell(row, index, "Plugin")
        description = _cell(row, index, "Description")
        for column, verb in (("Created Date", "created"), ("Modified Date", "modified")):
            moment = parse_time(_cell(row, index, column))
            if moment:
                events.append(Event(moment, _timeliner_kind(source),
                                    f"{description} {verb}".strip(), plugin=plugin,
                                    detail=source))
    return events


def _timeliner_kind(source: str) -> str:
    lowered = source.lower()
    for needle, kind in (("pslist", "process"), ("psscan", "process"),
                         ("dlllist", "dll"), ("netscan", "network"),
                         ("thrd", "thread"), ("thread", "thread"),
                         ("userassist", "execution"), ("shimcache", "execution"),
                         ("registry", "registry"), ("hive", "registry"),
                         ("mft", "file"), ("module", "driver"), ("driver", "driver")):
        if needle in lowered:
            return kind
    return "other"


def _generic_events(plugin, columns, rows, ctx) -> list[Event]:
    """Any other plugin: every column that parses as a time becomes an event."""
    index = _index(columns)
    time_columns = [name for name in index
                    if re.search(r"time|date|created|modified|updated", name, re.I)]
    if not time_columns:
        return []
    events = []
    short = plugin.rsplit(".", 1)[-1]
    for row in rows:
        pid = _cell(row, index, "PID")
        label = (_cell(row, index, "Name", "ImageFileName", "Process", "Key", "Path")
                 or short)
        for column in time_columns:
            moment = parse_time(_cell(row, index, column))
            if moment:
                kind = "registry" if "registry" in plugin.lower() else "other"
                events.append(Event(moment, kind, f"{label} — {column}", pid,
                                    ctx.names.get(pid, ""), plugin))
    return events


_EXTRACTORS = {
    "pslist.pslist": _process_events,
    "psscan.psscan": _process_events,
    "pstree.pstree": _process_events,
    "dlllist.dlllist": _dll_events,
    "netscan.netscan": _network_events,
    "netstat.netstat": _network_events,
    "thrdscan.thrdscan": _thread_events,
    "threads.threads": _thread_events,
    "sessions.sessions": _session_events,
    "userassist.userassist": _userassist_events,
    "shimcachemem.shimcachemem": _shimcache_events,
    "mftscan.mftscan": _mft_events,
    "unloadedmodules.unloadedmodules": _unloaded_events,
    "timeliner.timeliner": _timeliner_events,
}

# Process facts are gathered first so later plugins can name the processes
# their rows only identify by PID.
_FIRST = ("pslist.pslist", "psscan.psscan", "pstree.pstree")


def build_events(payloads: list[dict]) -> list[Event]:
    """
    Every timestamped event in `payloads`, oldest first, de-duplicated.

    Each payload is {"plugin", "columns", "rows"} as stored by the database.
    A payload that is malformed in any way contributes nothing rather than
    stopping the rest from being read.
    """
    ctx = _Context()
    usable = []
    for payload in payloads or []:
        if not isinstance(payload, dict):
            continue
        plugin = str(payload.get("plugin") or "")
        columns = payload.get("columns") or []
        rows = payload.get("rows") or []
        if not isinstance(columns, list) or not isinstance(rows, list):
            continue
        rows = [r for r in rows if isinstance(r, (list, tuple))]
        usable.append((plugin, [str(c) for c in columns], rows))

    # pslist first, so a process both lists report is credited to the active
    # list; psscan then only contributes what pslist could not see.
    usable.sort(key=lambda item: _FIRST.index(_suffix(item[0]))
                if _suffix(item[0]) in _FIRST else len(_FIRST))
    for plugin, columns, rows in usable:
        if _suffix(plugin) == "cmdline.cmdline":
            index = _index(columns)
            for row in rows:
                pid = _cell(row, index, "PID")
                if pid:
                    ctx.cmdlines[pid] = _cell(row, index, "Args")

    seen: set = set()
    events: list[Event] = []
    for plugin, columns, rows in usable:
        extractor = _EXTRACTORS.get(_suffix(plugin), _generic_events)
        try:
            produced = extractor(plugin, columns, rows, ctx)
        except Exception:                # one odd payload must not sink the rest
            continue
        for event in produced:
            # pslist, psscan and pstree all report the same process creation;
            # one event per (kind, pid, time, summary) keeps the counts honest.
            key = (event.kind, event.pid, event.time, event.summary)
            if key in seen:
                continue
            seen.add(key)
            if event.pid and not event.detail and event.pid in ctx.cmdlines \
                    and event.kind in ("process", "network"):
                event = Event(event.time, event.kind, event.summary, event.pid,
                              event.process, event.plugin, ctx.cmdlines[event.pid])
            events.append(event)
    events.sort(key=lambda e: (e.time, e.kind, e.pid))
    return events


# ── Aggregation ───────────────────────────────────────────────────────────────

def time_range(events: list[Event]) -> tuple[datetime, datetime] | None:
    if not events:
        return None
    return events[0].time, events[-1].time


def histogram(events: list[Event], start: datetime, end: datetime,
              buckets: int) -> list[Counter]:
    """
    Event counts per kind in `buckets` equal slices of [start, end].

    A zero-width range (every event at one instant) is widened by a second so
    the single bar still has somewhere to be drawn.
    """
    buckets = max(1, int(buckets))
    if end <= start:
        end = start + timedelta(seconds=1)
    span = (end - start).total_seconds()
    counts = [Counter() for _ in range(buckets)]
    for event in events:
        if event.time < start or event.time > end:
            continue
        position = int((event.time - start).total_seconds() / span * buckets)
        counts[min(position, buckets - 1)][event.kind] += 1
    return counts


def filter_events(events: list[Event], kinds: set[str] | None = None,
                  start: datetime | None = None, end: datetime | None = None,
                  text: str = "") -> list[Event]:
    needle = (text or "").strip().lower()
    out = []
    for event in events:
        if kinds is not None and event.kind not in kinds:
            continue
        if start is not None and event.time < start:
            continue
        if end is not None and event.time > end:
            continue
        if needle and needle not in " ".join(
                (event.summary, event.process, event.pid, event.detail,
                 event.plugin)).lower():
            continue
        out.append(event)
    return out


def summarise(events: list[Event]) -> dict:
    """Headline numbers for the report and the timeline header."""
    span = time_range(events)
    return {
        "events": len(events),
        "first": format_time(span[0]) if span else "",
        "last": format_time(span[1]) if span else "",
        "by_kind": dict(Counter(e.kind for e in events)),
    }


def missing_inputs(available_plugins: set[str]) -> list[str]:
    """TIMELINE_PLUGINS that have no stored output yet."""
    have = {_suffix(p) for p in available_plugins}
    return [p for p in TIMELINE_PLUGINS if _suffix(p) not in have]
