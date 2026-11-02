"""
An incident timeline built from stored plugin output.

Volatility3 plugins each carry a few timestamps (when a process was created,
when a DLL was mapped, when a socket was opened) but each plugin reports only
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
from datetime import datetime, timedelta, UTC

# ── Event kinds ───────────────────────────────────────────────────────────────

# (key, label, colour). The order is the legend order and the stacking order.
KINDS: tuple[tuple[str, str, str], ...] = (
    ("process",      "Process created",   "#7fbfa6"),
    ("process_exit", "Process exited",    "#5f8f7c"),
    ("thread",       "Thread created",    "#9aa7b8"),
    ("dll",          "DLL loaded",        "#b39ddb"),
    ("network",      "Network activity",  "#6aa9e0"),
    ("session",      "User session",      "#d9c07a"),
    ("execution",    "Program executed",  "#e0a06a"),
    ("registry",     "Registry change",   "#c79ad9"),
    ("file",         "File activity",     "#8fbf7f"),
    ("driver",       "Driver activity",   "#e0796f"),
    ("other",        "Other",             "#95a09b"),
)
KIND_LABELS = {key: label for key, label, _ in KINDS}

# What each event type means and where it comes from, for the legend's
# tooltips and the "How the timeline works" panel.
KIND_HELP = {
    "process": "A program was started. Read from the process list and the "
               "process scan (each process's create time).",
    "process_exit": "A program ended, but its record was still in memory when "
                    "the image was taken (exit time).",
    "thread": "A thread was started inside a process (thread scan).",
    "dll": "A DLL was loaded into a process (DLL List load time). Bursts of "
           "these follow every program start.",
    "network": "A network connection or listening socket was opened (Net Scan "
               "created time).",
    "session": "The first process seen for a user in a session (Sessions). Shows when "
               "the user was active; the plugin does not record the logon itself.",
    "execution": "Evidence that a program was run by a user, such as the "
                 "registry's UserAssist and ShimCache records.",
    "registry": "A registry key was last written.",
    "file": "A file's timestamps, from the file system's master file table.",
    "driver": "A driver was loaded or unloaded.",
    "other": "Any other timestamp in a plugin's output.",
}
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
_EARLIEST = datetime(1990, 1, 1, tzinfo=UTC)
_LATEST = datetime(2100, 1, 1, tzinfo=UTC)


def parse_time(value) -> datetime | None:
    """A vol3 timestamp as an aware UTC datetime, or None when there is none."""
    if value is None:
        return None
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=UTC)
    else:
        match = _TIME.match(str(value))
        if not match:
            return None
        year, month, day, hour, minute, second, fraction, zone = match.groups()
        try:
            moment = datetime(
                int(year), int(month), int(day), int(hour), int(minute), int(second),
                int((fraction or "0")[:6].ljust(6, "0")), tzinfo=UTC,
            )
        except ValueError:
            return None
        if zone and zone[0] in "+-":
            sign = 1 if zone[0] == "+" else -1
            digits = zone[1:].replace(":", "")
            offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
            moment -= sign * offset
    moment = moment.astimezone(UTC)
    if not _EARLIEST <= moment < _LATEST:
        return None
    return moment


def format_time(moment: datetime | None) -> str:
    if moment is None:
        return ""
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


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
            parent = ctx.names.get(ppid, "")
            if parent:
                by = f" by {parent} (PID {ppid})"
            elif ppid and ppid != "0":
                by = f" by PID {ppid}, which had already exited"
            else:
                by = ""
            events.append(Event(created, "process", f"{name or '?'} started{by}",
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
    """
    One event per person per session. The plugin has a row per process and its
    time is that process's start, so this is when the user was first active,
    not a recorded logon. Service and machine accounts say nothing about people.
    """
    index = _index(columns)
    first: dict[tuple[str, str], tuple] = {}
    for row in rows:
        moment = parse_time(_cell(row, index, "Create Time"))
        user = _cell(row, index, "User Name")
        name = user.replace("\\", "/").rsplit("/", 1)[-1].upper()
        if not moment or not name or name.endswith("$") or name == "SYSTEM" \
                or "NT AUTHORITY" in user.upper():
            continue
        key = (_cell(row, index, "Session ID"), user)
        if key not in first or moment < first[key][0]:
            first[key] = (moment, _cell(row, index, "Process ID"), _cell(row, index, "Process"))
    return [Event(moment, "session", f"First process of {user} in session {session}: {process}",
                  pid, process, plugin)
            for (session, user), (moment, pid, process) in first.items()]


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
                events.append(Event(moment, kind, f"{label}: {column}", pid,
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
    # Its process times repeat pslist's, and it is read by the Memory Usage tab.
    "procmem.procmem": lambda plugin, columns, rows, ctx: [],
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
    # Every process's name before any event is built, so "started by" can
    # name the parent even when the parent's row comes later.
    for plugin, columns, rows in usable:
        if _suffix(plugin) in _FIRST:
            index = _index(columns)
            for row in rows:
                pid = _cell(row, index, "PID")
                name = _cell(row, index, "ImageFileName", "Name")
                if pid and name:
                    ctx.names.setdefault(pid, name)
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


# ── Key moments ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Moment:
    """One line of the timeline's summary: what happened, and why it matters."""
    time: datetime
    title: str
    detail: str
    tone: str = "neutral"            # neutral | alert
    pid: str = ""


def capture_time(payloads: list[dict]) -> datetime | None:
    """The system clock recorded in the image (windows.info's SystemTime)."""
    for payload in payloads or []:
        if not isinstance(payload, dict) or _suffix(str(payload.get("plugin") or "")) != "info.info":
            continue
        index = _index([str(c) for c in payload.get("columns") or []])
        for row in payload.get("rows") or []:
            if isinstance(row, (list, tuple)) and _cell(row, index, "Variable") == "SystemTime":
                return parse_time(_cell(row, index, "Value"))
    return None


_LATE_WINDOW = timedelta(minutes=10)
_COUNTED = {"process": "processes started", "process_exit": "processes exited",
            "thread": "threads started", "dll": "DLLs loaded", "network": "connections",
            "session": "user sessions", "execution": "program runs",
            "registry": "registry writes", "file": "file events",
            "driver": "driver events", "other": "other events"}


def key_moments(events: list[Event], findings=(), captured: datetime | None = None,
                limit: int = 14) -> list[Moment]:
    """
    The handful of events worth reading first, in time order.

    Boot and logon anchor the story; everything Insights flagged is pinned to
    when its process started; the busiest minute and the programs started just
    before the capture are where an intrusion in progress usually shows.
    """
    if not events:
        return []
    moments: list[Moment] = []
    starts = [e for e in events if e.kind == "process"]

    boot = next((e for e in starts if e.pid == "4" or e.process.lower() == "system"), None) \
        or next((e for e in starts if e.process.lower() == "smss.exe"), None)
    if boot:
        moments.append(Moment(boot.time, "Windows started",
                              f"{boot.process} was created; this is the boot time.",
                              pid=boot.pid))
    logon = next((e for e in starts if e.process.lower() in ("userinit.exe", "explorer.exe")),
                 None)
    if logon:
        moments.append(Moment(logon.time, "User logged on",
                              f"{logon.process} started (PID {logon.pid}), which happens "
                              "when someone signs in at the console.", pid=logon.pid))

    # The most severe finding per process, pinned to the process's start.
    severity = {"high": 0, "medium": 1, "low": 2, "info": 3}
    worst: dict[str, object] = {}
    for finding in findings or ():
        if finding.pid and finding.severity in ("high", "medium"):
            current = worst.get(finding.pid)
            if current is None or severity[finding.severity] < severity[current.severity]:
                worst[finding.pid] = finding
    first_start = {}
    for event in starts:
        first_start.setdefault(event.pid, event)
    for pid, finding in worst.items():
        event = first_start.get(pid)
        if event is None:
            continue
        moments.append(Moment(event.time, f"Flagged process started: {event.process}",
                              f"PID {pid}. Insights: {finding.title}.", "alert", pid))
    flagged_net = [e for e in events if e.kind == "network" and e.pid in worst]
    for event in flagged_net[:3]:
        moments.append(Moment(event.time, f"{event.process or 'PID ' + event.pid} "
                              "made a connection", event.summary, "alert", event.pid))

    # The busiest minute, when it stands well above the rest.
    per_minute = Counter(e.time.replace(second=0, microsecond=0) for e in events)
    if per_minute:
        minute, count = per_minute.most_common(1)[0]
        typical = sorted(per_minute.values())[len(per_minute) // 2]
        # Every boot is a burst; only one later on says something.
        after_boot = boot is None or minute - boot.time > timedelta(minutes=2)
        if count >= 5 and count >= 3 * typical and after_boot:
            kinds = Counter(e.kind for e in events
                            if e.time.replace(second=0, microsecond=0) == minute)
            parts = ", ".join(f"{n} {_COUNTED.get(k, k)}" for k, n in kinds.most_common(4))
            moments.append(Moment(minute, f"Busiest minute: {count} events", parts))

    end = captured or events[-1].time
    late = [e for e in starts if end - _LATE_WINDOW <= e.time <= end]
    if late:
        names = list(dict.fromkeys(e.process for e in late if e.process))
        shown = ", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "")
        moments.append(Moment(late[0].time,
                              f"{len(late)} program start{'' if len(late) == 1 else 's'} "
                              "in the last 10 minutes",
                              f"Started shortly before the capture: {shown}."))
    moments.append(Moment(
        end, "Memory captured",
        "System time recorded in the image when it was taken." if captured else
        "Latest timestamp in the analysed output; the capture was at or after this."))

    moments.sort(key=lambda m: (m.time, m.tone != "alert"))
    if len(moments) > limit:
        keep = [m for m in moments if m.tone == "alert"][:limit - 3]
        rest = [m for m in moments if m.tone != "alert"]
        moments = sorted(keep + rest[:limit - len(keep)], key=lambda m: m.time)
    return moments


def missing_inputs(available_plugins: set[str]) -> list[str]:
    """TIMELINE_PLUGINS that have no stored output yet."""
    have = {_suffix(p) for p in available_plugins}
    return [p for p in TIMELINE_PLUGINS if _suffix(p) not in have]
