"""The incident timeline: timestamp parsing, event extraction, aggregation."""
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest

from core.timeline import (
    KINDS, TIMELINE_PLUGINS, Event, build_events, filter_events, format_time,
    histogram, missing_inputs, parse_time, summarise, time_range,
)
from tests.vol_fixtures import all_payloads, payload

UTC = timezone.utc


# ── Timestamps ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("text, expected", [
    ("2024-03-14 09:41:32.000000 UTC", datetime(2024, 3, 14, 9, 41, 32, tzinfo=UTC)),
    ("2024-03-14 09:41:32.123456 UTC",
     datetime(2024, 3, 14, 9, 41, 32, 123456, tzinfo=UTC)),
    ("2024-03-14 09:41:32", datetime(2024, 3, 14, 9, 41, 32, tzinfo=UTC)),
    ("2024-03-14 09:41:32.000000 ", datetime(2024, 3, 14, 9, 41, 32, tzinfo=UTC)),
    ("2024-03-14T09:41:32Z", datetime(2024, 3, 14, 9, 41, 32, tzinfo=UTC)),
    ("2024-03-14T11:41:32+02:00", datetime(2024, 3, 14, 9, 41, 32, tzinfo=UTC)),
    ("2024-03-14T04:41:32-0500", datetime(2024, 3, 14, 9, 41, 32, tzinfo=UTC)),
    ("2024-03-14 09:41:32.1 utc", datetime(2024, 3, 14, 9, 41, 32, 100000, tzinfo=UTC)),
    ("2024-03-14 09:41:32.123456789 UTC",          # nanoseconds truncated
     datetime(2024, 3, 14, 9, 41, 32, 123456, tzinfo=UTC)),
])
def test_parse_time_formats(text, expected):
    assert parse_time(text) == expected


@pytest.mark.parametrize("text", [
    None, "", "N/A", "-", "garbage", "2024-13-01 00:00:00", "2024-02-30 00:00:00",
    "2024-03-14 25:00:00",
    "1601-01-01 00:00:00.000000 UTC",      # FILETIME zero
    "1970-01-01 00:00:00.000000 UTC",      # epoch zero
    "2150-01-01 00:00:00 UTC",             # corrupted far future
    "2024-03-14",                          # date only
    12345,
])
def test_parse_time_rejects_non_events(text):
    assert parse_time(text) is None


def test_parse_time_accepts_datetimes_naive_and_aware():
    naive = datetime(2024, 1, 1, 12, 0)
    assert parse_time(naive) == naive.replace(tzinfo=UTC)
    aware = datetime(2024, 1, 1, 14, 0, tzinfo=timezone(timedelta(hours=2)))
    assert parse_time(aware) == datetime(2024, 1, 1, 12, 0, tzinfo=UTC)


def test_format_time():
    assert format_time(None) == ""
    assert format_time(datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)) == "2024-01-02 03:04:05 UTC"


# ── Extraction ────────────────────────────────────────────────────────────────

def test_fixture_scenario_builds_the_expected_story():
    events = build_events(all_payloads())
    kinds = Counter(e.kind for e in events)
    assert kinds["process"] == 13               # 12 in pslist + 1 hidden from psscan
    assert kinds["process_exit"] == 1
    assert kinds["dll"] == 6
    assert kinds["network"] == 3                # the UDP row has no Created time
    assert kinds["session"] == 1
    assert kinds["execution"] == 1
    assert [e.time for e in events] == sorted(e.time for e in events)


def test_the_attack_chain_is_in_order():
    events = build_events(all_payloads())
    story = [(e.kind, e.process) for e in events if e.time >= parse_time("2024-03-14 09:41:00")]
    order = [story.index(item) for item in (
        ("execution", ""), ("process", "WINWORD.EXE"), ("process", "powershell.exe"),
        ("network", "powershell.exe"), ("process", "scvhost.exe"),
        ("network", "scvhost.exe"), ("process", "lsass.exe"))]
    assert order == sorted(order)


def test_processes_seen_by_several_plugins_appear_once_credited_to_pslist():
    events = build_events([payload("windows.psscan.PsScan"),
                           payload("windows.pslist.PsList")])
    creations = [e for e in events if e.kind == "process"]
    assert len(creations) == len({e.pid for e in creations}) == 13
    assert all(e.plugin == "windows.pslist.PsList" for e in creations if e.pid != "3100")


def test_network_events_name_their_process_and_state():
    events = [e for e in build_events(all_payloads()) if e.kind == "network"]
    listening = next(e for e in events if e.pid == "620")
    assert "listening on 0.0.0.0:135" in listening.summary
    outbound = next(e for e in events if e.pid == "2600")
    assert "→ 185.220.101.4:4444" in outbound.summary
    assert "ESTABLISHED" in outbound.summary


def test_dll_events_take_the_process_name_from_pslist_when_missing():
    rows = [["0", "2520", "", "0x1", "0x1", "evil.dll", r"C:\x\evil.dll", "1",
             "2024-03-14 09:41:33.000000 UTC", ""]]
    from tests.vol_fixtures import DLLLIST_COLUMNS
    events = build_events([payload("windows.pslist.PsList"),
                           {"plugin": "windows.dlllist.DllList",
                            "columns": DLLLIST_COLUMNS, "rows": rows}])
    dll = next(e for e in events if e.kind == "dll")
    assert dll.process == "powershell.exe"
    assert dll.detail == r"C:\x\evil.dll"


def test_command_lines_annotate_process_events():
    events = build_events([payload("windows.pslist.PsList"), payload("windows.cmdline.CmdLine")])
    ps = next(e for e in events if e.kind == "process" and e.pid == "2520")
    assert "-enc" in ps.detail


def test_plugin_ids_are_matched_by_module_not_full_path():
    """vol3 moves plugins between packages (malfind moved under malware/)."""
    moved = dict(payload("windows.dlllist.DllList"), plugin="windows.legacy.dlllist.DllList")
    assert any(e.kind == "dll" for e in build_events([moved]))


@pytest.mark.parametrize("plugin, columns, row, kind", [
    ("windows.thrdscan.ThrdScan",
     ["Offset", "PID", "TID", "StartAddress", "StartPath", "Win32StartAddress",
      "Win32StartPath", "CreateTime", "ExitTime"],
     ["0x1", "4", "8", "0x0", "", "0x0", r"\ntoskrnl.exe", "2024-01-01 10:00:00 UTC", "N/A"],
     "thread"),
    ("windows.shimcachemem.ShimcacheMem",
     ["Order", "Last Modified", "Last Update", "Exec Flag", "File Size", "File Path"],
     ["1", "2024-01-01 10:00:00 UTC", "N/A", "True", "0x0", r"C:\tools\x.exe"],
     "execution"),
    ("windows.mftscan.MFTScan",
     ["Offset", "Record Type", "Record Number", "Link Count", "MFT Type", "Permissions",
      "Attribute Type", "Created", "Modified", "Updated", "Accessed", "Filename"],
     ["0x1", "FILE", "5", "1", "File", "", "FILE_NAME", "2024-01-01 10:00:00 UTC",
      "N/A", "N/A", "N/A", "a.txt"],
     "file"),
    ("windows.unloadedmodules.UnloadedModules",
     ["Name", "StartAddress", "EndAddress", "Time"],
     ["drv.sys", "0x1", "0x2", "2024-01-01 10:00:00 UTC"], "driver"),
    ("timeliner.Timeliner",
     ["Plugin", "Description", "Created Date", "Modified Date", "Accessed Date",
      "Changed Date"],
     ["NetScan", "TCP 1.2.3.4", "2024-01-01 10:00:00 UTC", "N/A", "N/A", "N/A"],
     "network"),
    ("windows.registry.hivelist.HiveList",
     ["Offset", "FileFullPath", "Last Write Time"],
     ["0x1", r"\SystemRoot\System32\Config\SAM", "2024-01-01 10:00:00 UTC"], "registry"),
    ("windows.something.New",
     ["PID", "Name", "When Created"], ["4", "thing", "2024-01-01 10:00:00 UTC"], "other"),
])
def test_each_extractor(plugin, columns, row, kind):
    events = build_events([{"plugin": plugin, "columns": columns, "rows": [row]}])
    assert [e.kind for e in events] == [kind]


def test_plugins_without_times_contribute_nothing():
    assert build_events([payload("windows.cmdline.CmdLine"),
                         payload("windows.malware.malfind.Malfind")]) == []


@pytest.mark.parametrize("payloads", [
    None, [], [None], ["string"], [{"plugin": None}],
    [{"plugin": "windows.pslist.PsList", "columns": "not a list", "rows": []}],
    [{"plugin": "windows.pslist.PsList", "columns": ["PID"], "rows": "nope"}],
    [{"plugin": "windows.pslist.PsList", "columns": ["PID", "CreateTime"],
      "rows": [None, 5, "x", [], ["4"], ["4", None]]}],
    [{"plugin": "windows.pslist.PsList", "columns": [], "rows": [["1", "2"]]}],
])
def test_malformed_payloads_never_raise(payloads):
    assert build_events(payloads) == []


def test_one_bad_payload_does_not_hide_the_others(monkeypatch):
    import core.timeline as timeline
    def explode(*a):
        raise RuntimeError("boom")
    monkeypatch.setitem(timeline._EXTRACTORS, "netscan.netscan", explode)
    events = build_events(all_payloads())
    assert events and not any(e.kind == "network" for e in events)


def test_large_input_is_fast():
    from tests.vol_fixtures import DLLLIST_COLUMNS
    base = datetime(2024, 1, 1, tzinfo=UTC)
    rows = [["0", str(i % 500), "p.exe", "0x1", "0x1", f"m{i}.dll", f"C:\\m{i}.dll", "1",
             (base + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S.%f UTC"), ""]
            for i in range(100_000)]
    started = time.monotonic()
    events = build_events([{"plugin": "windows.dlllist.DllList",
                            "columns": DLLLIST_COLUMNS, "rows": rows}])
    assert len(events) == 100_000
    assert time.monotonic() - started < 15


# ── Aggregation ───────────────────────────────────────────────────────────────

def _ev(seconds, kind="process"):
    return Event(datetime(2024, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds), kind, "x")


def test_histogram_counts_every_event_once():
    events = [_ev(s, k) for s, k in ((0, "process"), (5, "dll"), (10, "dll"), (99, "network"))]
    bins = histogram(events, events[0].time, events[-1].time, 10)
    assert len(bins) == 10
    assert sum(sum(b.values()) for b in bins) == 4
    assert bins[0]["process"] == 1 and bins[-1]["network"] == 1


def test_histogram_zero_width_range_and_bad_bucket_counts():
    events = [_ev(0), _ev(0, "dll")]
    for buckets in (0, -3, 1, 7):
        bins = histogram(events, events[0].time, events[0].time, buckets)
        assert sum(sum(b.values()) for b in bins) == 2


def test_histogram_ignores_events_outside_the_range():
    events = [_ev(0), _ev(50), _ev(100)]
    bins = histogram(events, events[1].time, events[1].time + timedelta(seconds=10), 4)
    assert sum(sum(b.values()) for b in bins) == 1


def test_filter_events():
    events = build_events(all_payloads())
    assert filter_events(events) == events
    assert all(e.kind == "dll" for e in filter_events(events, kinds={"dll"}))
    assert filter_events(events, kinds=set()) == []
    hits = filter_events(events, text="185.220")
    assert hits and all(e.kind == "network" for e in hits)
    assert filter_events(events, text="  POWERSHELL ")
    start = parse_time("2024-03-14 09:41:00")
    assert all(e.time >= start for e in filter_events(events, start=start))


def test_summary_and_range():
    assert time_range([]) is None
    assert summarise([]) == {"events": 0, "first": "", "last": "", "by_kind": {}}
    summary = summarise(build_events(all_payloads()))
    assert summary["first"] == "2024-03-14 08:00:01 UTC"
    assert summary["last"] == "2024-03-14 09:43:00 UTC"


def test_missing_inputs():
    assert missing_inputs(set()) == list(TIMELINE_PLUGINS)
    assert "windows.pslist.PsList" not in missing_inputs({"windows.pslist.PsList"})
    assert missing_inputs(set(TIMELINE_PLUGINS)) == []


def test_every_kind_has_a_label_and_colour():
    for key, label, color in KINDS:
        assert label and color.startswith("#") and len(color) == 7
