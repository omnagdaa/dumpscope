"""
The RunGate: volatility3 processes run one at a time unless the examiner
raises the limit, and a queued run can always be cancelled.
"""
import glob
import lzma
import os
import threading
import time

from PyQt6.QtCore import QEventLoop, QTimer

from core.vol_runner import RUN_GATE, RunGate, RunSpec, VolatilityRunner


# ── The gate on its own ───────────────────────────────────────────────────────

def test_limit_is_never_below_one():
    assert RunGate(0).limit == 1
    assert RunGate(-5).limit == 1
    gate = RunGate(3)
    gate.set_limit(0)
    assert gate.limit == 1


def test_acquire_and_release_track_active_count():
    gate = RunGate(2)
    assert gate.acquire()
    assert gate.acquire()
    assert gate.active == 2
    gate.release()
    gate.release()
    assert gate.active == 0


def test_extra_release_does_not_go_negative():
    """A double release (error path plus finally) must not open a phantom slot."""
    gate = RunGate(1)
    gate.release()
    gate.release()
    assert gate.active == 0
    assert gate.acquire()
    assert gate.active == 1


def test_second_caller_waits_for_the_first():
    gate = RunGate(1)
    assert gate.acquire()
    got_it = threading.Event()

    def waiter():
        gate.acquire()
        got_it.set()

    thread = threading.Thread(target=waiter, daemon=True)
    thread.start()
    assert not got_it.wait(0.3), "the second caller should be blocked"
    assert gate.waiting == 1
    gate.release()
    assert got_it.wait(2.0), "releasing should hand the slot over"
    thread.join(1)


def test_cancelled_waiter_gives_up_without_a_slot():
    gate = RunGate(1)
    gate.acquire()
    cancel = threading.Event()
    result = {}

    thread = threading.Thread(
        target=lambda: result.update(ok=gate.acquire(cancelled=cancel.is_set, poll=0.02)),
        daemon=True,
    )
    thread.start()
    time.sleep(0.1)
    cancel.set()
    thread.join(2.0)
    assert result["ok"] is False
    assert gate.active == 1, "a cancelled waiter must not take a slot"
    assert gate.waiting == 0


def test_already_cancelled_caller_never_acquires_even_when_free():
    gate = RunGate(1)
    assert gate.acquire(cancelled=lambda: True) is False
    assert gate.active == 0


def test_raising_the_limit_wakes_waiters():
    gate = RunGate(1)
    gate.acquire()
    got_it = threading.Event()
    thread = threading.Thread(target=lambda: (gate.acquire(poll=5), got_it.set()),
                              daemon=True)
    thread.start()
    time.sleep(0.1)
    gate.set_limit(2)
    assert got_it.wait(1.0), "set_limit should notify, not wait out the poll"
    thread.join(1)


def test_many_threads_never_exceed_the_limit():
    gate = RunGate(3)
    peak = {"now": 0, "max": 0}
    lock = threading.Lock()

    def worker():
        for _ in range(20):
            gate.acquire()
            with lock:
                peak["now"] += 1
                peak["max"] = max(peak["max"], peak["now"])
            time.sleep(0.001)
            with lock:
                peak["now"] -= 1
            gate.release()

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert peak["max"] <= 3
    assert gate.active == 0


# ── The gate as the runner uses it ────────────────────────────────────────────

def _start(spec, gate, sink):
    runner = VolatilityRunner(spec, gate=gate)
    runner.queued.connect(lambda n: sink.setdefault("queued", []).append(n))
    runner.run_finished.connect(lambda code: sink.setdefault("exit", []).append(code))
    runner.start()
    return runner


def _wait_for(predicate, timeout_ms=20000):
    loop = QEventLoop()
    timer = QTimer()
    timer.timeout.connect(lambda: predicate() and loop.quit())
    timer.start(20)
    QTimer.singleShot(timeout_ms, loop.quit)
    loop.exec()
    timer.stop()


def _intervals(trace_path):
    starts, ends = {}, {}
    lines = [line for path in glob.glob(f"{trace_path}.*") for line in open(path)]
    for line in lines:
        kind, pid, stamp = line.split()
        (starts if kind == "start" else ends)[pid] = float(stamp)
    return sorted((starts[p], ends[p]) for p in starts)


def test_runs_are_serialised_by_default(qapp, stub_vol, tmp_path):
    """The proposal's subprocess lock: two plugins never overlap at limit 1."""
    trace = tmp_path / "trace.txt"
    gate = RunGate(1)
    sink_a, sink_b = {}, {}
    args = ["--stub-mode", "slow", "--stub-trace", str(trace), "--stub-delay", "0.15"]
    a = _start(RunSpec("/i.raw", "p", [], args), gate, sink_a)
    b = _start(RunSpec("/i.raw", "p", [], args), gate, sink_b)
    _wait_for(lambda: "exit" in sink_a and "exit" in sink_b)
    a.wait(5000), b.wait(5000)

    assert sink_a["exit"] == [0] and sink_b["exit"] == [0]
    (s1, e1), (s2, e2) = _intervals(trace)
    assert s2 >= e1, "the second run started before the first finished"
    assert "queued" in sink_a or "queued" in sink_b, "the waiting run should say it is queued"
    assert gate.active == 0


def test_runs_overlap_when_the_limit_allows(qapp, stub_vol, tmp_path):
    trace = tmp_path / "trace.txt"
    gate = RunGate(2)
    sink_a, sink_b = {}, {}
    args = ["--stub-mode", "slow", "--stub-trace", str(trace), "--stub-delay", "0.3"]
    a = _start(RunSpec("/i.raw", "p", [], args), gate, sink_a)
    b = _start(RunSpec("/i.raw", "p", [], args), gate, sink_b)
    _wait_for(lambda: "exit" in sink_a and "exit" in sink_b)
    a.wait(5000), b.wait(5000)

    (s1, e1), (s2, e2) = _intervals(trace)
    assert s2 < e1, "with two slots the runs should overlap"


def test_cancelling_a_queued_run_never_launches_it(qapp, stub_vol, tmp_path):
    trace = tmp_path / "trace.txt"
    gate = RunGate(1)
    sink_a, sink_b = {}, {}
    args = ["--stub-mode", "slow", "--stub-trace", str(trace), "--stub-delay", "0.3"]
    a = _start(RunSpec("/i.raw", "p", [], args), gate, sink_a)
    _wait_for(lambda: gate.active == 1, 5000)
    b = _start(RunSpec("/i.raw", "p", [], args), gate, sink_b)
    _wait_for(lambda: "queued" in sink_b, 5000)
    b.cancel()
    _wait_for(lambda: "exit" in sink_a and "exit" in sink_b)
    a.wait(5000), b.wait(5000)

    assert len(_intervals(trace)) == 1, "the cancelled run must not have started vol3"
    assert sink_b["exit"] == [1]
    assert gate.active == 0


def test_a_crashing_run_still_releases_its_slot(qapp, monkeypatch):
    """An exception inside the run must not leave the gate held forever."""
    gate = RunGate(1)
    monkeypatch.setattr(VolatilityRunner, "_execute",
                        lambda self: (_ for _ in ()).throw(RuntimeError("boom")))
    sink = {}
    runner = _start(RunSpec("/i.raw", "p", [], []), gate, sink)
    _wait_for(lambda: "exit" in sink, 5000)
    runner.wait(5000)
    assert sink["exit"] == [1]
    assert gate.active == 0


def test_shared_gate_defaults_to_one():
    assert RUN_GATE.limit == 1


def test_solo_caps_limit_until_case_has_symbols(tmp_path):
    # A fresh case: parallel runs must not race the first PDB download.
    from core.vol_runner import awaiting_case_symbols
    sym = tmp_path / "symbols"
    (sym / "windows" / "ntkrnlmp.pdb").mkdir(parents=True)
    solo = lambda: awaiting_case_symbols([str(sym)])
    gate = RunGate(4)
    assert solo() and not awaiting_case_symbols([])
    assert gate.acquire(solo=solo)
    assert not gate.acquire(cancelled=lambda: True, solo=solo)
    isf = sym / "windows" / "ntkrnlmp.pdb" / "ABC.json.xz"
    # vol3 creates its output file before downloading the PDB, then streams
    # into it for minutes. Neither state means the case has symbols yet.
    isf.write_bytes(b"")
    assert solo(), "an empty placeholder must keep runs serial"
    full = lzma.compress(b'{"symbols": {}}')
    isf.write_bytes(full[: len(full) // 2])
    assert solo(), "a half-written xz stream must keep runs serial"
    isf.write_bytes(full)
    assert not solo()
    assert gate.acquire(solo=solo)


# ── Symbol files left behind by a killed run ─────────────────────────────────

def _isf_dir(tmp_path):
    folder = tmp_path / "symbols" / "windows" / "ntkrnlmp.pdb"
    folder.mkdir(parents=True)
    return folder


def test_unfinished_isfs_are_discarded_and_finished_ones_kept(tmp_path):
    from core.vol_runner import discard_partial_isfs
    folder = _isf_dir(tmp_path)
    full = lzma.compress(b'{"symbols": {}}')
    (folder / "A-1.json.xz").write_bytes(full)
    (folder / "B-1.json.xz").write_bytes(b"")                 # killed before writing
    (folder / "C-1.json.xz").write_bytes(full[: len(full) // 2])   # killed mid-write
    removed = discard_partial_isfs([str(tmp_path / "symbols")])
    assert sorted(os.path.basename(p) for p in removed) == ["B-1.json.xz", "C-1.json.xz"]
    assert sorted(os.listdir(folder)) == ["A-1.json.xz"]


def test_a_run_on_a_case_without_symbols_clears_a_killed_runs_isf(qapp, stub_vol, tmp_path):
    """The probe used to be killed mid-conversion and leave an empty ISF behind."""
    folder = _isf_dir(tmp_path)
    (folder / "X-1.json.xz").write_bytes(b"")
    spec = RunSpec("/image.raw", "p", [str(tmp_path / "symbols")], ["--stub-mode", "rows"])
    runner = VolatilityRunner(spec, gate=RunGate(1))
    lines = []
    runner.log_line.connect(lines.append)
    loop = QEventLoop()
    runner.run_finished.connect(lambda _code: loop.quit())
    QTimer.singleShot(20000, loop.quit)
    runner.start()
    loop.exec()
    assert runner.wait(10000)
    assert not (folder / "X-1.json.xz").exists()
    assert any("unfinished symbol file" in line for line in lines)


def test_the_probe_allows_time_to_fetch_symbols_on_a_new_case(tmp_path, monkeypatch):
    from core import os_detect
    probe = os_detect.ImageProbe("/image.raw", [str(tmp_path / "symbols")])
    seen = []

    def guarded(_command, timeout):
        seen.append(timeout)
        return 1, "", ""

    monkeypatch.setattr(probe, "_guarded", guarded)
    probe._probe_windows("/image.raw")
    folder = _isf_dir(tmp_path)
    (folder / "A-1.json.xz").write_bytes(lzma.compress(b"{}"))
    probe._probe_windows("/image.raw")
    assert seen == [probe.INFO_TIMEOUT_FETCHING, probe.INFO_TIMEOUT]
    assert probe.INFO_TIMEOUT_FETCHING >= 600
