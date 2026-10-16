"""
The RunGate: volatility3 processes run one at a time unless the examiner
raises the limit, and a queued run can always be cancelled.
"""
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
    for line in open(trace_path):
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
    (sym / "windows" / "ntkrnlmp.pdb" / "ABC.json.xz").write_bytes(b"")
    assert not solo()
    assert gate.acquire(solo=solo)
