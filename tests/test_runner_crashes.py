"""
How the runner behaves when volatility3 misbehaves: bad output, missing
executables, corrupted caches, and cancellation at awkward moments.

Every test here asserts that `run_finished` arrives. A runner that never emits
it leaves a tab spinning forever and a slot in the RunGate held, so "it did not
hang" is the property under test as much as the output is.
"""
import time

import pytest
from PyQt6.QtCore import QEventLoop, QTimer

from core import vol_runner
from core.vol_runner import (
    RunGate, RunSpec, VolatilityRunner, looks_like_cache_corruption,
)


def _run(spec, runner_cls=VolatilityRunner, timeout_ms=30000, before_start=None):
    runner = runner_cls(spec, gate=RunGate(1))
    out = {"columns": [], "rows": [], "log": [], "failed": [], "exit": None}
    runner.columns_ready.connect(out["columns"].extend)
    runner.rows_ready.connect(out["rows"].extend)
    runner.log_line.connect(out["log"].append)
    runner.failed.connect(out["failed"].append)
    loop = QEventLoop()
    runner.run_finished.connect(lambda code: (out.update(exit=code), loop.quit()))
    QTimer.singleShot(timeout_ms, loop.quit)
    if before_start:
        before_start(runner)
    runner.start()
    loop.exec()
    assert runner.wait(10000), "the runner thread did not finish"
    assert out["exit"] is not None, "run_finished was never emitted (hang)"
    return runner, out


def _spec(mode, *extra):
    return RunSpec("/image.raw", "p", [], ["--stub-mode", mode, *extra])


# ── Output shapes ─────────────────────────────────────────────────────────────

def test_invalid_utf8_is_replaced_not_fatal(qapp, stub_vol):
    _, out = _run(_spec("garbage"))
    assert out["exit"] == 0
    assert out["columns"] == ["PID", "Name"]
    assert len(out["rows"]) == 2
    assert "�" in out["rows"][0][1]
    assert out["rows"][1] == ["5", "ok"]


def test_no_output_at_all_is_a_clean_empty_result(qapp, stub_vol):
    _, out = _run(_spec("empty"))
    assert out["exit"] == 0
    assert out["columns"] == [] and out["rows"] == [] and out["failed"] == []


def test_header_without_rows(qapp, stub_vol):
    _, out = _run(_spec("header_only"))
    assert out["exit"] == 0
    assert out["columns"] == ["PID", "Name"]
    assert out["rows"] == []


def test_ragged_rows_are_squared_to_the_header(qapp, stub_vol):
    _, out = _run(_spec("ragged"))
    assert out["columns"] == ["A", "B", "C"]
    assert all(len(row) == 3 for row in out["rows"])
    assert out["rows"][0] == ["1", "", ""]
    assert out["rows"][1] == ["1", "2", "3,4,5"]
    assert out["rows"][2] == ["x", "y", "z"]


# ── Launch failures ───────────────────────────────────────────────────────────

def test_missing_executable_reports_and_finishes(qapp, monkeypatch):
    monkeypatch.setattr(vol_runner, "find_vol3_command",
                        lambda: ["/definitely/not/here/vol"])
    runner, out = _run(RunSpec("/image.raw", "p", [], []))
    assert out["exit"] == 1
    assert out["failed"] and "Could not launch volatility3" in out["failed"][0]
    assert runner.gate.active == 0


def test_unexpected_exception_is_reported_with_traceback(qapp, monkeypatch):
    def explode(self):
        raise ValueError("unexpected shape")
    monkeypatch.setattr(VolatilityRunner, "_execute", explode)
    _, out = _run(RunSpec("/image.raw", "p", [], []))
    assert out["exit"] == 1
    assert "ValueError: unexpected shape" in out["failed"][0]
    assert "Traceback" in out["failed"][0]


def test_failure_is_reported_exactly_once(qapp, stub_vol):
    _, out = _run(_spec("fail"))
    assert out["exit"] == 1
    assert len(out["failed"]) == 1


# ── Corrupted symbol cache ────────────────────────────────────────────────────

@pytest.mark.parametrize("text", [
    "sqlite3.DatabaseError: database disk image is malformed",
    "sqlite3.DatabaseError: file is not a database",
    "json.decoder.JSONDecodeError: Expecting value: line 1 column 1",
    "_lzma.LZMAError: Input format not supported by decoder",
    "EOFError: Compressed file ended before the end-of-stream marker was reached",
])
def test_cache_corruption_signatures_are_recognised(text):
    assert looks_like_cache_corruption(text)


@pytest.mark.parametrize("text", [
    "", "Unsatisfied requirement plugins.PsList.kernel",
    "Symbol table not found", "A real warning message",
])
def test_ordinary_failures_are_not_mistaken_for_corruption(text):
    assert not looks_like_cache_corruption(text)


def test_corrupted_cache_is_cleared_and_the_run_retried(qapp, stub_vol):
    runner, out = _run(_spec("corrupt"))
    assert out["exit"] == 0, out["failed"]
    assert runner.retried_after_cache_clear
    assert out["rows"] == [["4", "System"]]
    assert out["failed"] == [], "a successful retry must not leave an error behind"
    assert any("corrupted" in line for line in out["log"])
    assert "--clear-cache" in runner.spec.command()


def test_cache_still_broken_after_retry_fails_once_with_a_hint(qapp, stub_vol):
    runner, out = _run(_spec("corrupt_always"))
    assert out["exit"] == 1
    assert runner.retried_after_cache_clear
    assert len(out["failed"]) == 1
    assert "clearing it did not help" in out["failed"][0]


def test_no_retry_for_an_ordinary_failure(qapp, stub_vol):
    runner, out = _run(_spec("fail"))
    assert not runner.retried_after_cache_clear


def test_clear_cache_flag_only_when_asked():
    plain = RunSpec("/i.raw", "p", [], [])
    assert "--clear-cache" not in plain.command()
    plain.clear_cache = True
    command = plain.command()
    # A global option: it must precede the plugin name to be parsed by vol3.
    assert command.index("--clear-cache") < command.index("p")


# ── Cancellation ──────────────────────────────────────────────────────────────

def test_cancel_before_start_never_launches(qapp, stub_vol):
    runner, out = _run(_spec("slow"), before_start=lambda r: r.cancel())
    assert out["exit"] == 1
    assert out["columns"] == []
    assert runner.cancelled


def test_cancel_mid_flood_does_not_deadlock(qapp, stub_vol):
    """
    Regression: when reading stopped on a cancel that had not managed to
    terminate the process (it raced the launch), vol3 blocked writing to a
    full stdout pipe and wait() never returned.
    """
    class RacingRunner(VolatilityRunner):
        def _consume_rows(self, stdout):
            # The flag is set but terminate() is never called, exactly as
            # when cancel() runs before _proc is assigned.
            self._cancelled = True
            super()._consume_rows(stdout)

    started = time.monotonic()
    runner, out = _run(_spec("flood"), runner_cls=RacingRunner, timeout_ms=20000)
    assert time.monotonic() - started < 15
    assert any("Cancelled" in line for line in out["log"])


def test_cancel_on_a_finished_runner_is_harmless(qapp, stub_vol):
    runner, out = _run(_spec("header_only"))
    runner.cancel()
    runner.cancel()
    assert out["exit"] == 0


# ── Messages ──────────────────────────────────────────────────────────────────

def test_failure_message_without_stderr_is_still_useful():
    runner = VolatilityRunner(RunSpec("/i.raw", "windows.x.Y", [], []))
    message = runner._failure_message(3)
    assert message == "windows.x.Y exited with code 3."


def test_stderr_tail_is_bounded():
    runner = VolatilityRunner(RunSpec("/i.raw", "p", [], []))
    for i in range(500):
        runner._handle_stderr_line(f"line {i}")
    assert len(runner._stderr_tail) == 40
    assert runner._stderr_tail[-1] == "line 499"


@pytest.mark.parametrize("line", [
    "Progress:", "Progress: abc\tstage", "Progress:\t\t", "Progress: 1e999\tbig",
])
def test_malformed_progress_lines_never_raise(line):
    runner = VolatilityRunner(RunSpec("/i.raw", "p", [], []))
    runner._handle_stderr_line(line)
