"""Streaming, parsing and process-handling behaviour of the vol3 runner."""
import os
import signal
import subprocess
import sys

import pytest
from PyQt6.QtCore import QEventLoop, QTimer

from core import vol_runner
from core.vol_runner import RunSpec, VolatilityRunner, detect_os_from_banner


def _run(spec, timeout_ms=30000):
    """Run a spec to completion, collecting everything it emitted."""
    runner = VolatilityRunner(spec)
    captured = {"columns": [], "rows": [], "progress": [], "log": [], "failed": [],
                "exit": None}
    runner.columns_ready.connect(captured["columns"].extend)
    runner.rows_ready.connect(captured["rows"].extend)
    runner.progress.connect(lambda p, d: captured["progress"].append((p, d)))
    runner.log_line.connect(captured["log"].append)
    runner.failed.connect(captured["failed"].append)

    loop = QEventLoop()
    runner.run_finished.connect(lambda code: (captured.update(exit=code), loop.quit()))
    QTimer.singleShot(timeout_ms, loop.quit)
    runner.start()
    loop.exec()
    runner.wait(5000)
    return runner, captured


def test_columns_and_rows_stream(qapp, stub_vol):
    _, out = _run(RunSpec("/image.raw", "windows.pstree.PsTree", [], []))
    assert out["exit"] == 0
    assert out["columns"] == ["TreeDepth", "PID", "ImageFileName", "Path", "Note"]
    assert len(out["rows"]) == 4


def test_values_with_commas_spaces_and_newlines_survive(qapp, stub_vol):
    _, out = _run(RunSpec("/image.raw", "windows.pstree.PsTree", [], []))
    rows = out["rows"]
    assert rows[0][3] == ""                                    # empty cell kept in place
    assert rows[1][3] == r"C:\Program Files\Some App\thing.exe"
    assert rows[2][3] == "C:\\a,b\\c"
    assert rows[2][4] == "comma, inside"
    assert rows[3][3] == "line1\nline2"


def test_progress_is_parsed_from_stderr(qapp, stub_vol):
    _, out = _run(RunSpec("/image.raw", "windows.pstree.PsTree", [], []))
    assert any(abs(p - 12.5) < 0.01 for p, _ in out["progress"])
    assert any("PdbSignatureScanner" in d for _, d in out["progress"])


def test_plain_stderr_reaches_the_log(qapp, stub_vol):
    _, out = _run(RunSpec("/image.raw", "windows.pstree.PsTree", [], []))
    assert any("A real warning message" in line for line in out["log"])


def test_heavy_stderr_does_not_deadlock(qapp, stub_vol):
    """
    Regression: draining stdout to exhaustion before reading stderr hangs as
    soon as stderr fills its pipe buffer. The stub writes ~2 MB of it.
    """
    _, out = _run(RunSpec("/image.raw", "p", [], ["--stub-mode", "chatty"]),
                  timeout_ms=45000)
    assert out["exit"] == 0
    assert len(out["rows"]) == 2000


def test_naive_sequential_read_really_does_deadlock(stub_vol):
    """
    Pins the behaviour the runner exists to avoid, so the fix cannot silently
    regress: draining stdout fully and only then reading stderr hangs forever
    once stderr fills its pipe buffer.

    The naive reader gets its own process group and its output goes to
    /dev/null. Killing it alone is not enough — the stub it spawned would
    outlive it still holding the pipes, and waiting on those never returns.
    """
    naive = (
        "import subprocess, sys;"
        f"p=subprocess.Popen([sys.executable, {stub_vol!r}, '--stub-mode', 'chatty'],"
        "stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1);"
        "[None for _ in p.stdout];"
        "p.stderr.read()"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", naive],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            process.wait(timeout=10)
    finally:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=10)


def test_failure_carries_the_stderr_tail(qapp, stub_vol):
    _, out = _run(RunSpec("/image.raw", "windows.pslist.PsList", [],
                          ["--stub-mode", "fail"]))
    assert out["exit"] == 1
    assert out["failed"], "a non-zero exit must report a reason"
    message = out["failed"][0]
    assert "Unsatisfied requirement" in message
    assert "plugin browser" in message      # the actionable hint


def test_command_uses_the_csv_renderer(stub_vol):
    command = RunSpec("/image.raw", "windows.pslist.PsList", [], ["--pid", "4"]).command()
    assert "-r" in command and command[command.index("-r") + 1] == "csv"
    assert command[-3:] == ["windows.pslist.PsList", "--pid", "4"]


def test_banner_detection():
    assert detect_os_from_banner("Linux version 5.15.0-generic") == "linux"
    assert detect_os_from_banner("Microsoft Windows 10 ntoskrnl.exe") == "windows"
    assert detect_os_from_banner("Darwin Kernel Version 21.0") == "mac"
    assert detect_os_from_banner("nothing recognisable here") is None


# ── Locating volatility3 ──────────────────────────────────────────────────────

class TestFindingVolatility3:
    """
    How vol3 is invoked. On Windows the installed `vol.exe` in a uv venv is a
    trampoline that re-resolves its own path at startup; when that fails the
    process dies with "uv trampoline failed to canonicalize script path" before
    volatility3 is ever imported. Calling the library through the interpreter
    avoids the trampoline, and pins the run to the same volatility3 the GUI
    introspected for plugin arguments.
    """

    @pytest.fixture(autouse=True)
    def _clear_cache(self):
        vol_runner._COMMAND_CACHE = None
        yield
        vol_runner._COMMAND_CACHE = None

    def test_prefers_the_library_over_the_installed_script(self):
        command = vol_runner.find_vol3_command()
        assert command[0] == sys.executable
        assert command[1] == "-c"
        assert not any(part.endswith(("vol", "vol.exe")) for part in command)

    def test_the_entry_point_rewrites_argv0(self):
        # volatility3's parser reads argv[0]; left as "-c" it is taken for the
        # --config flag and every run dies on argument parsing.
        assert "sys.argv[0] = 'vol'" in vol_runner._CLI_ENTRY

    def test_the_entry_point_actually_starts_volatility3(self):
        proc = subprocess.run(
            vol_runner.find_vol3_command() + ["-h"],
            capture_output=True, text=True, timeout=180,
        )
        assert proc.returncode == 0, proc.stderr
        assert "usage: vol" in proc.stdout

    def test_the_answer_is_cached_but_not_shared(self):
        first = vol_runner.find_vol3_command()
        first.append("mutated")
        assert "mutated" not in vol_runner.find_vol3_command()

    def test_the_script_search_ignores_cmd_and_bat_on_windows(self, monkeypatch, tmp_path):
        # CreateProcess cannot run a .cmd without a shell, so finding one here
        # would report success and then fail to launch.
        monkeypatch.setattr(vol_runner.sys, "platform", "win32")
        monkeypatch.setattr(vol_runner.sys, "executable", str(tmp_path / "python.exe"))
        (tmp_path / "vol.cmd").write_text("@echo off")
        monkeypatch.setattr(vol_runner.shutil, "which", lambda _name: None)
        assert vol_runner._script_command() is None

    def test_falls_back_to_the_script_when_the_library_is_absent(self, monkeypatch, tmp_path):
        script = tmp_path / "vol"
        script.write_text("#!/bin/sh\n")
        script.chmod(0o755)
        monkeypatch.setattr(vol_runner, "_module_command", lambda: None)
        monkeypatch.setattr(vol_runner.sys, "executable", str(tmp_path / "python"))
        assert vol_runner.find_vol3_command() == [str(script)]
