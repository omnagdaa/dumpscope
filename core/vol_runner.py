"""
Volatility3 execution for DumpScope.

Runs vol3 as a subprocess with the CSV renderer, which streams one row at a
time and quotes properly — unlike the default text renderer, whose columns can
only be recovered by guessing at runs of whitespace and which corrupts any
value containing spaces (file paths, command lines, service descriptions).

Three things here are deliberate:

* stdout is parsed by ``csv.reader`` over the pipe itself, so a field
  containing an embedded newline (disassembly, multi-line data) is reassembled
  correctly rather than being torn into bogus rows.

* stderr is drained by a dedicated thread. vol3 writes progress there, and a
  single-threaded "read all stdout, then read stderr" sequence deadlocks the
  moment stderr fills its pipe buffer while the parent is still blocked on
  stdout.

* the completion signal is named ``run_finished``. ``QThread`` already defines
  ``finished``; redefining it on the subclass shadows Qt's own signal.
"""

from __future__ import annotations

import csv
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass

from PyQt6.QtCore import QThread, pyqtSignal

log = logging.getLogger("dumpscope.vol_runner")

# Rows are handed to the UI in batches; a signal per row swamps the event loop
# on plugins that emit tens of thousands of them (filescan, handles).
_BATCH_ROWS = 250
_BATCH_SECONDS = 0.10

BANNER_HINTS = {
    "windows": ("windows", "microsoft", "ntoskrnl", "win32k", "ntkrnl"),
    "linux":   ("linux", "ubuntu", "debian", "centos", "fedora", "arch",
                "gnu/linux", "vmlinuz"),
    "mac":     ("darwin", "mac os x", "macos", "xnu"),
}


def detect_os_from_banner(text: str) -> str | None:
    """Guess the image OS from banner text. None when nothing matches."""
    lowered = text.lower()
    for os_name, hints in BANNER_HINTS.items():
        if any(hint in lowered for hint in hints):
            return os_name
    return None


def find_vol3_command() -> list[str]:
    """
    Locate the volatility3 CLI. Prefers an executable next to the running
    interpreter (the project venv) before falling back to PATH, so a system-wide
    vol3 of a different version cannot shadow the one this app was built
    against. Falls back to invoking the library through the interpreter itself,
    which always works when volatility3 is importable but no script was
    installed.
    """
    interpreter_dir = os.path.dirname(sys.executable)
    search_dirs = [
        interpreter_dir,
        os.path.normpath(os.path.join(interpreter_dir, "..", "Scripts")),
        os.path.join(interpreter_dir, "Scripts"),
    ]
    suffixes = (".exe", ".cmd", ".bat", "") if sys.platform == "win32" else ("",)

    for name in ("vol", "vol3", "volatility3", "volatility"):
        for directory in search_dirs:
            for suffix in suffixes:
                candidate = os.path.join(directory, name + suffix)
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    log.debug("Using vol3 at %s", candidate)
                    return [candidate]
        found = shutil.which(name)
        if found:
            log.debug("Using vol3 from PATH: %s", found)
            return [found]

    log.warning("No vol3 executable found — invoking the library directly")
    return [sys.executable, "-m", "volatility3.cli"]


def build_environment(symbol_dirs: list[str] | None = None) -> dict[str, str]:
    """Process environment for a vol3 run, with case symbol dirs taking priority."""
    env = os.environ.copy()
    existing = [p for p in env.get("VOLATILITY_SYMBOL_DIRS", "").split(os.pathsep) if p]
    for directory in reversed(symbol_dirs or []):
        if directory and directory not in existing:
            existing.insert(0, directory)
    if existing:
        env["VOLATILITY_SYMBOL_DIRS"] = os.pathsep.join(existing)
    # vol3 block-buffers stdout when it is a pipe; without this, rows arrive in
    # 8 KB clumps and the table looks frozen on slow plugins.
    env["PYTHONUNBUFFERED"] = "1"
    if sys.platform == "win32":
        env.setdefault("PATHEXT", ".exe;.cmd;.bat;.com")
    return env


def _creation_flags() -> int:
    return subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


@dataclass
class RunSpec:
    """Everything needed to launch one plugin against one image."""
    image_path: str
    plugin_id: str
    symbol_dirs: list[str]
    extra_args: list[str]
    # Where --dump writes what it extracts. vol3 defaults to the process's
    # working directory, which for a GUI is wherever it happened to be started
    # from — so extractions would land outside the case with nothing recording
    # where they went.
    output_dir: str = ""
    # vol3's own worker pool for a single plugin. "off" is its default.
    parallelism: str = ""

    def command(self) -> list[str]:
        command = find_vol3_command() + ["-r", "csv"]
        if self.output_dir:
            command += ["-o", os.path.abspath(self.output_dir)]
        if self.parallelism:
            command += ["--parallelism", self.parallelism]
        return (
            command
            + ["-f", os.path.abspath(self.image_path)]
            + [self.plugin_id]
            + list(self.extra_args)
        )


class VolatilityRunner(QThread):
    """
    Runs one plugin and streams its results.

    Signals
    -------
    columns_ready(list)   header row, emitted once before any data
    rows_ready(list)      a batch of rows, each a list[str] aligned to columns
    progress(float, str)  percentage 0-100 and the current stage description
    log_line(str)         human-readable notices (command line, warnings)
    failed(str)           the run could not produce results; carries the reason
    run_finished(int)     process exit code; always emitted exactly once
    """

    columns_ready = pyqtSignal(list)
    rows_ready    = pyqtSignal(list)
    progress      = pyqtSignal(float, str)
    log_line      = pyqtSignal(str)
    failed        = pyqtSignal(str)
    run_finished  = pyqtSignal(int)

    def __init__(self, spec: RunSpec, parent=None):
        super().__init__(parent)
        self.spec = spec
        self._proc: subprocess.Popen | None = None
        self._cancelled = False
        self._stderr_tail: list[str] = []
        self._row_count = 0

    # ── Control ───────────────────────────────────────────────────────────────

    def cancel(self):
        """Ask the run to stop. Safe to call from the GUI thread."""
        self._cancelled = True
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.terminate()
        except Exception:
            pass

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    @property
    def row_count(self) -> int:
        return self._row_count

    # ── Execution ─────────────────────────────────────────────────────────────

    def run(self):
        exit_code = 1
        try:
            exit_code = self._execute()
        except FileNotFoundError as exc:
            self.failed.emit(
                f"Could not launch volatility3: {exc}\n\n"
                "Check that volatility3 is installed in this environment."
            )
        except Exception as exc:
            log.exception("Unhandled error running %s", self.spec.plugin_id)
            self.failed.emit(f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc()}")
        finally:
            self.run_finished.emit(exit_code)

    def _execute(self) -> int:
        import io

        command = self.spec.command()
        self.log_line.emit("$ " + " ".join(command))

        self._proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=build_environment(self.spec.symbol_dirs),
            creationflags=_creation_flags(),
        )

        stderr_thread = threading.Thread(
            target=self._drain_stderr, name="vol3-stderr", daemon=True
        )
        stderr_thread.start()

        # newline="" is required: csv handles its own line endings, and letting
        # the wrapper translate them corrupts fields with embedded newlines.
        stdout = io.TextIOWrapper(
            self._proc.stdout, encoding="utf-8", errors="replace", newline=""
        )
        self._consume_rows(stdout)

        self._proc.wait()
        stderr_thread.join(timeout=2.0)
        code = self._proc.returncode

        if self._cancelled:
            self.log_line.emit("Cancelled by user.")
        elif code != 0:
            self.failed.emit(self._failure_message(code))

        self._proc = None
        return code

    def _consume_rows(self, stdout) -> None:
        reader = csv.reader(stdout, escapechar="\\")
        columns: list[str] = []
        batch: list[list[str]] = []
        last_flush = time.monotonic()

        for record in reader:
            if self._cancelled:
                break
            if not record or not any(field.strip() for field in record):
                continue

            if not columns:
                columns = [c.strip() for c in record]
                self.columns_ready.emit(columns)
                continue

            # Pad or fold so every row matches the header width exactly; a
            # short row from a truncated write must not shift columns.
            if len(record) < len(columns):
                record = record + [""] * (len(columns) - len(record))
            elif len(record) > len(columns):
                head = record[: len(columns) - 1]
                record = head + [",".join(record[len(columns) - 1:])]

            batch.append(record)
            self._row_count += 1

            now = time.monotonic()
            if len(batch) >= _BATCH_ROWS or (now - last_flush) >= _BATCH_SECONDS:
                self.rows_ready.emit(batch)
                batch = []
                last_flush = now

        if batch:
            self.rows_ready.emit(batch)

    def _drain_stderr(self) -> None:
        """
        Consume stderr continuously so vol3 never blocks writing to a full pipe,
        and turn its \\r-delimited progress writes into progress signals.
        """
        stream = self._proc.stderr if self._proc else None
        if stream is None:
            return
        pending = b""
        try:
            while True:
                chunk = stream.read1(4096)
                if not chunk:
                    break
                pending += chunk
                # Progress updates end in \r; real messages end in \n.
                parts = pending.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
                pending = parts.pop()
                for raw in parts:
                    self._handle_stderr_line(raw.decode("utf-8", "replace").strip())
            if pending:
                self._handle_stderr_line(pending.decode("utf-8", "replace").strip())
        except Exception as exc:
            log.debug("stderr drain ended: %s", exc)

    def _handle_stderr_line(self, line: str) -> None:
        if not line:
            return
        if line.startswith("Progress:"):
            body = line[len("Progress:"):].strip()
            percent, _, description = body.partition("\t")
            try:
                value = float(percent.strip())
            except ValueError:
                return
            self.progress.emit(value, description.strip())
            return

        # Keep the tail for diagnosing a non-zero exit, and surface it in the log.
        self._stderr_tail.append(line)
        del self._stderr_tail[:-40]
        self.log_line.emit(line)

    def _failure_message(self, code: int) -> str:
        tail = "\n".join(self._stderr_tail[-15:]).strip()
        hint = ""
        lowered = tail.lower()
        if "symbol" in lowered and ("not found" in lowered or "unsatisfied" in lowered):
            hint = (
                "\n\nThis usually means the symbol table for this image is missing. "
                "Open Symbols & YARA to fetch or import one."
            )
        elif "unsatisfied requirement" in lowered:
            hint = (
                "\n\nThe plugin needs an argument that was not supplied. "
                "Run it from the plugin browser to fill in its parameters."
            )
        return (
            f"{self.spec.plugin_id} exited with code {code}."
            + (f"\n\n{tail}" if tail else "")
            + hint
        )


# OS detection used to live here as OsProbe, which ran banners.Banners and
# treated an empty result as failure. That is the guaranteed outcome on a
# Windows image, since banners only looks for Linux and Mac kernels. It now
# lives in core.os_detect, which sniffs the container header first and only
# falls back to a full banner scan for images that are not Windows.
