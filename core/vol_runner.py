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
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from typing import Callable

from PyQt6.QtCore import QThread, pyqtSignal

log = logging.getLogger("dumpscope.vol_runner")


# ── Run gate ──────────────────────────────────────────────────────────────────

class RunGate:
    """
    Caps how many volatility3 processes run at once.

    Concurrent vol3 processes share one identifier cache and one symbol cache
    on disk; two of them rebuilding it at the same moment is the usual way that
    cache gets corrupted. They also each map the whole image, so on a large
    dump several at once can exhaust memory. The default limit is therefore 1,
    and every launch — plugins and the OS probe alike — queues here.

    Waiting is done in short slices so a queued run can be cancelled without
    ever having held a slot.
    """

    def __init__(self, limit: int = 1):
        self._cond = threading.Condition()
        self._limit = max(1, int(limit))
        self._active = 0
        self._waiting = 0

    @property
    def limit(self) -> int:
        return self._limit

    def set_limit(self, limit: int) -> None:
        with self._cond:
            self._limit = max(1, int(limit))
            self._cond.notify_all()

    @property
    def active(self) -> int:
        return self._active

    @property
    def waiting(self) -> int:
        return self._waiting

    def acquire(self, cancelled: Callable[[], bool] = lambda: False,
                poll: float = 0.1) -> bool:
        """Block until a slot is free. False if `cancelled()` became true first."""
        with self._cond:
            self._waiting += 1
            try:
                while self._active >= self._limit:
                    if cancelled():
                        return False
                    self._cond.wait(poll)
                if cancelled():
                    return False
                self._active += 1
                return True
            finally:
                self._waiting -= 1

    def release(self) -> None:
        with self._cond:
            if self._active > 0:
                self._active -= 1
            self._cond.notify_all()


RUN_GATE = RunGate(limit=1)


# ── Symbol-cache corruption ───────────────────────────────────────────────────

# vol3 keeps an SQLite identifier cache and decompressed ISF files under its
# cache directory. An interrupted write leaves either one damaged, and every run
# after that fails the same way until the cache is cleared. These are the
# shapes that failure takes on stderr.
_CACHE_CORRUPTION = re.compile(
    r"database disk image is malformed"
    r"|file is not a database"
    r"|sqlite3\.(?:Database|Operational)Error"
    r"|JSONDecodeError"
    r"|LZMAError"
    r"|Compressed file ended before the end-of-stream marker"
    r"|Not a gzipped file"
    r"|Invalid data stream"
    r"|BadZipFile",
    re.IGNORECASE,
)


def looks_like_cache_corruption(text: str) -> bool:
    """True when vol3's stderr shows a damaged identifier or symbol cache."""
    return bool(text) and _CACHE_CORRUPTION.search(text) is not None

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


_COMMAND_CACHE: list[str] | None = None


# volatility3.cli is a package with no __main__, so ``-m volatility3.cli``
# refuses to run; the installed script calls ``main()`` from it directly, and
# so does this.
# argv[0] is rewritten because volatility3's parser reads it: left as "-c" it
# is taken for the --config flag and the run dies on argument parsing.
_CLI_ENTRY = (
    "import sys; sys.argv[0] = 'vol'; "
    "from volatility3.cli import main; sys.exit(main())"
)


def _module_command() -> list[str] | None:
    """
    volatility3's CLI entry point, called through the interpreter running this
    app, when volatility3 is importable from it.

    This is preferred over the installed ``vol`` script for two reasons. It
    cannot pick up a different volatility3 than the one the GUI introspected
    for plugin arguments — the script on PATH may belong to another
    environment entirely. And on Windows, console scripts in a uv-created venv
    are trampoline executables that re-resolve their own path at launch; when
    that resolution fails the process dies before volatility3 is reached, with
    no traceback and only "uv trampoline failed to canonicalize script path"
    on stderr. Going through the interpreter skips the trampoline.
    """
    if getattr(sys, "frozen", False):
        return None                     # a bundled app has no importable venv
    executable = sys.executable
    if not executable:
        return None
    # pythonw has no console, but it also cannot report a startup failure;
    # the console build sits beside it and is the one to spawn.
    if sys.platform == "win32" and os.path.basename(executable).lower() == "pythonw.exe":
        console = os.path.join(os.path.dirname(executable), "python.exe")
        if os.path.isfile(console):
            executable = console
    try:
        import importlib.util
        if importlib.util.find_spec("volatility3.cli") is None:
            return None
    except (ImportError, ValueError, ModuleNotFoundError):
        return None
    return [executable, "-c", _CLI_ENTRY]


def _script_command() -> list[str] | None:
    """The installed vol3 console script, looked for beside the interpreter first."""
    interpreter_dir = os.path.dirname(sys.executable)
    search_dirs = [
        interpreter_dir,
        os.path.normpath(os.path.join(interpreter_dir, "..", "Scripts")),
        os.path.join(interpreter_dir, "Scripts"),
        os.path.normpath(os.path.join(interpreter_dir, "..", "bin")),
    ]
    # Only .exe: CreateProcess cannot run a .cmd or .bat without a shell, so
    # offering them here would find a file that then fails to launch.
    suffixes = (".exe",) if sys.platform == "win32" else ("",)

    for name in ("vol", "vol3", "volatility3", "volatility"):
        for directory in search_dirs:
            for suffix in suffixes:
                candidate = os.path.join(directory, name + suffix)
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    return [candidate]
        found = shutil.which(name)
        if found and found.lower().endswith(suffixes):
            return [found]
    return None


def find_vol3_command() -> list[str]:
    """
    How to invoke volatility3, decided once and reused.

    The result was previously recomputed for every run, which meant a
    filesystem walk per plugin launch and a log line to match.
    """
    global _COMMAND_CACHE
    if _COMMAND_CACHE is not None:
        return list(_COMMAND_CACHE)

    command = _module_command()
    if command is None:
        command = _script_command()
        if command is None:
            log.warning("No volatility3 found — calling the library directly")
            command = [sys.executable, "-c", _CLI_ENTRY]
        else:
            log.info("Using the vol3 script at %s", command[0])
    else:
        log.info("Using the volatility3 library via %s", command[0])

    _COMMAND_CACHE = command
    return list(command)


def vol3_cache_path() -> str:
    """Where vol3 keeps its identifier cache and decompressed symbols."""
    try:
        from volatility3.framework import constants
        return constants.CACHE_PATH
    except Exception:
        from core.paths import cache_dir
        return os.path.join(os.path.dirname(cache_dir()), "volatility3")


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


def _printable(command: list[str]) -> str:
    """The command as a line an examiner could paste into a shell."""
    return " ".join(
        f'"{part}"' if (" " in part or ";" in part) else part for part in command
    )


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
    # Ask vol3 to discard its identifier/symbol cache before running. Set only
    # on the automatic retry after a corrupted-cache failure.
    clear_cache: bool = False

    def command(self) -> list[str]:
        command = find_vol3_command() + ["-r", "csv"]
        if self.clear_cache:
            command.append("--clear-cache")
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
    queued(int)           waiting behind this many other runs for the RunGate
    failed(str)           the run could not produce results; carries the reason
    run_finished(int)     process exit code; always emitted exactly once

    A run whose stderr shows a corrupted vol3 cache, and which produced no
    rows, is retried once with ``--clear-cache`` before being reported failed.
    """

    columns_ready = pyqtSignal(list)
    rows_ready    = pyqtSignal(list)
    progress      = pyqtSignal(float, str)
    log_line      = pyqtSignal(str)
    queued        = pyqtSignal(int)
    failed        = pyqtSignal(str)
    run_finished  = pyqtSignal(int)

    def __init__(self, spec: RunSpec, parent=None, gate: RunGate | None = None):
        super().__init__(parent)
        self.spec = spec
        self.gate = gate if gate is not None else RUN_GATE
        self._proc: subprocess.Popen | None = None
        self._cancelled = False
        self._stderr_tail: list[str] = []
        self._row_count = 0
        self._columns_sent = False
        self.retried_after_cache_clear = False

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
        holding = False
        try:
            if self.gate.active >= self.gate.limit:
                self.queued.emit(self.gate.active)
                self.log_line.emit("Queued: waiting for another volatility3 run to finish.")
            holding = self.gate.acquire(cancelled=lambda: self._cancelled)
            if not holding:
                self.log_line.emit("Cancelled before it started.")
                return
            exit_code = self._execute()
            if (exit_code != 0 and not self._cancelled and not self._columns_sent
                    and looks_like_cache_corruption("\n".join(self._stderr_tail))):
                self.retried_after_cache_clear = True
                self.log_line.emit(
                    "volatility3's symbol cache looks corrupted — clearing it and "
                    "retrying once.")
                self.spec.clear_cache = True
                self._stderr_tail = []
                exit_code = self._execute()
            if exit_code != 0 and not self._cancelled:
                self.failed.emit(self._failure_message(exit_code))
        except FileNotFoundError as exc:
            self.failed.emit(
                f"Could not launch volatility3: {exc}\n\n"
                "Check that volatility3 is installed in this environment."
            )
        except Exception as exc:
            log.exception("Unhandled error running %s", self.spec.plugin_id)
            self.failed.emit(f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc()}")
        finally:
            if holding:
                self.gate.release()
            self.run_finished.emit(exit_code)

    def _execute(self) -> int:
        import io

        command = self.spec.command()
        self.log_line.emit("$ " + _printable(command))

        self._proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=build_environment(self.spec.symbol_dirs),
            creationflags=_creation_flags(),
        )
        # cancel() may have run between the flag check and _proc being set, in
        # which case it found nothing to terminate.
        if self._cancelled:
            self._terminate()

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
        if self._cancelled:
            # Reading stopped early; a process still writing would block on a
            # full stdout pipe and wait() would never return.
            self._terminate()

        self._proc.wait()
        stderr_thread.join(timeout=2.0)
        code = self._proc.returncode

        if self._cancelled:
            self.log_line.emit("Cancelled by user.")

        self._proc = None
        return code

    def _terminate(self) -> None:
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception:
            pass

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
                self._columns_sent = True
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
        if looks_like_cache_corruption(tail):
            hint = (
                "\n\nvolatility3's cache appears to be corrupted"
                + (" and clearing it did not help" if self.retried_after_cache_clear else "")
                + ". Delete the folder below and try again:\n" + vol3_cache_path()
            )
        elif "symbol" in lowered and ("not found" in lowered or "unsatisfied" in lowered):
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
