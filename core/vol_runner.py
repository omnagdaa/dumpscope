"""
Volatility3 execution for DumpScope.

Runs vol3 as a subprocess with the CSV renderer, which streams one row at a
time and quotes properly: unlike the default text renderer, whose columns can
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
from collections.abc import Callable

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
    and every launch (plugins and the OS probe alike) queues here.

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
                poll: float = 0.1, solo: Callable[[], bool] = lambda: False) -> bool:
        """
        Block until a slot is free. False if `cancelled()` became true first.

        While `solo()` is true the limit is treated as 1. It is re-checked on
        every poll, so queued runs fan out again as soon as it turns false.
        """
        with self._cond:
            self._waiting += 1
            try:
                while self._active >= (1 if solo() else self._limit):
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


ISF_SUFFIXES = (".json", ".json.xz", ".json.gz", ".json.bz2")


def isf_complete(path: str) -> bool:
    """
    True when the ISF at `path` has been fully written.

    vol3 creates its output ``.json.xz`` before it starts downloading the PDB
    and only finishes it minutes later, so the file's existence says nothing.
    An xz stream ends with the footer magic ``YZ`` (optionally followed by
    zero padding), which is written when the file is closed.
    """
    try:
        size = os.path.getsize(path)
        if size == 0:
            return False
        if not path.endswith(".json.xz"):
            return True
        with open(path, "rb") as handle:
            handle.seek(max(0, size - 64))
            return handle.read().rstrip(b"\0").endswith(b"YZ")
    except OSError:
        return False


def awaiting_case_symbols(symbol_dirs: list[str] | None) -> bool:
    """
    True when the run uses case symbol folders that hold no complete ISF yet.

    The first run on such a case downloads the kernel PDB into the case cache
    and converts it into the case symbols folder. A second run started during
    that download reads the half-written PDB and fails with "Offset outside of
    the buffer boundaries", so runs go one at a time until an ISF is complete.

    Known limit: only the first kernel of a case is guarded. A second image
    with a different kernel in the same case can still race.
    """
    dirs = [d for d in (symbol_dirs or []) if d]
    if not dirs:
        return False
    return not any(
        isf_complete(os.path.join(root, name))
        for d in dirs for root, _, files in os.walk(d)
        for name in files if name.endswith(ISF_SUFFIXES)
    )


def discard_partial_isfs(symbol_dirs: list[str] | None) -> list[str]:
    """
    Delete ISF files in `symbol_dirs` that were never finished; return them.

    vol3 removes its own half-written ISF when a conversion fails, but not
    when its process is killed (a timeout, a cancel). Call this only while
    holding the gate in solo mode: then no other vol3 process can be writing
    to these folders.
    """
    removed = []
    for d in (symbol_dirs or []):
        if not d:
            continue
        for root, _, files in os.walk(d):
            for name in files:
                path = os.path.join(root, name)
                if name.endswith(ISF_SUFFIXES) and not isf_complete(path):
                    try:
                        os.remove(path)
                        removed.append(path)
                    except OSError as exc:
                        log.warning("Could not remove partial ISF %s: %s", path, exc)
    return removed


# ── Symbol-cache corruption ───────────────────────────────────────────────────

# vol3 keeps an SQLite identifier cache and decompressed ISF files under its
# cache directory. An interrupted write leaves either one damaged, and every run
# after that fails the same way until the cache is cleared. These are the
# shapes that failure takes on stderr.
_CACHE_CORRUPTION = re.compile(
    r"database disk image is malformed"
    r"|file is not a database"
    r"|sqlite3\.DatabaseError"
    # "database is locked" is another vol3 process writing the same cache,
    # not damage; clearing the cache then would break that process too.
    r"|sqlite3\.OperationalError(?!: database is locked)"
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


# Failures caused by another vol3 process working on the same case at the same
# moment: a locked identifier cache, or a PDB that is still being downloaded.
# They clear up once the other run is done, so the run is simply tried again.
_CONTENTION = re.compile(
    r"database is locked|Offset outside of the buffer boundaries", re.IGNORECASE)


def looks_like_contention(text: str) -> bool:
    return bool(text) and _CONTENTION.search(text) is not None


# A symbol download that timed out or was cut off. vol3 removes the partial
# files itself, so a second attempt starts clean.
_DOWNLOAD_STALLED = re.compile(
    r"did not download completely|timed out|TimeoutError|Connection reset",
    re.IGNORECASE)


def looks_like_stalled_download(text: str) -> bool:
    return bool(text) and _DOWNLOAD_STALLED.search(text) is not None


# How long a cancelled vol3 process gets to exit on SIGTERM before it is killed.
_KILL_GRACE_SECONDS = 5.0


def stop_process(proc: subprocess.Popen | None) -> None:
    """
    Terminate `proc` now and kill it if it is still alive after a grace period.

    Returns immediately. The kill guarantees the process exits, which is what
    lets the window wait for its worker threads on close without a timeout.
    """
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
    except OSError:
        return

    def kill_if_alive():
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass

    timer = threading.Timer(_KILL_GRACE_SECONDS, kill_if_alive)
    timer.daemon = True
    timer.start()

# Rows are handed to the UI in batches; a signal per row swamps the event loop
# on plugins that emit tens of thousands of them (filescan, handles).
_BATCH_ROWS = 250
_BATCH_SECONDS = 0.10

# csv's default 128 KB field cap is below what malfind hexdumps and long
# command lines reach; hitting it aborted the whole run. 2**31-1 because the
# limit is a C long, which is 32-bit on Windows.
csv.field_size_limit(2**31 - 1)

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

DOWNLOAD_STALL_SECONDS = 60

# volatility3 plugins that ship with DumpScope. The folder is passed with -p
# only to runs of those plugins, so every other run sees stock volatility3.
BUNDLED_PLUGIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vol_plugins")
BUNDLED_PREFIX = "dumpscope."


# volatility3.cli is a package with no __main__, so ``-m volatility3.cli``
# refuses to run; the installed script calls ``main()`` from it directly, and
# so does this.
# -P keeps the working directory off sys.path: `python -c` would otherwise
# import a planted volatility3/ from whatever folder DumpScope was started in.
#
# argv[0] is rewritten because volatility3's parser reads it: left as "-c" it
# is taken for the --config flag and the run dies on argument parsing.
#
# vol3 downloads PDBs with urlopen() and no timeout, so a symbol-server
# connection that stops sending data blocks the run forever. The first run on a
# case holds the gate alone while it downloads, so every other run waits behind
# it. A default socket timeout turns the stall into an error after
# DOWNLOAD_STALL_SECONDS without data; vol3 then deletes its partial download
# and partial ISF, and the run is retried once (see _DOWNLOAD_STALLED).
#
# With DUMPSCOPE_CASE_SYMBOLS set, vol3's per-user symbol cache
# (~/.cache/volatility3/symbols) is dropped from its search path before the CLI
# runs. The case's own symbols folder, passed with -s, is then the first
# writable location, so a PDB that vol3 downloads and converts for this image
# lands inside the case rather than in a cache shared by every investigation.
# symbols.__path__ is the same list object, so editing it in place covers both.
_CLI_ENTRY = (
    "import os, socket, sys; sys.argv[0] = 'vol'\n"
    f"socket.setdefaulttimeout({DOWNLOAD_STALL_SECONDS})\n"
    "if os.environ.get('DUMPSCOPE_CASE_SYMBOLS'):\n"
    "    from volatility3.framework import constants as c\n"
    "    user = os.path.realpath(os.path.join(c.CACHE_PATH, 'symbols'))\n"
    "    c.SYMBOL_BASEPATHS[:] = [p for p in c.SYMBOL_BASEPATHS"
    " if os.path.realpath(p) != user]\n"
    "from volatility3.cli import main; sys.exit(main())"
)


def _module_command() -> list[str] | None:
    """
    volatility3's CLI entry point, called through the interpreter running this
    app, when volatility3 is importable from it.

    This is preferred over the installed ``vol`` script for two reasons. It
    cannot pick up a different volatility3 than the one the GUI introspected
    for plugin arguments: the script on PATH may belong to another
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
    return [executable, "-P", "-c", _CLI_ENTRY]


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
    if getattr(sys, "frozen", False):
        return [sys.executable, "--vol3-cli"]   # see the top of main.py
    if _COMMAND_CACHE is not None:
        return list(_COMMAND_CACHE)

    command = _module_command()
    if command is None:
        command = _script_command()
        if command is None:
            log.warning("No volatility3 found; calling the library directly")
            command = [sys.executable, "-P", "-c", _CLI_ENTRY]
        else:
            log.info("Using the vol3 script at %s", command[0])
    else:
        log.info("Using the volatility3 library via %s", command[0])

    _COMMAND_CACHE = command
    return list(command)


def vol3_cache_path(cache_dir: str = "") -> str:
    """Where vol3 keeps its identifier cache: the case's, or vol3's default."""
    if cache_dir:
        return os.path.abspath(cache_dir)
    try:
        from volatility3.framework import constants
        return constants.CACHE_PATH
    except Exception:
        from core.paths import cache_dir
        return os.path.join(os.path.dirname(cache_dir()), "volatility3")


def case_symbol_args(symbol_dirs: list[str] | None, cache_dir: str = "") -> list[str]:
    """
    vol3 global options that keep symbols and the identifier cache in the case.

    ``-s`` takes a semicolon-separated list on every platform (vol3 splits on
    ";" itself). Its first writable entry is where vol3 writes the ISF it
    builds from a downloaded PDB. ``--cache-path`` moves the identifier cache,
    so clearing a corrupted cache only ever touches this case.
    """
    args: list[str] = []
    dirs = [os.path.abspath(d) for d in (symbol_dirs or []) if d]
    if dirs:
        args += ["-s", ";".join(dirs)]
    if cache_dir:
        args += ["--cache-path", os.path.abspath(cache_dir)]
    return args


def build_environment(symbol_dirs: list[str] | None = None) -> dict[str, str]:
    """
    Process environment for a vol3 run.

    vol3 reads no environment variable for symbol locations; they are passed on
    the command line (see case_symbol_args). What the environment carries is
    the switch that hides the per-user symbol cache whenever the run has case
    symbol folders, so the case stays self-contained.
    """
    env = os.environ.copy()
    env.pop("DUMPSCOPE_CASE_SYMBOLS", None)
    if any(symbol_dirs or []):
        env["DUMPSCOPE_CASE_SYMBOLS"] = "1"
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
    # from: so extractions would land outside the case with nothing recording
    # where they went.
    output_dir: str = ""
    # vol3's own worker pool for a single plugin. "off" is its default.
    parallelism: str = ""
    # Ask vol3 to discard its identifier/symbol cache before running. Set only
    # on the automatic retry after a corrupted-cache failure.
    clear_cache: bool = False
    # The case's private vol3 cache (identifier cache). Empty: vol3's default.
    cache_dir: str = ""

    def command(self) -> list[str]:
        command = find_vol3_command() + ["-r", "csv"]
        if self.plugin_id.startswith(BUNDLED_PREFIX):
            command += ["-p", BUNDLED_PLUGIN_DIR]
        command += case_symbol_args(self.symbol_dirs, self.cache_dir)
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

    A run that produced no rows is retried once when its stderr shows:

    * contention with another run on the same case (a locked cache, a PDB still
      downloading): it queues again and reruns unchanged;
    * a symbol download that timed out or was cut off: it reruns unchanged;
    * a corrupted vol3 cache: it waits until no other vol3 process is running,
      then reruns with ``--clear-cache``, so clearing never pulls the cache out
      from under a concurrent run.
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
        self._columns_sent = False
        self.retried_after_cache_clear = False

    # ── Control ───────────────────────────────────────────────────────────────

    def cancel(self):
        """Ask the run to stop. Safe to call from the GUI thread."""
        self._cancelled = True
        stop_process(self._proc)

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    # ── Execution ─────────────────────────────────────────────────────────────

    def run(self):
        exit_code = 1
        holding = False
        try:
            solo = lambda: awaiting_case_symbols(self.spec.symbol_dirs)
            if self.gate.active >= (1 if solo() else self.gate.limit):
                self.queued.emit(self.gate.active)
                self.log_line.emit("Queued: waiting for another volatility3 run to finish.")
            holding = self.gate.acquire(cancelled=lambda: self._cancelled, solo=solo)
            if not holding:
                self.log_line.emit("Cancelled before it started.")
                return
            exit_code = self._execute()
            retry = self._retry_kind(exit_code)
            if retry:
                # Give the slot back while waiting, so the run being waited on
                # (or anything else queued) can proceed.
                self.gate.release()
                holding = False
                if retry in ("contention", "download"):
                    self.log_line.emit(
                        "The symbol download stalled or was cut off. Retrying."
                        if retry == "download" else
                        "Another run was still preparing this case's symbols or "
                        "cache. Retrying once it is done.")
                    holding = self.gate.acquire(cancelled=lambda: self._cancelled,
                                                solo=solo)
                else:
                    self.retried_after_cache_clear = True
                    self.spec.clear_cache = True
                    self.log_line.emit(
                        "volatility3's cache looks corrupted. Clearing it and retrying "
                        "once no other run is using it.")
                    holding = self.gate.acquire(cancelled=lambda: self._cancelled,
                                                solo=lambda: True)
                if not holding:
                    self.log_line.emit("Cancelled before the retry started.")
                    return
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

    def _retry_kind(self, exit_code: int) -> str:
        """"contention", "download", "corruption" or "" for the run that just ended."""
        if exit_code == 0 or self._cancelled or self._columns_sent:
            return ""
        tail = "\n".join(self._stderr_tail)
        if looks_like_contention(tail):
            return "contention"
        if looks_like_stalled_download(tail):
            return "download"
        if looks_like_cache_corruption(tail):
            return "corruption"
        return ""

    def _execute(self) -> int:
        import io

        command = self.spec.command()
        if awaiting_case_symbols(self.spec.symbol_dirs):
            for path in discard_partial_isfs(self.spec.symbol_dirs):
                self.log_line.emit(f"Removed an unfinished symbol file: {path}")
        self.log_line.emit("$ " + _printable(command))
        # vol3 writes its identifier cache into --cache-path but never creates
        # the folder; a missing one fails the run on its first cache write.
        for folder in [self.spec.cache_dir, *self.spec.symbol_dirs]:
            if folder:
                os.makedirs(folder, exist_ok=True)

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
        # Reading stopped early (cancelled, or the parser raised); a process
        # still writing would block on a full stdout pipe and never exit.
        try:
            self._consume_rows(stdout)
        except BaseException:
            self._terminate()
            raise
        if self._cancelled:
            self._terminate()

        self._proc.wait()
        stderr_thread.join(timeout=2.0)
        code = self._proc.returncode
        # Popen leaves its pipes open until garbage collection; a session of
        # several hundred runs would otherwise exhaust the process's handles.
        for stream in (stdout, self._proc.stderr):
            try:
                stream.close()
            except Exception:
                pass

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
                + ". Delete the folder below and try again:\n"
                + vol3_cache_path(self.spec.cache_dir)
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
