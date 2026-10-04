"""
Symbol table management.

volatility3 needs a symbol table (ISF) matching the kernel in the image. For
Windows it can build one itself: it reads the kernel's PDB GUID from the image,
downloads that PDB from Microsoft's symbol server and converts it. DumpScope
points that machinery at the case — every run passes the case's symbols folder
first and hides vol3's shared per-user cache — so the ISF for an image is
written into, and only ever read from, the case that examined it.

SymbolFetcher triggers that download deliberately, for one image. The bulk
packs (gigabytes, every known kernel) remain available for offline work.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import urllib.error
import urllib.request
import zipfile

import subprocess

from PyQt6.QtCore import QThread, pyqtSignal

from core.paths import cache_dir

log = logging.getLogger("dumpscope.symbols")

SYMBOL_BASE_URL = "https://downloads.volatilityfoundation.org/volatility3/symbols"

SYMBOL_PACKS = {
    "windows": f"{SYMBOL_BASE_URL}/windows.zip",
    "linux":   f"{SYMBOL_BASE_URL}/linux.zip",
    "mac":     f"{SYMBOL_BASE_URL}/mac.zip",
}

SYMBOL_EXTENSIONS = (".json", ".json.xz", ".json.gz", ".json.bz2")


def symbols_present(base_dir: str) -> bool:
    """True when the case's symbols directory holds at least one ISF file."""
    symbols_dir = os.path.join(base_dir, "symbols")
    if not os.path.isdir(symbols_dir):
        return False
    for _, _, files in os.walk(symbols_dir):
        if any(name.endswith(SYMBOL_EXTENSIONS) for name in files):
            return True
    return False


def count_symbols(base_dir: str) -> int:
    symbols_dir = os.path.join(base_dir, "symbols")
    if not os.path.isdir(symbols_dir):
        return 0
    return sum(
        1
        for _, _, files in os.walk(symbols_dir)
        for name in files
        if name.endswith(SYMBOL_EXTENSIONS)
    )


def get_vol3_cache_dir() -> str:
    """volatility3's own symbol cache, which it populates on automatic fetches."""
    try:
        from volatility3.framework import constants
        for path in getattr(constants, "SYMBOL_BASEPATHS", ()):
            if os.path.isdir(path):
                return path
    except Exception:
        pass
    return os.path.join(os.path.dirname(cache_dir()), "volatility3")


class SymbolDownloader(QThread):
    """
    Streams a symbol pack to disk and extracts it into <base_dir>/symbols.

    The packs are large (the Windows pack runs to gigabytes), so the download
    goes to a temporary file in chunks with progress reporting and can be
    cancelled part-way; a cancelled or failed download never leaves a partial
    archive behind.
    """

    progress = pyqtSignal(str)      # human-readable status lines
    percent  = pyqtSignal(int)      # 0-100, or 0 when the size is unknown
    done     = pyqtSignal(bool, str)

    _CHUNK = 1024 * 512

    def __init__(self, base_dir: str, pack: str, parent=None):
        super().__init__(parent)
        self.base_dir = base_dir
        self.pack = pack
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        url = SYMBOL_PACKS.get(self.pack)
        if url is None:
            self.done.emit(False, f"Unknown symbol pack: {self.pack}")
            return

        target_dir = os.path.join(self.base_dir, "symbols")
        os.makedirs(target_dir, exist_ok=True)
        archive_path = None

        try:
            archive_path = self._download(url)
            if self._cancelled:
                self.done.emit(False, "Download cancelled.")
                return
            added = self._extract(archive_path, target_dir)
            if self._cancelled:
                self.done.emit(False, "Extraction cancelled.")
                return
            self.done.emit(True, f"Installed {added} symbol files into {target_dir}")
        except urllib.error.URLError as exc:
            log.warning("Symbol download failed: %s", exc)
            self.done.emit(False, f"Could not reach the symbol server: {exc.reason}")
        except zipfile.BadZipFile:
            self.done.emit(False, "The downloaded archive was corrupt. Try again.")
        except Exception as exc:
            log.exception("Symbol download failed")
            self.done.emit(False, f"{type(exc).__name__}: {exc}")
        finally:
            if archive_path and os.path.exists(archive_path):
                try:
                    os.unlink(archive_path)
                except OSError:
                    pass

    def _download(self, url: str) -> str:
        self.progress.emit(f"Fetching {url}")
        handle, archive_path = tempfile.mkstemp(suffix=".zip", prefix="dumpscope-symbols-")
        os.close(handle)

        request = urllib.request.Request(url, headers={"User-Agent": "DumpScope"})
        with urllib.request.urlopen(request, timeout=60) as response:
            total = int(response.headers.get("Content-Length") or 0)
            if total:
                self.progress.emit(f"Size: {_format_bytes(total)}")
            else:
                self.progress.emit("Size unknown — progress will not be shown.")

            downloaded = 0
            last_reported = -1
            with open(archive_path, "wb") as out:
                while not self._cancelled:
                    chunk = response.read(self._CHUNK)
                    if not chunk:
                        break
                    out.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = int(downloaded * 100 / total)
                        if pct != last_reported:
                            self.percent.emit(pct)
                            last_reported = pct
                    elif downloaded % (self._CHUNK * 20) == 0:
                        self.progress.emit(f"Downloaded {_format_bytes(downloaded)}")

        self.progress.emit(f"Downloaded {_format_bytes(downloaded)}")
        return archive_path

    def _extract(self, archive_path: str, target_dir: str) -> int:
        self.progress.emit("Extracting…")
        added = 0
        with zipfile.ZipFile(archive_path) as archive:
            members = [m for m in archive.infolist() if not m.is_dir()]
            for index, member in enumerate(members, start=1):
                if self._cancelled:
                    break
                # Reject absolute paths and traversal before writing anything.
                root = os.path.abspath(target_dir)
                destination = os.path.normpath(os.path.join(root, member.filename))
                if not destination.startswith(root + os.sep):
                    log.warning("Skipping unsafe archive entry %s", member.filename)
                    continue
                os.makedirs(os.path.dirname(destination), exist_ok=True)
                with archive.open(member) as source, open(destination, "wb") as out:
                    shutil.copyfileobj(source, out)
                added += 1
                if members and index % 50 == 0:
                    self.percent.emit(int(index * 100 / len(members)))
        self.percent.emit(100)
        return added


def _format_bytes(count: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if count < 1024:
            return f"{count:.1f} {unit}"
        count /= 1024
    return f"{count:.1f} TB"


def list_symbols(base_dir: str) -> list[tuple[str, int]]:
    """Every ISF file in the case's symbols folder: (relative path, size)."""
    symbols_dir = os.path.join(base_dir, "symbols")
    found = []
    for root, _dirs, files in os.walk(symbols_dir):
        for name in files:
            if name.endswith(SYMBOL_EXTENSIONS):
                path = os.path.join(root, name)
                try:
                    size = os.path.getsize(path)
                except OSError:
                    size = 0
                found.append((os.path.relpath(path, symbols_dir), size))
    return sorted(found)


class SymbolFetcher(QThread):
    """
    Fetch the symbols for one Windows image into the case.

    Runs ``windows.info.Info`` with the case's symbol arguments. To answer it,
    vol3 identifies the kernel, downloads the matching PDB and writes the ISF
    into the first symbol folder — the case's. Whatever ISF files are new
    afterwards are what was fetched.
    """

    progress = pyqtSignal(str)
    done = pyqtSignal(bool, str, list)        # ok, message, new relative paths

    TIMEOUT = 900

    def __init__(self, image_path: str, base_dir: str, parent=None):
        super().__init__(parent)
        self.image_path = image_path
        self.base_dir = base_dir
        self._proc: subprocess.Popen | None = None
        self._cancelled = False

    def cancel(self):
        self._cancelled = True
        proc = self._proc
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass

    def command(self) -> list[str]:
        from core.vol_runner import case_symbol_args, find_vol3_command
        return find_vol3_command() + case_symbol_args(
            [os.path.join(self.base_dir, "symbols")],
            os.path.join(self.base_dir, "cache"),
        ) + ["-r", "csv", "-f", os.path.abspath(self.image_path), "windows.info.Info"]

    def run(self):
        from core.vol_runner import RUN_GATE, _creation_flags, build_environment
        if not self.image_path or not os.path.isfile(self.image_path):
            self.done.emit(False, "No memory image is loaded.", [])
            return
        symbols_dir = os.path.join(self.base_dir, "symbols")
        os.makedirs(symbols_dir, exist_ok=True)
        os.makedirs(os.path.join(self.base_dir, "cache"), exist_ok=True)
        before = {path for path, _ in list_symbols(self.base_dir)}

        self.progress.emit("Waiting for other volatility3 runs to finish…")
        if not RUN_GATE.acquire(cancelled=lambda: self._cancelled):
            self.done.emit(False, "Cancelled.", [])
            return
        try:
            self.progress.emit("Identifying the kernel and fetching its PDB from "
                               "Microsoft's symbol server…")
            self._proc = subprocess.Popen(
                self.command(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env=build_environment([symbols_dir]),
                creationflags=_creation_flags(),
            )
            try:
                _out, err = self._proc.communicate(timeout=self.TIMEOUT)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.communicate()
                self.done.emit(False, "Timed out fetching symbols.", [])
                return
            code = self._proc.returncode
        except OSError as exc:
            self.done.emit(False, f"Could not run volatility3: {exc}", [])
            return
        finally:
            self._proc = None
            RUN_GATE.release()

        if self._cancelled:
            self.done.emit(False, "Cancelled.", [])
            return
        added = sorted({path for path, _ in list_symbols(self.base_dir)} - before)
        if added:
            self.done.emit(True, f"Fetched {len(added)} symbol table(s) into the case.", added)
        elif code == 0:
            self.done.emit(True, "This image's symbols are already in the case.", [])
        else:
            tail = " ".join((err or "").strip().splitlines()[-3:])
            self.done.emit(False,
                           "volatility3 could not fetch symbols for this image. "
                           "Check the network connection to msdl.microsoft.com, or "
                           "download the full Windows pack instead."
                           + (f"\n\n{tail}" if tail else ""), [])
