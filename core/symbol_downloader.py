"""
Symbol table management.

volatility3 needs a symbol table (ISF) matching the kernel in the image. It
will fetch one automatically for Windows images when it can reach the internet,
but analysts frequently work offline or against kernels the remote server does
not cover, so DumpScope also supports downloading the bulk packs up front into
the case's own symbols directory.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import urllib.error
import urllib.request
import zipfile

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
