import hashlib
import os
import threading
from concurrent.futures import ThreadPoolExecutor

from PyQt6.QtCore import QThread, pyqtSignal


class HashCancelled(Exception):
    """hash_file was asked to stop part-way."""


def hash_file(path: str, chunk: int = 8 * 1024 * 1024,
              cancelled=lambda: False, progress=lambda done, total: None):
    """
    MD5 and SHA-256 of `path` in one pass, returned as (md5, sha256) hex.

    The two digests run side by side: hashlib releases the GIL on large
    buffers, so MD5 is computed on a helper thread while SHA-256 runs here.
    That cuts the wall time to roughly the slower of the two rather than their
    sum: about a third off for a multi-gigabyte image.
    """
    # A checksum for the evidence record, not security; without the flag a
    # FIPS-mode system refuses md5 outright.
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    total = os.path.getsize(path)
    done = 0
    with open(path, "rb") as handle, ThreadPoolExecutor(1) as helper:
        while True:
            if cancelled():
                raise HashCancelled()
            data = handle.read(chunk)
            if not data:
                break
            pending = helper.submit(md5.update, data)
            sha256.update(data)
            pending.result()
            done += len(data)
            progress(done, total)
    return md5.hexdigest(), sha256.hexdigest()


class HashWorker(QThread):
    hashes_ready = pyqtSignal(str, str)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, file_path: str, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self._cancelled = threading.Event()

    def cancel(self):
        """Stop at the next chunk. Neither hashes_ready nor error is emitted."""
        self._cancelled.set()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def run(self):
        last = -1

        def report(done: int, total: int):
            nonlocal last
            pct = int(done * 100 / total) if total else 100
            if pct != last:
                last = pct
                self.progress.emit(pct)

        try:
            md5, sha256 = hash_file(self.file_path, cancelled=self._cancelled.is_set,
                                    progress=report)
        except HashCancelled:
            return
        except Exception as e:
            if not self.cancelled:
                self.error.emit(str(e))
            return
        if not self.cancelled:
            self.hashes_ready.emit(md5, sha256)


class FileHasher(QThread):
    """
    SHA-256 for a list of files, one after another, off the GUI thread.

    Extractions are hashed the moment they are written, because that is the
    only point at which the hash means "this is what volatility3 produced":
    computed later, it only proves what the file contains now.
    """

    hashed = pyqtSignal(str, str, int)      # path, sha256, size
    failed = pyqtSignal(str, str)           # path, reason
    all_done = pyqtSignal(int)              # how many were hashed

    CHUNK = 1024 * 1024 * 8

    def __init__(self, paths: list[str], parent=None):
        super().__init__(parent)
        self.paths = list(paths)
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        done = 0
        for path in self.paths:
            if self._cancelled:
                break
            try:
                digest = hashlib.sha256()
                size = 0
                with open(path, "rb") as handle:
                    while True:
                        if self._cancelled:
                            return
                        block = handle.read(self.CHUNK)
                        if not block:
                            break
                        digest.update(block)
                        size += len(block)
                self.hashed.emit(path, digest.hexdigest(), size)
                done += 1
            except OSError as exc:
                self.failed.emit(path, str(exc))
        self.all_done.emit(done)
