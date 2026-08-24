import hashlib
import os
from PyQt6.QtCore import QThread, pyqtSignal


class HashWorker(QThread):
    hashes_ready = pyqtSignal(str, str)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, file_path: str, parent=None):
        super().__init__(parent)
        self.file_path = file_path

    def run(self):
        try:
            md5 = hashlib.md5()
            sha256 = hashlib.sha256()
            total = os.path.getsize(self.file_path)
            done = 0
            chunk = 1024 * 1024 * 8  # 8 MB chunks

            with open(self.file_path, "rb") as f:
                while True:
                    data = f.read(chunk)
                    if not data:
                        break
                    md5.update(data)
                    sha256.update(data)
                    done += len(data)
                    if total > 0:
                        pct = int((done / total) * 100)
                        self.progress.emit(pct)

            self.hashes_ready.emit(md5.hexdigest(), sha256.hexdigest())
        except Exception as e:
            self.error.emit(str(e))


class FileHasher(QThread):
    """
    SHA-256 for a list of files, one after another, off the GUI thread.

    Extractions are hashed the moment they are written, because that is the
    only point at which the hash means "this is what volatility3 produced" —
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
