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
