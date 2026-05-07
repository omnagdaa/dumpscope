import subprocess
import sys
import os
import shutil
import traceback
import logging
from PyQt6.QtCore import QThread, pyqtSignal

log = logging.getLogger("dumpscope.vol_worker")

# ── OS → plugin prefix map ────────────────────────────────────────────────────
OS_PLUGIN_MAP = {
    "windows": "windows",
    "linux":   "linux",
    "mac":     "mac",
}

# Banner keywords → OS guess
BANNER_HINTS = {
    "windows": ["windows", "microsoft", "ntoskrnl", "win32k"],
    "linux":   ["linux", "ubuntu", "debian", "centos", "fedora", "arch",
                "kernel", "gnu/linux"],
    "mac":     ["darwin", "macos", "mac os x", "xnu"],
}


def detect_os_from_banner(banner: str) -> str:
    """Guess OS from volatility3 banner string."""
    bl = banner.lower()
    for os_name, hints in BANNER_HINTS.items():
        if any(h in bl for h in hints):
            return os_name
    return "windows"   # safe default


def _find_vol3_cmd() -> list[str]:
    """
    Cross-platform: find the volatility3 CLI entry point.
    Works on Windows (vol3.exe / vol.exe) and Linux/Mac.
    """
    venv_bin = os.path.dirname(sys.executable)

    candidates = ["vol3", "vol", "volatility3", "volatility"]

    for name in candidates:
        # Check venv Scripts/ (Windows) or bin/ (Unix)
        for scripts_dir in [venv_bin,
                            os.path.join(venv_bin, "..", "Scripts"),  # Windows venv
                            os.path.join(venv_bin, "Scripts")]:
            scripts_dir = os.path.normpath(scripts_dir)
            for ext in ["", ".exe", ".cmd", ".bat"]:
                candidate = os.path.join(scripts_dir, name + ext)
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    log.debug("Found vol3 at: %s", candidate)
                    return [candidate]

        # PATH fallback
        found = shutil.which(name)
        if found:
            log.debug("Found vol3 in PATH: %s", found)
            return [found]

    # Last resort: python -c
    log.warning("vol3 executable not found — falling back to python -c invocation")
    return [
        sys.executable, "-c",
        "from volatility3.cli import main; main()"
    ]


class VolatilityWorker(QThread):
    output_ready = pyqtSignal(str)
    finished     = pyqtSignal(int)
    error        = pyqtSignal(str)
    os_detected  = pyqtSignal(str)   # emits "windows" / "linux" / "mac"

    def __init__(self, image_path: str, plugin_id: str, base_dir: str,
                 yara_file: str = None, parent=None):
        super().__init__(parent)
        self.image_path = image_path
        self.plugin_id  = plugin_id
        self.base_dir   = base_dir
        self.yara_file  = yara_file
        self._proc      = None
        self._abort     = False

    def stop(self):
        self._abort = True
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def run(self):
        try:
            self._run()
        except Exception as e:
            msg = f"{type(e).__name__}: {e}\n\n{traceback.format_exc()}"
            log.exception("VolatilityWorker unhandled exception")
            self.error.emit(msg)
            self.finished.emit(1)

    def _run(self):
        symbols_dir = os.path.join(self.base_dir, "symbols")
        os.makedirs(symbols_dir, exist_ok=True)

        env = os.environ.copy()
        # Cross-platform symbol dir env var
        existing = env.get("VOLATILITY_SYMBOL_DIRS", "")
        paths = [p for p in existing.split(os.pathsep) if p]
        if symbols_dir not in paths:
            paths.insert(0, symbols_dir)
        env["VOLATILITY_SYMBOL_DIRS"] = os.pathsep.join(paths)

        # Windows: also set PATHEXT so shutil.which finds .exe/.cmd
        if sys.platform == "win32":
            env.setdefault("PATHEXT", ".exe;.cmd;.bat;.com")

        base_cmd = _find_vol3_cmd()
        cmd = base_cmd + ["-f", os.path.abspath(self.image_path), self.plugin_id]

        if self.yara_file and "yarascan" in self.plugin_id.lower():
            cmd += ["--yara-file", os.path.abspath(self.yara_file)]

        log.info("Running: %s", " ".join(cmd))
        self.output_ready.emit(f"  $  {' '.join(cmd)}")
        self.output_ready.emit("")

        # Windows: hide console window
        creation_flags = 0
        if sys.platform == "win32":
            creation_flags = subprocess.CREATE_NO_WINDOW

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
            creationflags=creation_flags,
        )

        # Stream stdout
        first_lines = []
        for line in self._proc.stdout:
            if self._abort:
                break
            stripped = line.rstrip()
            if stripped:
                self.output_ready.emit(stripped)
                if len(first_lines) < 10:
                    first_lines.append(stripped)

        # Detect OS from early output (banner lines)
        banner_text = " ".join(first_lines)
        detected = detect_os_from_banner(banner_text)
        self.os_detected.emit(detected)
        log.info("OS detected from banner: %s", detected)

        # Emit stderr
        stderr_out = self._proc.stderr.read()
        if stderr_out:
            for line in stderr_out.splitlines():
                s = line.strip()
                if s:
                    log.debug("vol3 stderr: %s", s)
                    self.output_ready.emit(f"  ◌  {s}")

        self._proc.wait()
        rc = self._proc.returncode
        log.info("vol3 exited with code %d", rc)
        self._proc = None
        self.finished.emit(rc)
