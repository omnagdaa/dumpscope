"""
Working out what an image is, before anything is run against it.

The previous probe ran ``banners.Banners`` and treated "no banner" as failure.
That is backwards for the case this tool is mostly used on: ``banners`` only
ever finds *Linux and Mac* kernel banners, so on a Windows image it is
guaranteed to find nothing, scanning the entire file to prove it. Windows was
therefore never actually detected — it was the hardcoded default that happened
to be right, and the status bar said the detection had failed while showing the
correct answer.

Detection here is three-tier, cheapest first:

1. ``sniff_header`` — a few bytes off the front of the file. Crash dumps,
   hibernation files, ELF cores, LiME captures and VMware snapshots all
   announce themselves in their first 8 bytes. Instant, no subprocess.
2. ``windows.info.Info`` — fast on a Windows image (it walks to the KDBG
   directly) and returns the build, kernel base and capture time, which is
   worth having anyway.
3. ``banners.Banners`` — the slow full scan, only for images that are not
   Windows.

The result carries a confidence, because "this file starts with PAGEDU64" and
"nothing else matched" are not the same claim and the UI should not present
them as if they were.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass, field

from PyQt6.QtCore import QThread, pyqtSignal

from core.vol_runner import (
    RUN_GATE, _creation_flags, awaiting_case_symbols, build_environment, case_symbol_args,
    detect_os_from_banner, find_vol3_command,
)

log = logging.getLogger("dumpscope.os_detect")

SUPPORTED = ("windows", "linux", "mac")

# Signatures found at offset 0. Everything here is a container format that
# states its own type; a plain `.raw` / `.mem` dump matches none of them.
_MAGIC = (
    (b"PAGEDU64", "windows", "64-bit Windows crash dump"),
    (b"PAGEDUMP", "windows", "32-bit Windows crash dump"),
    (b"HIBR",     "windows", "Windows hibernation file"),
    (b"hibr",     "windows", "Windows hibernation file"),
    (b"WAKE",     "windows", "Windows hibernation file (resumed)"),
    (b"\x7fELF",  "linux",   "ELF core dump"),
    (b"EMiL",     "linux",   "LiME capture"),
)

# VMware suspend/snapshot containers. Little-endian magic in the first word.
_VMWARE_MAGIC = (b"\xd2\xbe\xd2\xbe", b"\xd1\xba\xd1\xba", b"\xd0\xba\xd0\xba")


@dataclass
class ImageProfile:
    """What we concluded about an image, and how sure we are."""

    os: str = ""
    confidence: str = "unknown"      # certain | likely | assumed | unknown
    method: str = ""                 # human-readable, shown in the UI
    container: str = ""              # crash dump, LiME, raw, …
    details: dict = field(default_factory=dict)   # windows.info key/value pairs

    @property
    def is_confident(self) -> bool:
        return self.confidence in ("certain", "likely")

    def summary(self) -> str:
        if not self.os:
            return "Unidentified image"
        name = {"windows": "Windows", "linux": "Linux", "mac": "macOS"}.get(
            self.os, self.os.title())
        qualifier = {
            "certain": "", "likely": " (likely)", "assumed": " (assumed)",
        }.get(self.confidence, "")
        return f"{name}{qualifier} — {self.method}" if self.method else f"{name}{qualifier}"


def sniff_header(path: str) -> ImageProfile:
    """
    Identify an image from its first bytes. Returns an empty-OS profile when
    the file is a raw dump, which carries no signature at all.
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(16)
    except OSError as exc:
        log.debug("Could not read the header of %s: %s", path, exc)
        return ImageProfile()

    for magic, os_name, container in _MAGIC:
        if head.startswith(magic):
            return ImageProfile(
                os=os_name, confidence="certain",
                method=f"{container} signature", container=container,
            )

    if any(head.startswith(magic) for magic in _VMWARE_MAGIC):
        # The container is identified but says nothing about the guest OS.
        return ImageProfile(container="VMware snapshot")

    return ImageProfile(container="raw memory dump")


def _run_vol(command: list[str], symbol_dirs: list[str], timeout: int):
    """Run a vol3 command to completion. Returns (returncode, stdout, stderr)."""
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=build_environment(symbol_dirs), creationflags=_creation_flags(),
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    return proc.returncode, stdout or "", stderr or ""


def parse_info_rows(stdout: str) -> dict:
    """
    Turn ``windows.info.Info`` CSV output into a dict.

    The plugin emits one Variable/Value pair per row; only the handful worth
    putting in front of an examiner is kept, in a fixed order.
    """
    import csv
    import io

    wanted = {
        "Kernel Base": "Kernel Base",
        "DTB": "DTB",
        "Is64Bit": "64-bit",
        "IsPAE": "PAE",
        "NtMajorVersion": "NT Major",
        "NtMinorVersion": "NT Minor",
        "NtProductType": "Product",
        "NTBuildLab": "Build Lab",
        "PrimaryProcessor": "Processor",
        "NumberOfProcessors": "Processors",
        "SystemTime": "Capture Time",
        "Major/Minor": "Major/Minor",
        "MachineType": "Machine Type",
        "KdVersionBlock": "KdVersionBlock",
    }
    out: dict[str, str] = {}
    try:
        reader = csv.reader(io.StringIO(stdout))
        header = next(reader, None)
        if not header:
            return out
        try:
            key_col = header.index("Variable")
            value_col = header.index("Value")
        except ValueError:
            return out
        for row in reader:
            if len(row) <= max(key_col, value_col):
                continue
            label = wanted.get(row[key_col].strip())
            if label:
                out[label] = row[value_col].strip()
    except csv.Error as exc:
        log.debug("windows.info output could not be parsed: %s", exc)
    return out


class ImageProbe(QThread):
    """
    Identifies an image in the background.

    Emits `sniffed` almost immediately with the header verdict so the UI can
    commit to a plugin set without waiting, then `profiled` once volatility3
    has confirmed it and collected the image details.
    """

    sniffed  = pyqtSignal(object)     # ImageProfile — header only, may have os=""
    profiled = pyqtSignal(object)     # ImageProfile — final
    note     = pyqtSignal(str)        # progress text for the status bar

    INFO_TIMEOUT = 180
    BANNER_TIMEOUT = 300

    def __init__(self, image_path: str, symbol_dirs: list[str] | None = None,
                 parent=None, cache_dir: str = ""):
        super().__init__(parent)
        self.image_path = image_path
        self.symbol_dirs = symbol_dirs or []
        # With case symbol folders, windows.info is also what fetches this
        # image's kernel PDB: vol3 downloads it and writes the ISF into the
        # first symbol folder, which is the case's.
        self.cache_dir = cache_dir
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

    # ── The probe ─────────────────────────────────────────────────────────────

    def run(self):
        path = os.path.abspath(self.image_path)
        header = sniff_header(path)
        self.sniffed.emit(header)

        if self._cancelled:
            return

        # A container signature is conclusive about the OS. Still ask
        # windows.info for the details, but never let it overturn the verdict.
        if header.os == "windows":
            # windows.info is asked for the build details, but it must not
            # overturn the header: "PAGEDU64 at offset 0" is a stronger claim
            # than "vol3 could not find symbols for this kernel", and letting
            # the weaker one win downgraded a certain answer to a guess.
            confirmed = self._probe_windows(path)
            if confirmed is not None:
                header.details = confirmed.details
                if confirmed.details:
                    header.method = f"{header.method}, confirmed by windows.info"
            self.profiled.emit(header)
            return
        if header.os in ("linux", "mac"):
            self.profiled.emit(header)
            return

        # Raw image. Windows first: it is both the common case and the fast one.
        self.note.emit("Checking whether this is a Windows image…")
        windows = self._probe_windows(path)
        if self._cancelled:
            return
        if windows is not None:
            windows.container = header.container
            self.profiled.emit(windows)
            return

        self.note.emit("Scanning for a Linux or Mac kernel banner…")
        banner = self._probe_banners(path)
        if self._cancelled:
            return
        if banner is not None:
            banner.container = header.container
            self.profiled.emit(banner)
            return

        # Nothing identified it. Windows remains the best available guess —
        # banners would have found a Linux or Mac image — but say so plainly
        # rather than presenting a guess as a detection.
        self.profiled.emit(ImageProfile(
            os="windows", confidence="assumed",
            method="no Linux or Mac kernel found; Windows assumed",
            container=header.container,
        ))

    def _probe_windows(self, path: str) -> ImageProfile | None:
        command = find_vol3_command() + case_symbol_args(
            self.symbol_dirs, self.cache_dir) + [
            "-q", "-r", "csv", "-f", path, "windows.info.Info",
        ]
        try:
            code, stdout, stderr = self._guarded(command, self.INFO_TIMEOUT)
        except subprocess.TimeoutExpired:
            log.info("windows.info timed out on %s", path)
            return None
        except Exception as exc:
            log.warning("windows.info could not be run: %s", exc)
            return None

        if code == 0 and stdout.strip():
            details = parse_info_rows(stdout)
            return ImageProfile(
                os="windows", confidence="certain",
                method="confirmed by windows.info", details=details,
            )

        # A missing symbol table means the image *was* recognised as Windows;
        # vol3 got far enough to look for symbols for a specific kernel build.
        lowered = stderr.lower()
        if "symbol" in lowered and ("table" in lowered or "isf" in lowered):
            return ImageProfile(
                os="windows", confidence="likely",
                method="Windows kernel found, but its symbols are missing",
            )
        return None

    def _probe_banners(self, path: str) -> ImageProfile | None:
        command = find_vol3_command() + case_symbol_args(
            self.symbol_dirs, self.cache_dir) + [
            "-q", "-r", "csv", "-f", path, "banners.Banners",
        ]
        try:
            _code, stdout, _stderr = self._guarded(command, self.BANNER_TIMEOUT)
        except subprocess.TimeoutExpired:
            log.info("Banner scan timed out on %s", path)
            return None
        except Exception as exc:
            log.warning("Banner scan could not be run: %s", exc)
            return None

        guess = detect_os_from_banner(stdout)
        if guess in ("linux", "mac"):
            return ImageProfile(
                os=guess, confidence="certain", method="kernel banner found",
            )
        return None

    def _guarded(self, command: list[str], timeout: int):
        """
        Run a command, keeping a handle on it so `cancel` can stop it.

        Queues on the shared RunGate like any plugin run: the probe is a vol3
        process too, and it touches the same caches.
        """
        if not RUN_GATE.acquire(cancelled=lambda: self._cancelled,
                                solo=lambda: awaiting_case_symbols(self.symbol_dirs)):
            raise RuntimeError("cancelled while queued")
        for folder in [self.cache_dir, *self.symbol_dirs]:
            if folder:
                os.makedirs(folder, exist_ok=True)
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=build_environment(self.symbol_dirs), creationflags=_creation_flags(),
            )
            self._proc = proc
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise
            finally:
                self._proc = None
            return proc.returncode, stdout or "", stderr or ""
        finally:
            RUN_GATE.release()
