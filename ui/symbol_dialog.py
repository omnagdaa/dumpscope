"""
Symbols & YARA for one case.

Symbols live in the case: `<case>/symbols`. The primary action fetches the
symbol table for the loaded image only (a few megabytes, straight from
Microsoft's symbol server via volatility3); the bulk packs remain for offline
work. volatility3's shared per-user cache is never read or written by a case,
so a case folder carries every symbol table its results depended on.
"""

from __future__ import annotations

import os

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QComboBox, QDialog, QGroupBox, QHBoxLayout, QLabel, QListWidget,
    QListWidgetItem, QProgressBar, QPushButton, QTextEdit, QVBoxLayout,
)

from core.symbol_downloader import SymbolDownloader, SymbolFetcher, list_symbols
from ui.theme import restyle

YARA_SUFFIXES = (".yar", ".yara", ".rule", ".rules")


def _size(count: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if count < 1024:
            return f"{count:.0f} {unit}" if unit == "B" else f"{count:.1f} {unit}"
        count /= 1024
    return f"{count:.1f} TB"


class SymbolDialog(QDialog):
    def __init__(self, base_dir: str, parent=None, image_path: str = "",
                 case_mode: bool = True):
        super().__init__(parent)
        self.base_dir = base_dir
        self.image_path = image_path
        self.case_mode = case_mode
        self.symbols_dir = os.path.join(base_dir, "symbols")
        self.yara_dir = os.path.join(base_dir, "yara")
        self._downloader: SymbolDownloader | None = None
        self._fetcher: SymbolFetcher | None = None
        self.setWindowTitle("Symbols & YARA")
        self.setMinimumSize(700, 660)
        self._build()
        self._refresh_status()

    # ── Construction ──────────────────────────────────────────────────────────

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        sym_grp = QGroupBox("Symbol tables for this case")
        sym_layout = QVBoxLayout(sym_grp)
        where = QLabel(
            f"Stored in {self.symbols_dir}\n"
            "Only this folder is used — volatility3's shared cache is not, so the "
            "case carries every symbol table its results depend on."
            if self.case_mode else
            "Quick Analysis has no case folder, so volatility3's own shared symbol "
            "cache is used.")
        where.setObjectName("fieldHint")
        where.setWordWrap(True)
        where.setMinimumHeight(where.sizeHint().height() + 14)
        self.sym_status = QLabel("")
        self.sym_status.setWordWrap(True)
        self.sym_list = QListWidget()
        self.sym_list.setMaximumHeight(110)
        self.sym_list.setAlternatingRowColors(True)

        fetch_row = QHBoxLayout()
        self.fetch_btn = QPushButton("Fetch Symbols for This Image")
        self.fetch_btn.setObjectName("primaryButton")
        self.fetch_btn.setToolTip(
            "Downloads only the kernel PDB this image needs from Microsoft's "
            "symbol server and converts it into the case. Needs network access.")
        self.fetch_btn.clicked.connect(self._start_fetch)
        self.fetch_btn.setEnabled(self.case_mode and bool(self.image_path)
                                  and os.path.isfile(self.image_path))
        open_btn = QPushButton("Open Folder")
        open_btn.clicked.connect(lambda: self._open_dir(self.symbols_dir))
        open_btn.setEnabled(self.case_mode)
        fetch_row.addWidget(self.fetch_btn)
        fetch_row.addWidget(open_btn)
        fetch_row.addStretch()

        pack_row = QHBoxLayout()
        pack_lbl = QLabel("Offline? Full pack:")
        pack_lbl.setObjectName("fieldHint")
        self.pack_combo = QComboBox()
        self.pack_combo.addItems(["windows", "linux", "mac"])
        self.pack_combo.setFixedWidth(110)
        self.dl_btn = QPushButton("Download Pack")
        self.dl_btn.setToolTip("Every known kernel for that OS. Large: the Windows "
                               "pack runs to gigabytes.")
        self.dl_btn.clicked.connect(self._start_download)
        self.dl_btn.setEnabled(self.case_mode)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setVisible(False)
        self.cancel_btn.clicked.connect(self._cancel)
        pack_row.addWidget(pack_lbl)
        pack_row.addWidget(self.pack_combo)
        pack_row.addWidget(self.dl_btn)
        pack_row.addStretch()
        pack_row.addWidget(self.cancel_btn)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setTextVisible(False)
        self.dl_log = QTextEdit()
        self.dl_log.setReadOnly(True)
        self.dl_log.setMinimumHeight(70)
        self.dl_log.setMaximumHeight(110)
        self.dl_log.setPlaceholderText("Activity…")

        for widget in (where, self.sym_status, self.sym_list):
            sym_layout.addWidget(widget)
        sym_layout.addLayout(fetch_row)
        sym_layout.addLayout(pack_row)
        sym_layout.addWidget(self.progress_bar)
        sym_layout.addWidget(self.dl_log)

        yara_grp = QGroupBox("YARA rules")
        yara_layout = QVBoxLayout(yara_grp)
        yara_info = QLabel(f"Rule files (.yar, .yara) in {self.yara_dir} are used "
                           "by YARA Scan.")
        yara_info.setObjectName("fieldHint")
        yara_info.setWordWrap(True)
        yara_row = QHBoxLayout()
        open_yara_btn = QPushButton("Open YARA Folder")
        open_yara_btn.clicked.connect(lambda: self._open_dir(self.yara_dir))
        refresh_yara_btn = QPushButton("Refresh")
        refresh_yara_btn.clicked.connect(self._refresh_yara)
        yara_row.addWidget(open_yara_btn)
        yara_row.addWidget(refresh_yara_btn)
        yara_row.addStretch()
        self.yara_list = QListWidget()
        self.yara_list.setMaximumHeight(90)
        self.yara_list.setAlternatingRowColors(True)
        yara_layout.addWidget(yara_info)
        yara_layout.addLayout(yara_row)
        yara_layout.addWidget(self.yara_list)

        close_row = QHBoxLayout()
        close_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setFixedWidth(100)
        close_btn.clicked.connect(self.accept)
        close_row.addWidget(close_btn)

        layout.addWidget(sym_grp)
        layout.addWidget(yara_grp)
        layout.addLayout(close_row)

    # ── Status ────────────────────────────────────────────────────────────────

    def _refresh_status(self):
        self.sym_list.clear()
        found = list_symbols(self.base_dir) if self.case_mode else []
        for path, size in found:
            self.sym_list.addItem(QListWidgetItem(f"{path}    {_size(size)}"))
        self.sym_list.setVisible(bool(found))
        if found:
            total = sum(size for _, size in found)
            self.sym_status.setText(f"{len(found)} symbol table(s), {_size(total)}.")
            self.sym_status.setObjectName("hintOk")
        elif self.case_mode:
            self.sym_status.setText(
                "No symbol tables yet. Fetch the ones this image needs, or load "
                "the image and run a plugin — volatility3 fetches them into the "
                "case automatically when it has network access.")
            self.sym_status.setObjectName("hintWarn")
        else:
            self.sym_status.setText("")
        restyle(self.sym_status)
        self._refresh_yara()

    def _refresh_yara(self):
        self.yara_list.clear()
        rules = []
        if os.path.isdir(self.yara_dir):
            rules = sorted(f for f in os.listdir(self.yara_dir)
                           if f.lower().endswith(YARA_SUFFIXES))
        for rule in rules:
            self.yara_list.addItem(QListWidgetItem(rule))
        if not rules:
            self.yara_list.addItem(QListWidgetItem("No rule files in the yara folder."))

    def _busy(self, busy: bool):
        self.fetch_btn.setEnabled(not busy and self.case_mode and bool(self.image_path)
                                  and os.path.isfile(self.image_path))
        self.dl_btn.setEnabled(not busy and self.case_mode)
        self.cancel_btn.setVisible(busy)
        self.progress_bar.setVisible(busy)

    # ── Fetch for this image ──────────────────────────────────────────────────

    def _start_fetch(self):
        self._busy(True)
        self.progress_bar.setRange(0, 0)              # indeterminate
        self.dl_log.clear()
        self._fetcher = SymbolFetcher(self.image_path, self.base_dir, parent=self)
        self._fetcher.progress.connect(self.dl_log.append)
        self._fetcher.done.connect(self._on_fetch_done)
        self._fetcher.start()

    def _on_fetch_done(self, ok: bool, message: str, added: list):
        self.progress_bar.setRange(0, 100)
        self._busy(False)
        self.dl_log.append(("✓ " if ok else "✗ ") + message)
        for path in added:
            self.dl_log.append(f"  + {path}")
        if self._fetcher is not None:
            self._fetcher.wait(2000)
            self._fetcher = None
        self._refresh_status()

    # ── Full pack ─────────────────────────────────────────────────────────────

    def _start_download(self):
        pack = self.pack_combo.currentText()
        self._busy(True)
        self.progress_bar.setValue(0)
        self.dl_log.clear()
        self.dl_log.append(f"Starting download: {pack}…")
        self._downloader = SymbolDownloader(self.base_dir, pack, parent=self)
        self._downloader.progress.connect(self.dl_log.append)
        self._downloader.percent.connect(self.progress_bar.setValue)
        self._downloader.done.connect(self._on_download_done)
        self._downloader.start()

    def _on_download_done(self, success: bool, msg: str):
        self._busy(False)
        self.dl_log.append(("✓ " if success else "✗ ") + msg)
        if self._downloader:
            self._downloader.wait(2000)
            self._downloader = None
        self._refresh_status()

    def _cancel(self):
        for worker in (self._fetcher, self._downloader):
            if worker is not None:
                worker.cancel()

    def closeEvent(self, event):
        self._cancel()
        for worker in (self._fetcher, self._downloader):
            if worker is not None:
                worker.wait(5000)
        super().closeEvent(event)

    def _open_dir(self, path: str):
        os.makedirs(path, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path)))

    def get_yara_files(self) -> list[str]:
        if not os.path.isdir(self.yara_dir):
            return []
        return [os.path.join(self.yara_dir, f) for f in sorted(os.listdir(self.yara_dir))
                if f.lower().endswith(YARA_SUFFIXES)]
