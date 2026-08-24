import os
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QComboBox, QTextEdit, QGroupBox, QFileDialog,
    QListWidget, QListWidgetItem, QWidget
)
from ui.theme import restyle
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices
from core.symbol_downloader import SymbolDownloader


class SymbolDialog(QDialog):
    def __init__(self, base_dir: str, parent=None):
        super().__init__(parent)
        self.base_dir = base_dir
        self.symbols_dir = os.path.join(base_dir, "symbols")
        self.yara_dir = os.path.join(base_dir, "yara")
        self._downloader = None
        self.setWindowTitle("Symbols & YARA Manager")
        self.setMinimumSize(600, 500)
        self._build()
        self._refresh_status()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        # ── Symbols ──────────────────────────────────────────────────────────
        sym_grp = QGroupBox("Volatility3 Symbol Tables")
        sym_layout = QVBoxLayout(sym_grp)

        self.sym_status = QLabel("")
        self.sym_status.setWordWrap(True)
        self.sym_status.setObjectName("fieldHint")

        row = QHBoxLayout()
        self.pack_combo = QComboBox()
        self.pack_combo.addItems(["windows", "linux", "mac"])
        self.pack_combo.setFixedWidth(120)

        self.dl_btn = QPushButton("⬇  Download")
        self.dl_btn.setObjectName("primaryBtn")
        self.dl_btn.setFixedWidth(130)
        self.dl_btn.clicked.connect(self._start_download)

        open_btn = QPushButton("📂  Open Folder")
        open_btn.setFixedWidth(130)
        open_btn.clicked.connect(lambda: self._open_dir(self.symbols_dir))

        row.addWidget(QLabel("Pack:"))
        row.addWidget(self.pack_combo)
        row.addSpacing(10)
        row.addWidget(self.dl_btn)
        row.addWidget(open_btn)
        row.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setTextVisible(False)

        self.dl_log = QTextEdit()
        self.dl_log.setReadOnly(True)
        self.dl_log.setMaximumHeight(80)
        self.dl_log.setPlaceholderText("Download log …")

        sym_layout.addWidget(self.sym_status)
        sym_layout.addLayout(row)
        sym_layout.addWidget(self.progress_bar)
        sym_layout.addWidget(self.dl_log)

        # ── YARA ─────────────────────────────────────────────────────────────
        yara_grp = QGroupBox("YARA Rules")
        yara_layout = QVBoxLayout(yara_grp)

        yara_info = QLabel(
            f"Place .yar / .yara rule files in:\n  {self.yara_dir}"
        )
        yara_info.setObjectName("fieldHint")

        yara_btn_row = QHBoxLayout()
        open_yara_btn = QPushButton("📂  Open YARA Folder")
        open_yara_btn.clicked.connect(lambda: self._open_dir(self.yara_dir))
        refresh_yara_btn = QPushButton("🔄  Refresh")
        refresh_yara_btn.clicked.connect(self._refresh_yara)
        yara_btn_row.addWidget(open_yara_btn)
        yara_btn_row.addWidget(refresh_yara_btn)
        yara_btn_row.addStretch()

        self.yara_list = QListWidget()
        self.yara_list.setMaximumHeight(120)
        self.yara_list.setAlternatingRowColors(True)

        yara_layout.addWidget(yara_info)
        yara_layout.addLayout(yara_btn_row)
        yara_layout.addWidget(self.yara_list)

        # ── Close ─────────────────────────────────────────────────────────────
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        close_btn.setFixedWidth(100)

        close_row = QHBoxLayout()
        close_row.addStretch()
        close_row.addWidget(close_btn)

        layout.addWidget(sym_grp)
        layout.addWidget(yara_grp)
        layout.addLayout(close_row)

    def _refresh_status(self):
        os.makedirs(self.symbols_dir, exist_ok=True)
        os.makedirs(self.yara_dir, exist_ok=True)

        packs_found = []
        for root, dirs, files in os.walk(self.symbols_dir):
            for f in files:
                if f.endswith((".zip", ".json", ".json.xz", ".json.gz")):
                    pack = os.path.relpath(root, self.symbols_dir).split(os.sep)[0]
                    if pack and pack not in packs_found:
                        packs_found.append(pack)

        if packs_found:
            self.sym_status.setText(
                f"✓  Installed packs: {', '.join(packs_found)}"
            )
            self.sym_status.setObjectName("hintOk")
            restyle(self.sym_status)
        else:
            self.sym_status.setText(
                "⚠  No symbol packs found. Download at least 'windows' to analyse Windows memory dumps."
            )
            self.sym_status.setObjectName("hintWarn")
            restyle(self.sym_status)

        self._refresh_yara()

    def _refresh_yara(self):
        os.makedirs(self.yara_dir, exist_ok=True)
        self.yara_list.clear()
        rules = [
            f for f in os.listdir(self.yara_dir)
            if f.endswith((".yar", ".yara", ".rule"))
        ]
        if rules:
            for r in sorted(rules):
                self.yara_list.addItem(QListWidgetItem(f"🎯  {r}"))
        else:
            self.yara_list.addItem(
                QListWidgetItem("  No .yar / .yara files found in yara folder.")
            )

    def _start_download(self):
        pack = self.pack_combo.currentText()
        self.dl_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.dl_log.clear()
        self.dl_log.append(f"Starting download: {pack} …")

        self._downloader = SymbolDownloader(self.base_dir, pack, parent=self)
        self._downloader.progress.connect(self.dl_log.append)
        self._downloader.percent.connect(self.progress_bar.setValue)
        self._downloader.done.connect(self._on_download_done)
        self._downloader.start()

    def _on_download_done(self, success: bool, msg: str):
        self.dl_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.dl_log.append("✓  " + msg if success else "✗  " + msg)
        self._refresh_status()
        if self._downloader:
            self._downloader.wait()
            self._downloader = None

    def _open_dir(self, path: str):
        """Show a folder in the system file manager."""
        os.makedirs(path, exist_ok=True)
        # Qt picks the right opener per platform. Spawning `explorer` by hand
        # returns a non-zero exit code even on success and mishandles forward
        # slashes, which is what a path built with os.path.join can contain.
        QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path)))

    def get_yara_files(self) -> list[str]:
        """Return list of full paths to all yara rule files."""
        os.makedirs(self.yara_dir, exist_ok=True)
        return [
            os.path.join(self.yara_dir, f)
            for f in sorted(os.listdir(self.yara_dir))
            if f.endswith((".yar", ".yara", ".rule"))
        ]
