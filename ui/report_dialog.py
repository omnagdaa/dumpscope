"""
Generate Report: choose what goes in the report folder, then watch it build.

The work runs on a thread because a report folder can include gigabytes of
process dumps that all have to be hashed into the manifest. The Database opens
a fresh SQLite connection per call, so reading it from the worker is safe.
"""

from __future__ import annotations

import os

from PyQt6.QtCore import QThread, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QButtonGroup, QCheckBox, QDialog, QGroupBox, QHBoxLayout, QLabel, QLayout,
    QProgressBar, QPushButton, QRadioButton, QVBoxLayout,
)

from core.report_bundle import (
    BundleCancelled, BundleOptions, BundleResult, build_bundle, bundle_dirname,
)


class ReportWorker(QThread):
    progress = pyqtSignal(int, str)
    succeeded = pyqtSignal(object)            # BundleResult
    failed = pyqtSignal(str)
    cancelled = pyqtSignal()

    def __init__(self, case, db, options: BundleOptions, parent=None):
        super().__init__(parent)
        self.case = case
        self.db = db
        self.options = options
        self._stop = False

    def cancel(self):
        self._stop = True

    def run(self):
        try:
            result = build_bundle(
                self.case, self.db, options=self.options,
                progress=lambda pct, msg: self.progress.emit(pct, msg),
                cancelled=lambda: self._stop,
            )
        except BundleCancelled:
            self.cancelled.emit()
        except Exception as exc:          # reported in the dialog, never lost
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        else:
            self.succeeded.emit(result)


class ReportDialog(QDialog):
    """Emits `generated(BundleResult)` once a report folder is complete."""

    generated = pyqtSignal(object)

    def __init__(self, case, db, settings: dict | None = None, parent=None):
        super().__init__(parent)
        self.case = case
        self.db = db
        self.settings = settings or {}
        self.worker: ReportWorker | None = None
        self.result: BundleResult | None = None
        self.setWindowTitle("Generate Case Report")
        self.setMinimumWidth(620)
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        # Wrapped labels (the folder path, the result summary) grow after the
        # dialog has sized itself; without this they squeeze the option groups.
        layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(12)

        heading = QLabel("Generate Case Report")
        heading.setObjectName("dialogHeading")
        blurb = QLabel(
            "Writes a self-contained report folder inside the case: the HTML "
            "report with insights and the incident timeline, every analysis "
            "result as CSV, the extracted files, and a SHA-256 manifest of it all.")
        blurb.setObjectName("dialogBlurb")
        blurb.setWordWrap(True)
        target = os.path.join(self.case.directory, "reports",
                              bundle_dirname(self.case.case_name))
        self.target_lbl = QLabel(f"Folder:  {target}")
        self.target_lbl.setObjectName("reportOption")
        self.target_lbl.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(blurb)
        layout.addWidget(self.target_lbl)

        dumps = QGroupBox("Extracted files (dumps)")
        dumps_layout = QVBoxLayout(dumps)
        dumps_layout.setSpacing(8)
        self.dump_group = QButtonGroup(self)
        self.link_radio = QRadioButton("Include — hard-link when possible (no extra disk space)")
        self.copy_radio = QRadioButton("Include — always copy (a fully independent folder)")
        self.none_radio = QRadioButton("Leave out (list them in the report only)")
        for mode, radio in (("link", self.link_radio), ("copy", self.copy_radio),
                            ("none", self.none_radio)):
            radio.setProperty("mode", mode)
            self.dump_group.addButton(radio)
            dumps_layout.addWidget(radio)
        self.link_radio.setChecked(True)
        layout.addWidget(dumps)

        content = QGroupBox("Report content")
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(8)
        self.output_check = QCheckBox("Reproduce analysis output in the HTML (first 200 rows per run)")
        self.output_check.setChecked(bool(self.settings.get("report_include_output", True)))
        self.audit_check = QCheckBox("Include the audit trail")
        self.audit_check.setChecked(True)
        content_layout.addWidget(self.output_check)
        content_layout.addWidget(self.audit_check)
        layout.addWidget(content)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(8)
        self.status_lbl = QLabel("")
        self.status_lbl.setObjectName("reportOption")
        self.status_lbl.setWordWrap(True)
        layout.addWidget(self.progress)
        layout.addWidget(self.status_lbl)

        buttons = QHBoxLayout()
        self.open_folder_btn = QPushButton("Open Folder")
        self.open_folder_btn.setVisible(False)
        self.open_folder_btn.clicked.connect(self._open_folder)
        self.open_btn = QPushButton("Open Report")
        self.open_btn.setVisible(False)
        self.open_btn.clicked.connect(self._open_report)
        buttons.addWidget(self.open_folder_btn)
        buttons.addWidget(self.open_btn)
        buttons.addStretch()
        self.close_btn = QPushButton("Cancel")
        self.close_btn.clicked.connect(self._close_or_cancel)
        self.generate_btn = QPushButton("Generate")
        self.generate_btn.setObjectName("primaryButton")
        self.generate_btn.setDefault(True)
        self.generate_btn.clicked.connect(self.start)
        buttons.addWidget(self.close_btn)
        buttons.addWidget(self.generate_btn)
        layout.addLayout(buttons)

    def options(self) -> BundleOptions:
        checked = self.dump_group.checkedButton()
        return BundleOptions(
            dump_mode=checked.property("mode") if checked else "link",
            include_output=self.output_check.isChecked(),
            include_audit=self.audit_check.isChecked(),
        )

    def start(self):
        if self.worker is not None:
            return
        for widget in (self.link_radio, self.copy_radio, self.none_radio,
                       self.output_check, self.audit_check, self.generate_btn):
            widget.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.status_lbl.setText("Starting…")
        self.worker = ReportWorker(self.case, self.db, self.options(), parent=self)
        self.worker.progress.connect(self._on_progress)
        self.worker.succeeded.connect(self._on_done)
        self.worker.failed.connect(self._on_failed)
        self.worker.cancelled.connect(self._on_cancelled)
        self.worker.start()

    def _on_progress(self, pct: int, message: str):
        self.progress.setValue(max(0, min(100, pct)))
        self.status_lbl.setText(message)

    def _finish_worker(self):
        if self.worker is not None:
            self.worker.wait(5000)
            self.worker = None

    def _on_done(self, result: BundleResult):
        self._finish_worker()
        self.result = result
        self.progress.setValue(100)
        dumps = result.dumps_linked + result.dumps_copied
        lines = [f"Report written to {result.path}",
                 f"{result.files} files · {result.insights} insights · "
                 f"{result.events:,} timeline events · {dumps} dump(s)"
                 + (f" ({result.dumps_linked} linked, {result.dumps_copied} copied)"
                    if dumps else "")]
        if result.dumps_missing:
            lines.append(f"{len(result.dumps_missing)} recorded dump(s) were no longer on disk.")
        lines += result.warnings[:5]
        self.status_lbl.setText("\n".join(lines))
        self.open_btn.setVisible(True)
        self.open_folder_btn.setVisible(True)
        self.close_btn.setText("Close")
        self.adjustSize()
        self.generated.emit(result)

    def _on_failed(self, message: str):
        self._finish_worker()
        self.progress.setVisible(False)
        self.status_lbl.setText(f"The report could not be written:\n{message}")
        self.close_btn.setText("Close")
        self.generate_btn.setEnabled(True)

    def _on_cancelled(self):
        self._finish_worker()
        self.progress.setVisible(False)
        self.status_lbl.setText("Cancelled — nothing was left behind.")
        self.close_btn.setText("Close")

    def _close_or_cancel(self):
        if self.worker is not None:
            self.status_lbl.setText("Stopping…")
            self.worker.cancel()
            return
        self.accept() if self.result else self.reject()

    def closeEvent(self, event):
        if self.worker is not None:
            self.worker.cancel()
            self.worker.wait(10000)
        super().closeEvent(event)

    def _open_report(self):
        if self.result:
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.result.index))

    def _open_folder(self):
        if self.result:
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.result.path))
