"""
The launcher: pick up an existing investigation or start a new one.

This is the screen the app opens on, and it exists because the previous flow
had no way back into a case. Every launch pushed you through the new-case
wizard, which meant work done yesterday could only be reached by pointing a
fresh "new case" at the same folder — the behaviour that produced duplicate
case rows in the first place.
"""

from __future__ import annotations

import os
from datetime import datetime

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QDialog, QFileDialog, QFrame, QHBoxLayout, QLabel, QListWidget,
    QListWidgetItem, QMenu, QMessageBox, QPushButton, QVBoxLayout, QWidget,
)

from core.case import Case, CaseError, forget_case, load_recent, remember_case


def _friendly_time(stamp: str) -> str:
    """Render an ISO timestamp as something an analyst reads at a glance."""
    if not stamp:
        return ""
    try:
        moment = datetime.fromisoformat(stamp)
    except ValueError:
        return stamp
    if moment.tzinfo is not None:
        moment = moment.astimezone()
    delta = datetime.now(moment.tzinfo).replace(tzinfo=moment.tzinfo) - moment
    seconds = delta.total_seconds()
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)} h ago"
    if seconds < 604800:
        return f"{int(seconds // 86400)} d ago"
    return moment.strftime("%Y-%m-%d")


class CaseManager(QDialog):
    """
    Returns a Case through `selected_case` once accepted.

    Three ways in: create one (hands off to the wizard), open a case folder
    from disk, or pick one off the recent list. Quick Analysis is offered too,
    for the times an image needs a look with no case around it.
    """

    case_chosen = pyqtSignal(object)

    def __init__(self, is_dark: bool = True, parent=None):
        super().__init__(parent)
        self.is_dark = is_dark
        self.selected_case: Case | None = None
        self.setWindowTitle("DumpScope — Cases")
        self.setMinimumSize(880, 560)
        self._build()
        self._load_recent()

    # ── Construction ──────────────────────────────────────────────────────────

    def _build(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_sidebar())
        root.addWidget(self._build_recent_panel(), 1)

    def _build_sidebar(self) -> QWidget:
        panel = QWidget()
        panel.setObjectName("launcherSidebar")
        panel.setFixedWidth(280)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(28, 32, 24, 24)
        layout.setSpacing(12)

        logo = QLabel("DumpScope")
        logo.setObjectName("launcherLogo")
        tagline = QLabel("Memory forensics")
        tagline.setObjectName("launcherTagline")

        layout.addWidget(logo)
        layout.addWidget(tagline)
        layout.addSpacing(28)

        new_btn = QPushButton("New Case")
        new_btn.setObjectName("primaryButton")
        new_btn.setFixedHeight(40)
        new_btn.clicked.connect(self._new_case)

        open_btn = QPushButton("Open Case Folder…")
        open_btn.setFixedHeight(36)
        open_btn.clicked.connect(self._open_case_folder)

        quick_btn = QPushButton("Quick Analysis")
        quick_btn.setFixedHeight(36)
        quick_btn.setToolTip(
            "Examine an image without creating a case.\n"
            "Nothing is saved: no results, bookmarks or audit trail."
        )
        quick_btn.clicked.connect(self._quick_analysis)

        layout.addWidget(new_btn)
        layout.addWidget(open_btn)
        layout.addWidget(quick_btn)
        layout.addStretch()

        hint = QLabel("A case is a folder. Move it, copy it, archive it — "
                      "everything travels with it.")
        hint.setWordWrap(True)
        hint.setObjectName("launcherHint")
        layout.addWidget(hint)
        return panel

    def _build_recent_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(28, 30, 28, 24)
        layout.setSpacing(12)

        heading = QLabel("Recent Cases")
        heading.setObjectName("launcherHeading")
        layout.addWidget(heading)

        self.recent_list = QListWidget()
        self.recent_list.setObjectName("recentList")
        self.recent_list.setAlternatingRowColors(True)
        self.recent_list.itemActivated.connect(self._open_selected)
        self.recent_list.itemDoubleClicked.connect(self._open_selected)
        self.recent_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.recent_list.customContextMenuRequested.connect(self._recent_menu)
        layout.addWidget(self.recent_list, 1)

        self.empty_lbl = QLabel(
            "No cases yet. Create one to start keeping results, bookmarks "
            "and an audit trail."
        )
        self.empty_lbl.setWordWrap(True)
        self.empty_lbl.setObjectName("launcherHint")
        layout.addWidget(self.empty_lbl)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setFixedHeight(1)
        layout.addWidget(divider)

        buttons = QHBoxLayout()
        buttons.addStretch()
        self.open_btn = QPushButton("Open")
        self.open_btn.setObjectName("primaryButton")
        self.open_btn.setFixedWidth(110)
        self.open_btn.setEnabled(False)
        self.open_btn.clicked.connect(self._open_selected)
        buttons.addWidget(self.open_btn)
        layout.addLayout(buttons)

        self.recent_list.itemSelectionChanged.connect(
            lambda: self.open_btn.setEnabled(bool(self.recent_list.selectedItems()))
        )
        return panel

    # ── Recent list ───────────────────────────────────────────────────────────

    def _load_recent(self):
        self.recent_list.clear()
        entries = load_recent()
        for entry in entries:
            label = entry.get("case_name", "Untitled")
            number = entry.get("case_number", "")
            if number and number != "N/A":
                label += f"   [{number}]"
            detail = entry["directory"]
            when = _friendly_time(entry.get("last_opened", ""))
            item = QListWidgetItem(f"{label}\n{detail}")
            item.setData(Qt.ItemDataRole.UserRole, entry["directory"])
            item.setToolTip(f"{detail}\nLast opened: {when}" if when else detail)
            if when:
                item.setText(f"{label}     ·  {when}\n{detail}")
            self.recent_list.addItem(item)

        has_entries = bool(entries)
        self.recent_list.setVisible(has_entries)
        self.empty_lbl.setVisible(not has_entries)

    def _recent_menu(self, point):
        item = self.recent_list.itemAt(point)
        if item is None:
            return
        directory = item.data(Qt.ItemDataRole.UserRole)
        menu = QMenu(self)
        menu.addAction("Open", self._open_selected)
        menu.addAction("Open Containing Folder", lambda: self._reveal(directory))
        menu.addSeparator()
        menu.addAction(
            "Remove from Recent",
            lambda: (forget_case(directory), self._load_recent()),
        )
        menu.exec(self.recent_list.viewport().mapToGlobal(point))

    @staticmethod
    def _reveal(directory: str):
        import subprocess
        import sys
        try:
            if sys.platform == "linux":
                subprocess.Popen(["xdg-open", directory])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", directory])
            else:
                subprocess.Popen(["explorer", os.path.normpath(directory)])
        except OSError:
            pass

    # ── Actions ───────────────────────────────────────────────────────────────

    def _new_case(self):
        from ui.wizard import CaseWizard
        wizard = CaseWizard(parent=self)
        if wizard.exec() != QDialog.DialogCode.Accepted:
            return
        case = wizard.get_case()
        if case is None:
            return
        self._accept_case(case)

    def _open_case_folder(self):
        directory = QFileDialog.getExistingDirectory(
            self, "Open Case Folder", os.path.expanduser("~")
        )
        if not directory:
            return
        self._open_directory(directory)

    def _open_selected(self, *_):
        items = self.recent_list.selectedItems()
        if not items:
            return
        self._open_directory(items[0].data(Qt.ItemDataRole.UserRole))

    def _open_directory(self, directory: str):
        try:
            case = Case.open(directory)
        except CaseError as exc:
            answer = QMessageBox.question(
                self, "Not a Case Folder",
                f"{exc}\n\nRemove it from the recent list?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer == QMessageBox.StandardButton.Yes:
                forget_case(directory)
                self._load_recent()
            return
        remember_case(case)
        self._accept_case(case)

    def _quick_analysis(self):
        self._accept_case(Case.quick())

    def _accept_case(self, case: Case):
        case.is_dark = self.is_dark
        self.selected_case = case
        self.case_chosen.emit(case)
        self.accept()
