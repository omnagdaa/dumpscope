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

from PyQt6.QtCore import Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QApplication, QDialog, QFileDialog, QFrame, QHBoxLayout, QInputDialog,
    QLabel, QListWidget,
    QListWidgetItem, QMenu, QMessageBox, QPushButton, QStackedWidget,
    QVBoxLayout, QWidget,
)

from ui.theme import build as build_theme
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
        # The launcher opens before any main window exists, so nothing else has
        # set an application stylesheet yet — without this the first screen an
        # examiner sees is the only unthemed one in the application.
        QApplication.instance().setStyleSheet(build_theme(dark=self.is_dark))

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

        # The list and its empty state share one slot, so the heading stays
        # pinned to the top whichever is showing. Hiding the list outright
        # let the layout float the heading to the middle of the pane.
        self.recent_stack = QStackedWidget()
        self.recent_stack.addWidget(self.recent_list)
        self.recent_stack.addWidget(self._build_empty_state())
        layout.addWidget(self.recent_stack, 1)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setFixedHeight(1)
        divider.setObjectName("launcherDivider")
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

    def _build_empty_state(self) -> QWidget:
        card = QFrame()
        card.setObjectName("launcherEmpty")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(10)
        layout.addStretch()

        title = QLabel("No cases yet")
        title.setObjectName("launcherEmptyTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.empty_lbl = QLabel(
            "Create a case to keep results, bookmarks, extracted files and an "
            "audit trail together in one folder. Or start a Quick Analysis to "
            "look at an image without saving anything."
        )
        self.empty_lbl.setWordWrap(True)
        self.empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_lbl.setObjectName("launcherEmptyText")

        create = QPushButton("Create your first case")
        create.setObjectName("primaryButton")
        create.setFixedHeight(36)
        create.clicked.connect(self._new_case)
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(create)
        row.addStretch()

        layout.addWidget(title)
        layout.addWidget(self.empty_lbl)
        layout.addSpacing(8)
        layout.addLayout(row)
        layout.addStretch()
        return card

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
        self.recent_stack.setCurrentIndex(0 if has_entries else 1)

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
        """Show a case folder in the system file manager."""
        QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(directory)))

    # ── Actions ───────────────────────────────────────────────────────────────

    def _new_case(self):
        """
        Create a case and go straight to it.

        This used to open a three-page wizard to collect a case number, an
        examiner and notes before anything could be looked at. None of that is
        needed to start work, and asking for it up front means typing details
        about an image nobody has opened yet. A case needs a name and a folder;
        everything else is edited in the Case tab of the main window, next to
        the evidence it describes.
        """
        name, ok = QInputDialog.getText(
            self, "New Case", "Case name:", text="Case 1"
        )
        if not ok or not name.strip():
            return

        parent_dir = QFileDialog.getExistingDirectory(
            self, f"Where should “{name.strip()}” be created?",
            os.path.expanduser("~"),
        )
        if not parent_dir:
            return

        try:
            case = Case.create(parent_dir, name.strip())
        except CaseError as exc:
            QMessageBox.critical(self, "Could Not Create Case", str(exc))
            return
        remember_case(case)
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
