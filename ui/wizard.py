import os
from datetime import datetime
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QStackedWidget, QWidget, QFileDialog,
    QTextEdit, QGroupBox, QGridLayout, QFrame, QProgressBar,
    QApplication, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QMimeData
from PyQt6.QtGui import (
    QDragEnterEvent, QDropEvent, QFont, QIcon, QPainter, QPalette, QColor,
)
from PyQt6.QtWidgets import QStyle, QStyleOption
from ui.theme import build as build_theme, restyle
from core.case import Case, CaseError, remember_case
from core.hash_worker import HashWorker


class StepIndicator(QWidget):
    def __init__(self, steps, parent=None):
        super().__init__(parent)
        self.steps = steps
        self.current = 0
        self._build()

    def _build(self):
        layout = QHBoxLayout(self)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.circles = []
        self.labels = []
        for i, name in enumerate(self.steps):
            col = QVBoxLayout()
            col.setAlignment(Qt.AlignmentFlag.AlignHCenter)

            circle = QLabel(str(i + 1))
            circle.setFixedSize(32, 32)
            circle.setAlignment(Qt.AlignmentFlag.AlignCenter)
            circle.setObjectName("stepCircle")
            self.circles.append(circle)

            lbl = QLabel(name)
            lbl.setObjectName("stepLabel")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.labels.append(lbl)

            col.addWidget(circle)
            col.addWidget(lbl)

            layout.addLayout(col)

            if i < len(self.steps) - 1:
                line = QFrame()
                line.setFrameShape(QFrame.Shape.HLine)
                line.setFixedHeight(2)
                line.setObjectName("stepLine")
                line.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                layout.addWidget(line)

    def _state(self, idx: str) -> str:
        if idx < self.current:
            return "done"
        return "active" if idx == self.current else "pending"

    def set_step(self, idx):
        """
        Colour is a property here, not an inline stylesheet: the steps have to
        follow the theme, and an inline sheet outranks the application one.
        """
        self.current = idx
        for i, circle in enumerate(self.circles):
            state = self._state(i)
            circle.setProperty("state", state)
            restyle(circle)
            self.labels[i].setProperty("state", state)
            restyle(self.labels[i])


class DropZone(QWidget):
    file_dropped = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setMinimumHeight(160)
        self.file_path = None
        self._build()
        self._update_style(False)

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(10)

        self.icon_lbl = QLabel("🗂️")
        self.icon_lbl.setObjectName("dropIcon")
        self.icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.main_lbl = QLabel("Drag & Drop Memory Image Here")
        self.main_lbl.setObjectName("dropTitle")
        self.main_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.sub_lbl = QLabel("or click to browse files (.raw, .mem, .vmem, .dmp, .img)")
        self.sub_lbl.setObjectName("dropSubtitle")
        self.sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.file_lbl = QLabel("")
        self.file_lbl.setObjectName("dropFile")
        self.file_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.file_lbl.setWordWrap(True)

        layout.addWidget(self.icon_lbl)
        layout.addWidget(self.main_lbl)
        layout.addWidget(self.sub_lbl)
        layout.addWidget(self.file_lbl)

    def _update_style(self, hover=False):
        state = "loaded" if self.file_path else ("hover" if hover else "idle")
        self.setProperty("state", state)
        restyle(self)

    def paintEvent(self, event):
        """QWidget subclasses do not paint a stylesheet background on their own."""
        option = QStyleOption()
        option.initFrom(self)
        painter = QPainter(self)
        self.style().drawPrimitive(
            QStyle.PrimitiveElement.PE_Widget, option, painter, self
        )

    def set_file(self, path):
        self.file_path = path
        fname = os.path.basename(path)
        size = os.path.getsize(path)
        size_str = self._human_size(size)
        self.file_lbl.setText(f"✓  {fname}  ({size_str})")
        self.main_lbl.setText("Memory Image Loaded")
        self.icon_lbl.setText("✅")
        self._update_style(False)
        self.file_dropped.emit(path)

    def _human_size(self, b):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} PB"

    def mousePressEvent(self, event):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Memory Image", "",
            "Memory Images (*.raw *.mem *.vmem *.dmp *.img *.bin);;All Files (*)"
        )
        if path:
            self.set_file(path)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._update_style(True)

    def dragLeaveEvent(self, event):
        self._update_style(False)

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            self.set_file(path)
        self._update_style(False)


class CaseWizard(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("DumpScope — New Case")
        self.setMinimumSize(680, 600)
        self.resize(720, 650)
        self.is_dark = True
        self._case_data = {}
        self._hash_worker = None
        self._build()
        self.apply_theme()

    def _build(self):
        root = QVBoxLayout(self)
        root.setSpacing(0)
        root.setContentsMargins(0, 0, 0, 0)

        # Header
        header = QWidget()
        header.setObjectName("wizardHeader")
        header.setFixedHeight(80)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(28, 0, 28, 0)

        title_lbl = QLabel("New Case")
        title_lbl.setObjectName("wizardTitle")
        subtitle = QLabel("Record the case, the examiner and the memory image to analyse.")
        subtitle.setObjectName("wizardSubtitle")

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_col.addWidget(title_lbl)
        title_col.addWidget(subtitle)

        self.theme_btn = QPushButton("Light Theme")
        self.theme_btn.setFixedWidth(110)
        self.theme_btn.clicked.connect(self.toggle_theme)

        header_layout.addLayout(title_col)
        header_layout.addStretch()
        header_layout.addWidget(self.theme_btn)

        # Step indicator
        step_container = QWidget()
        step_container.setObjectName("stepContainer")
        step_layout = QVBoxLayout(step_container)
        step_layout.setContentsMargins(40, 20, 40, 20)
        self.step_indicator = StepIndicator(
            ["Case Info", "Examiner", "Memory Image"]
        )
        step_layout.addWidget(self.step_indicator)

        # Stacked pages
        self.stack = QStackedWidget()
        self.page_case = self._build_case_page()
        self.page_examiner = self._build_examiner_page()
        self.page_image = self._build_image_page()
        self.stack.addWidget(self.page_case)
        self.stack.addWidget(self.page_examiner)
        self.stack.addWidget(self.page_image)

        # Footer buttons
        footer = QWidget()
        footer.setObjectName("wizardFooter")
        footer.setFixedHeight(65)
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(28, 0, 28, 0)

        self.back_btn = QPushButton("Back")
        self.back_btn.setFixedWidth(100)
        self.back_btn.clicked.connect(self.go_back)
        self.back_btn.setEnabled(False)

        self.next_btn = QPushButton("Next")
        self.next_btn.setObjectName("primaryBtn")
        self.next_btn.setFixedWidth(100)
        self.next_btn.clicked.connect(self.go_next)

        self.finish_btn = QPushButton("✓  Finish")
        self.finish_btn.setObjectName("primaryBtn")
        self.finish_btn.setFixedWidth(120)
        self.finish_btn.clicked.connect(self.finish)
        self.finish_btn.setVisible(False)
        self.finish_btn.setEnabled(False)

        self.page_lbl = QLabel("Step 1 of 3")
        self.page_lbl.setObjectName("fieldHint")

        footer_layout.addWidget(self.back_btn)
        footer_layout.addStretch()
        footer_layout.addWidget(self.page_lbl)
        footer_layout.addStretch()
        footer_layout.addWidget(self.next_btn)
        footer_layout.addWidget(self.finish_btn)

        root.addWidget(header)
        root.addWidget(step_container)
        root.addWidget(self.stack, 1)
        root.addWidget(footer)

    def _section_label(self, text):
        lbl = QLabel(text)
        lbl.setObjectName("dialogHeading")
        return lbl

    def _field_label(self, text, required=False):
        # The asterisk keeps its own colour: it means "required" in every
        # palette, and it is the only literal colour left in this file.
        suffix = "  <span style='color:#f85149;'>*</span>" if required else ""
        lbl = QLabel(f"{text}{suffix}")
        lbl.setObjectName("fieldHint")
        return lbl

    def _build_case_page(self):
        w = QWidget()
        scroll_layout = QVBoxLayout(w)
        scroll_layout.setContentsMargins(36, 20, 36, 20)
        scroll_layout.setSpacing(16)

        scroll_layout.addWidget(self._section_label("Case Information"))

        grid = QGridLayout()
        grid.setSpacing(10)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)

        self.case_name = QLineEdit()
        self.case_name.setPlaceholderText("e.g., Incident_2024_001")
        self.case_number = QLineEdit()
        self.case_number.setPlaceholderText("e.g., DS-2024-001")

        now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self.case_date = QLineEdit(now)
        self.case_date.setPlaceholderText("YYYY-MM-DD HH:MM:SS")

        self.base_dir = QLineEdit()
        self.base_dir.setPlaceholderText("Select base output directory...")
        browse_btn = QPushButton("Browse")
        browse_btn.setFixedWidth(80)
        browse_btn.clicked.connect(self._browse_dir)

        grid.addWidget(self._field_label("Case Name", required=True), 0, 0)
        grid.addWidget(self.case_name, 0, 1)
        grid.addWidget(self._field_label("Case Number", required=True), 0, 2)
        grid.addWidget(self.case_number, 0, 3)

        grid.addWidget(self._field_label("Date / Time"), 1, 0)
        grid.addWidget(self.case_date, 1, 1)

        dir_row = QHBoxLayout()
        dir_row.addWidget(self.base_dir)
        dir_row.addWidget(browse_btn)
        grid.addWidget(self._field_label("Base Directory", required=True), 2, 0)
        grid.addLayout(dir_row, 2, 1, 1, 3)

        scroll_layout.addLayout(grid)

        req_note = QLabel("* Required fields")
        req_note.setObjectName("requiredNote")
        scroll_layout.addWidget(req_note)
        scroll_layout.addStretch()
        return w

    def _build_examiner_page(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(16)

        layout.addWidget(self._section_label("Examiner Information"))

        opt_lbl = QLabel("All fields are optional.")
        opt_lbl.setObjectName("fieldHint")
        layout.addWidget(opt_lbl)

        grid = QGridLayout()
        grid.setSpacing(10)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)

        self.exam_id = QLineEdit()
        self.exam_id.setPlaceholderText("e.g., EX-001")
        self.exam_name = QLineEdit()
        self.exam_name.setPlaceholderText("Full name")
        self.exam_email = QLineEdit()
        self.exam_email.setPlaceholderText("examiner@agency.gov")
        self.exam_phone = QLineEdit()
        self.exam_phone.setPlaceholderText("+1 555-000-0000")

        grid.addWidget(self._field_label("Examiner ID"), 0, 0)
        grid.addWidget(self.exam_id, 0, 1)
        grid.addWidget(self._field_label("Examiner Name"), 0, 2)
        grid.addWidget(self.exam_name, 0, 3)

        grid.addWidget(self._field_label("Email"), 1, 0)
        grid.addWidget(self.exam_email, 1, 1)
        grid.addWidget(self._field_label("Phone"), 1, 2)
        grid.addWidget(self.exam_phone, 1, 3)

        layout.addLayout(grid)

        layout.addWidget(self._field_label("Notes"))
        self.notes = QTextEdit()
        self.notes.setPlaceholderText("Add any additional case notes here...")
        self.notes.setMaximumHeight(130)
        layout.addWidget(self.notes)

        layout.addStretch()
        return w

    def _build_image_page(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(16)

        layout.addWidget(self._section_label("Memory Image"))

        self.drop_zone = DropZone()
        self.drop_zone.file_dropped.connect(self._on_image_loaded)
        layout.addWidget(self.drop_zone)

        # Hash group
        hash_group = QGroupBox("Image Integrity")
        hash_layout = QGridLayout(hash_group)
        hash_layout.setSpacing(10)

        self.hash_progress = QProgressBar()
        self.hash_progress.setRange(0, 0)
        self.hash_progress.setVisible(False)
        self.hash_progress.setFixedHeight(6)

        self.hash_status = QLabel("Load a memory image to compute hashes.")
        self.hash_status.setObjectName("fieldHint")

        self.md5_edit = QLineEdit()
        self.md5_edit.setReadOnly(True)
        self.md5_edit.setPlaceholderText("MD5 hash will appear here...")

        self.sha256_edit = QLineEdit()
        self.sha256_edit.setReadOnly(True)
        self.sha256_edit.setPlaceholderText("SHA-256 hash will appear here...")

        hash_layout.addWidget(QLabel("MD5"), 0, 0)
        hash_layout.addWidget(self.md5_edit, 0, 1)
        hash_layout.addWidget(QLabel("SHA-256"), 1, 0)
        hash_layout.addWidget(self.sha256_edit, 1, 1)
        hash_layout.addWidget(self.hash_status, 2, 0, 1, 2)
        hash_layout.addWidget(self.hash_progress, 3, 0, 1, 2)

        layout.addWidget(hash_group)
        layout.addStretch()
        return w

    def _browse_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Select Base Directory")
        if d:
            self.base_dir.setText(d)

    def _on_image_loaded(self, path):
        self.md5_edit.setText("Computing...")
        self.sha256_edit.setText("Computing...")
        self.hash_status.setText("Calculating hashes — please wait...")
        self.hash_progress.setVisible(True)
        self.finish_btn.setEnabled(False)

        self._hash_worker = HashWorker(path)
        self._hash_worker.hashes_ready.connect(self._on_hashes_done)
        self._hash_worker.error.connect(self._on_hash_error)
        self._hash_worker.start()

    def _on_hashes_done(self, md5, sha256):
        self.md5_edit.setText(md5)
        self.sha256_edit.setText(sha256)
        self.hash_status.setText("✓  Hashes computed successfully.")
        self.hash_progress.setVisible(False)
        self.finish_btn.setEnabled(True)

    def _on_hash_error(self, msg):
        self.hash_status.setText(f"Error: {msg}")
        self.hash_progress.setVisible(False)

    def go_next(self):
        idx = self.stack.currentIndex()
        if idx == 0:
            if not self._validate_case():
                return
        if idx < self.stack.count() - 1:
            self.stack.setCurrentIndex(idx + 1)
            self.step_indicator.set_step(idx + 1)
            self._update_nav(idx + 1)

    def go_back(self):
        idx = self.stack.currentIndex()
        if idx > 0:
            self.stack.setCurrentIndex(idx - 1)
            self.step_indicator.set_step(idx - 1)
            self._update_nav(idx - 1)

    def _update_nav(self, idx):
        last = self.stack.count() - 1
        self.back_btn.setEnabled(idx > 0)
        self.next_btn.setVisible(idx < last)
        self.finish_btn.setVisible(idx == last)
        self.page_lbl.setText(f"Step {idx + 1} of {self.stack.count()}")

    def _validate_case(self):
        missing = []
        if not self.case_name.text().strip():
            missing.append("Case Name")
        if not self.case_number.text().strip():
            missing.append("Case Number")
        if not self.base_dir.text().strip():
            missing.append("Base Directory")
        if missing:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(
                self, "Required Fields",
                "Please fill in:\n• " + "\n• ".join(missing)
            )
            return False
        return True

    def finish(self):
        """
        Create the case folder, then close.

        Creation happens here rather than after the dialog closes so a failure —
        an unwritable parent directory, a case of this name already there — can
        be reported while the fields are still on screen and editable.
        """
        parent_dir = self.base_dir.text().strip()
        try:
            self._case = Case.create(
                parent_dir,
                self.case_name.text().strip(),
                case_number=self.case_number.text().strip(),
                date_time=self.case_date.text().strip(),
                examiner_id=self.exam_id.text().strip(),
                examiner_name=self.exam_name.text().strip(),
                examiner_email=self.exam_email.text().strip(),
                examiner_phone=self.exam_phone.text().strip(),
                notes=self.notes.toPlainText().strip(),
                image_path=self.drop_zone.file_path or "",
                md5=self.md5_edit.text(),
                sha256=self.sha256_edit.text(),
                is_dark=self.is_dark,
            )
        except CaseError as exc:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Could Not Create Case", str(exc))
            return

        remember_case(self._case)
        self._case_data = self._case.to_dict()
        self.accept()

    def get_case(self):
        """The Case created by this wizard; valid only after it was accepted."""
        return getattr(self, "_case", None)

    def get_case_data(self):
        return self._case_data

    def toggle_theme(self):
        self.is_dark = not self.is_dark
        self.apply_theme()

    def apply_theme(self):
        QApplication.instance().setStyleSheet(build_theme(dark=self.is_dark))
        self.theme_btn.setText("Light Theme" if self.is_dark else "Dark Theme")
