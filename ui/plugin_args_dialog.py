"""
Parameter prompt for plugins that take arguments.

Several volatility3 plugins cannot run bare — windows.strings.Strings needs a
strings file, windows.pedump.PEDump needs a base address, regexscan needs a
pattern. The registry knows which, and this dialog builds a form from the
introspected requirements rather than from a hand-written list, so a plugin
gaining an argument in a future vol3 release needs no code change here.
"""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
    QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget,
)

from core.plugins import PluginInfo


class _FileField(QWidget):
    """A line edit with a Browse button, for URI-typed requirements."""

    def __init__(self, parent=None):
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        self.edit = QLineEdit()
        browse = QPushButton("Browse…")
        browse.setFixedWidth(84)
        browse.clicked.connect(self._browse)
        row.addWidget(self.edit, 1)
        row.addWidget(browse)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self.edit.setText(path)

    def text(self) -> str:
        return self.edit.text()


class PluginArgsDialog(QDialog):
    """Collects argument values for one plugin. `values()` is valid after accept()."""

    def __init__(self, info: PluginInfo, parent=None):
        super().__init__(parent)
        self.info = info
        self._fields: dict[str, object] = {}
        self.setWindowTitle(f"Parameters — {info.short_name}")
        self.setMinimumWidth(560)
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(14)

        heading = QLabel(self.info.id)
        heading.setObjectName("dialogHeading")
        layout.addWidget(heading)

        if self.info.description:
            blurb = QLabel(self.info.description)
            blurb.setWordWrap(True)
            blurb.setObjectName("dialogBlurb")
            layout.addWidget(blurb)

        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(form.labelAlignment())

        for arg in self.info.required_args + self.info.optional_args:
            widget = self._field_for(arg)
            self._fields[arg.name] = widget
            label = arg.name.replace("_", " ").title()
            if arg.required:
                label += " *"
            row_label = QLabel(label)
            if arg.description:
                row_label.setToolTip(arg.description)
                widget.setToolTip(arg.description)
            form.addRow(row_label, widget)

        layout.addLayout(form)

        if self.info.required_args:
            note = QLabel("* required")
            note.setObjectName("dialogBlurb")
            layout.addWidget(note)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._ok.setText("Run")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        for widget in self._fields.values():
            if isinstance(widget, QLineEdit):
                widget.textChanged.connect(self._revalidate)
            elif isinstance(widget, _FileField):
                widget.edit.textChanged.connect(self._revalidate)
        self._revalidate()

    def _field_for(self, arg) -> QWidget:
        if arg.kind == "Boolean":
            box = QCheckBox()
            box.setChecked(bool(arg.default))
            return box
        if arg.kind == "URI":
            return _FileField()
        edit = QLineEdit()
        if arg.default not in (None, ""):
            edit.setText(str(arg.default))
        if arg.kind == "Int":
            edit.setPlaceholderText("decimal or 0x-prefixed hex")
        elif arg.kind == "List":
            edit.setPlaceholderText("space- or comma-separated")
        return edit

    def _revalidate(self):
        self._ok.setEnabled(all(
            self._raw(name).strip()
            for name in (a.name for a in self.info.required_args)
        ))

    def _raw(self, name: str) -> str:
        widget = self._fields.get(name)
        if isinstance(widget, QCheckBox):
            return "1" if widget.isChecked() else ""
        if isinstance(widget, _FileField):
            return widget.text()
        if isinstance(widget, QLineEdit):
            return widget.text()
        return ""

    def values(self) -> dict[str, object]:
        """Field values keyed by requirement name, ready for build_command_args."""
        out: dict[str, object] = {}
        by_name = {a.name: a for a in self.info.args}
        for name, widget in self._fields.items():
            arg = by_name[name]
            if isinstance(widget, QCheckBox):
                if widget.isChecked():
                    out[name] = True
                continue
            text = self._raw(name).strip()
            if not text:
                continue
            if arg.kind == "List":
                out[name] = [p for p in text.replace(",", " ").split() if p]
            else:
                out[name] = text
        return out
