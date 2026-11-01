"""
Message boxes that show their text as text.

QMessageBox's static helpers render their message as HTML whenever it looks
like HTML (Qt.TextFormat.AutoText). DumpScope's messages carry process names,
paths, case fields and volatility3 output, all of which can come from the
image under examination or from a case folder someone else prepared. Shown as
HTML, ``<img src="\\\\host\\share\\x">`` makes Qt open that path (on Windows
an SMB connection that hands the examiner's NTLM credentials to the host)
and ``<img src="/dev/zero">`` hangs the window reading it.

These take the same arguments as the static functions they replace and always
show plain text. Use them for every message box; QMessageBox.about is the one
place the application writes its own markup.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QMessageBox, QWidget

Button = QMessageBox.StandardButton
Icon = QMessageBox.Icon


def _show(icon: Icon, parent: QWidget | None, title: str, text: str,
          buttons: Button, default: Button) -> Button:
    box = QMessageBox(icon, title, "", buttons, parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.setText("" if text is None else str(text))
    if default != Button.NoButton:
        box.setDefaultButton(default)
    # What QMessageBox's own static helpers return.
    if box.exec() == -1:
        return Button.Cancel
    return box.standardButton(box.clickedButton())


def information(parent, title, text, buttons=Button.Ok, defaultButton=Button.NoButton):
    return _show(Icon.Information, parent, title, text, buttons, defaultButton)


def warning(parent, title, text, buttons=Button.Ok, defaultButton=Button.NoButton):
    return _show(Icon.Warning, parent, title, text, buttons, defaultButton)


def critical(parent, title, text, buttons=Button.Ok, defaultButton=Button.NoButton):
    return _show(Icon.Critical, parent, title, text, buttons, defaultButton)


def question(parent, title, text, buttons=Button.Yes | Button.No,
             defaultButton=Button.NoButton):
    return _show(Icon.Question, parent, title, text, buttons, defaultButton)
