"""
Telling the examiner something finished.

Plugin runs are long — filescan on a 10 GB image is minutes — and an examiner
who starts six of them is not watching the window while they run. The status
bar is the wrong place to report that: it holds one message, so the sixth run
overwrites the first five, and it is invisible from another window anyway.

Two channels, and both are used:

* an in-app toast, stacked in the corner of the window, which needs no
  permission, no tray and no service, and works identically everywhere;
* a desktop notification, which is the only one that reaches an examiner who
  has switched to another application.

The desktop channel goes through QSystemTrayIcon, which maps to the native
mechanism on each platform — the Notifications DBus service on Linux, toast
notifications on Windows, Notification Center on macOS. Where no tray is
running, the toast is still shown, so nothing is ever silently dropped.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import QEasingCurve, QObject, QPoint, QPropertyAnimation, Qt, QTimer
from PyQt6.QtGui import QPainter
from PyQt6.QtWidgets import (
    QGraphicsOpacityEffect, QHBoxLayout, QLabel, QStyle, QStyleOption,
    QSystemTrayIcon, QVBoxLayout, QWidget,
)

from ui import icons

log = logging.getLogger("dumpscope.notifications")

# Long enough to read a sentence; a failure stays up longer because it usually
# has to be acted on.
_DURATION = {"info": 4200, "success": 4600, "warning": 6500, "error": 8000}
_GLYPH = {"info": "info", "success": "shield", "warning": "flask", "error": "bug"}
_MAX_VISIBLE = 4


class Toast(QWidget):
    """One in-app message. Fades in, sits, fades out, deletes itself."""

    def __init__(self, title: str, body: str, level: str, parent=None):
        super().__init__(parent)
        self.setObjectName("toast")
        self.setProperty("level", level)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setFixedWidth(340)

        row = QHBoxLayout(self)
        row.setContentsMargins(12, 10, 14, 10)
        row.setSpacing(10)

        self.glyph = QLabel()
        self.glyph.setObjectName("toastGlyph")
        self.glyph.setFixedWidth(18)

        column = QVBoxLayout()
        column.setSpacing(2)
        heading = QLabel(title)
        heading.setObjectName("toastTitle")
        column.addWidget(heading)
        if body:
            text = QLabel(body)
            text.setObjectName("toastBody")
            text.setWordWrap(True)
            column.addWidget(text)

        row.addWidget(self.glyph, 0, Qt.AlignmentFlag.AlignTop)
        row.addLayout(column, 1)

        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._effect.setOpacity(0.0)
        self._animation: QPropertyAnimation | None = None

    def paintEvent(self, event):
        # A bare QWidget subclass does not paint its own stylesheet background;
        # without this the toast is a floating label with no card behind it.
        option = QStyleOption()
        option.initFrom(self)
        painter = QPainter(self)
        self.style().drawPrimitive(
            QStyle.PrimitiveElement.PE_Widget, option, painter, self)

    def paint_glyph(self, level: str, colour: str, ratio: float = 1.0):
        self.glyph.setPixmap(icons.pixmap(
            _GLYPH.get(level, "info"), size=16, color=colour, ratio=ratio))

    def fade(self, to: float, ms: int, on_done=None):
        animation = QPropertyAnimation(self._effect, b"opacity", self)
        animation.setDuration(ms)
        animation.setStartValue(self._effect.opacity())
        animation.setEndValue(to)
        animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        if on_done is not None:
            animation.finished.connect(on_done)
        # Held on the widget: a QPropertyAnimation garbage-collected mid-flight
        # simply stops, leaving the toast at whatever opacity it reached.
        self._animation = animation
        animation.start()


class Notifier(QObject):
    """
    Posts messages through both channels.

    Owned by the main window, which hands it the widget the toasts stack in.
    """

    def __init__(self, host: QWidget, app_name: str = "DumpScope",
                 desktop: bool = True, parent=None):
        super().__init__(parent or host)
        self.host = host
        self.app_name = app_name
        self.desktop_enabled = desktop
        self._toasts: list[Toast] = []
        self._tray: QSystemTrayIcon | None = None
        self._is_dark = True

    # ── Desktop channel ───────────────────────────────────────────────────────

    def _tray_icon(self) -> QSystemTrayIcon | None:
        """The tray icon, created on first use. None where there is no tray."""
        if self._tray is not None:
            return self._tray
        try:
            if not QSystemTrayIcon.isSystemTrayAvailable():
                return None
            from ui.theme import palette

            tray = QSystemTrayIcon(icons.icon(
                "target", size=32, color=palette(dark=self._is_dark)["accent"]), self)
            tray.setToolTip(self.app_name)
            tray.show()
        except Exception as exc:              # a tray is never worth failing over
            log.debug("No system tray available: %s", exc)
            return None
        self._tray = tray
        return tray

    def _post_desktop(self, title: str, body: str, level: str):
        if not self.desktop_enabled:
            return
        tray = self._tray_icon()
        if tray is None:
            return
        kind = {
            "error": QSystemTrayIcon.MessageIcon.Critical,
            "warning": QSystemTrayIcon.MessageIcon.Warning,
        }.get(level, QSystemTrayIcon.MessageIcon.Information)
        try:
            tray.showMessage(title, body, kind, _DURATION.get(level, 4000))
        except Exception as exc:
            log.debug("Could not post a desktop notification: %s", exc)

    # ── In-app channel ────────────────────────────────────────────────────────

    def notify(self, title: str, body: str = "", level: str = "info"):
        """Show one message. `level` is info, success, warning or error."""
        self._post_desktop(title, body, level)
        self._show_toast(title, body, level)

    def _show_toast(self, title: str, body: str, level: str):
        from ui.theme import palette

        toast = Toast(title, body, level, parent=self.host)
        tokens = palette(dark=self._is_dark)
        toast.paint_glyph(level, {
            "success": tokens["ok"], "warning": tokens["warn"],
            "error": tokens["danger"],
        }.get(level, tokens["accent"]), self.host.devicePixelRatioF() or 1.0)
        toast.adjustSize()

        self._toasts.append(toast)
        # Oldest first out, so a burst of six finishing plugins does not bury
        # the window under six cards.
        while len(self._toasts) > _MAX_VISIBLE:
            self._retire(self._toasts[0], immediate=True)

        self._reposition()
        toast.show()
        toast.raise_()
        toast.fade(1.0, 160)
        QTimer.singleShot(_DURATION.get(level, 4000), lambda: self._retire(toast))

    def _retire(self, toast: Toast, immediate: bool = False):
        if toast not in self._toasts:
            return
        self._toasts.remove(toast)
        self._reposition()
        if immediate:
            toast.deleteLater()
            return
        toast.fade(0.0, 220, on_done=toast.deleteLater)

    def _anchor(self):
        """
        The rectangle to stack in: the working area, not the whole window.

        Measuring from the window's own bottom edge puts the newest toast
        underneath the status bar, where it is half visible.
        """
        central = getattr(self.host, "centralWidget", lambda: None)()
        if central is not None and central.isVisible():
            top_left = central.mapTo(self.host, QPoint(0, 0))
            return top_left, central.size()
        return QPoint(0, 0), self.host.size()

    def _reposition(self):
        """Stack from the bottom-right corner of the work area, newest lowest."""
        margin = 18
        origin, size = self._anchor()
        y = origin.y() + size.height() - margin
        for toast in reversed(self._toasts):
            y -= toast.height()
            toast.move(QPoint(origin.x() + size.width() - toast.width() - margin, y))
            y -= 8

    # ── Housekeeping ──────────────────────────────────────────────────────────

    def set_dark(self, is_dark: bool):
        self._is_dark = is_dark

    def set_desktop_enabled(self, enabled: bool):
        self.desktop_enabled = enabled
        if not enabled and self._tray is not None:
            self._tray.hide()
            self._tray.deleteLater()
            self._tray = None

    def handle_resize(self):
        self._reposition()

    def shutdown(self):
        for toast in list(self._toasts):
            self._retire(toast, immediate=True)
        if self._tray is not None:
            self._tray.hide()
