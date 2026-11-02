"""
Telling the examiner something finished: one desktop notification.

Plugin runs are long (filescan on a 10 GB image is minutes) and an examiner
who starts six of them is usually in another window by the time they end, so
the message goes to the desktop's notification centre, not into the window.
The status bar still carries the same line for anyone looking at DumpScope.

There is only ever one DumpScope notification on screen. Messages that arrive
together (a run finishing, then the batch it belonged to) are merged into one,
and each new notification replaces the previous one instead of stacking:

* Linux: org.freedesktop.Notifications over D-Bus (KDE, GNOME, XFCE, most
  others), using its replaces_id. Clicking the notification raises DumpScope.
* Windows and macOS, or Linux without that service: QSystemTrayIcon, which
  shows one balloon or toast at a time.
"""

from __future__ import annotations

import html
import logging
import sys

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSlot
from PyQt6.QtWidgets import QSystemTrayIcon, QWidget

from ui import icons

log = logging.getLogger("dumpscope.notifications")

LEVELS = ("info", "success", "warning", "error")
_RANK = {level: i for i, level in enumerate(LEVELS)}
# Long enough to read; a failure stays up longer because it usually has to be
# acted on.
_DURATION = {"info": 5000, "success": 6000, "warning": 8000, "error": 10000}
_FREEDESKTOP_ICON = {"info": "dialog-information", "success": "dialog-information",
                     "warning": "dialog-warning", "error": "dialog-error"}
# Messages posted within this window of each other become one notification.
_MERGE_MS = 450

_SERVICE = "org.freedesktop.Notifications"
_PATH = "/org/freedesktop/Notifications"


class _FreedesktopChannel(QObject):
    """org.freedesktop.Notifications, if the session bus offers it."""

    def __init__(self, host: QWidget, app_name: str):
        super().__init__(host)
        self.host = host
        self.app_name = app_name
        self.last_id = 0
        self.iface = None
        try:
            from PyQt6.QtDBus import QDBusConnection, QDBusInterface
        except ImportError:
            return
        bus = QDBusConnection.sessionBus()
        if not bus.isConnected():
            return
        iface = QDBusInterface(_SERVICE, _PATH, _SERVICE, bus)
        if not iface.isValid():
            return
        self.iface = iface
        bus.connect(_SERVICE, _PATH, _SERVICE, "ActionInvoked", self._action)

    @property
    def available(self) -> bool:
        return self.iface is not None

    def post(self, title: str, body: str, level: str) -> bool:
        from PyQt6.QtCore import QMetaType
        from PyQt6.QtDBus import QDBusArgument, QDBusMessage

        uint = QMetaType.Type.UInt.value
        reply = self.iface.call(
            "Notify", self.app_name, QDBusArgument(self.last_id, uint),
            _FREEDESKTOP_ICON.get(level, "dialog-information"),
            title,
            # Several servers render a subset of HTML in the body; the text can
            # quote names from the image.
            html.escape(body),
            QDBusArgument(["default", "Show DumpScope"], QMetaType.Type.QStringList.value),
            {}, _DURATION.get(level, 5000),
        )
        if reply.type() != QDBusMessage.MessageType.ReplyMessage or not reply.arguments():
            log.debug("Notification not delivered: %s", reply.errorMessage())
            return False
        self.last_id = int(reply.arguments()[0])
        return True

    @pyqtSlot("uint", str)
    def _action(self, notification_id: int, _key: str):
        if notification_id != self.last_id or self.host is None:
            return
        window = self.host.window()
        window.setWindowState(window.windowState() & ~Qt.WindowState.WindowMinimized)
        window.show()
        window.raise_()
        window.activateWindow()

    def close(self):
        if self.iface is not None and self.last_id:
            from PyQt6.QtCore import QMetaType
            from PyQt6.QtDBus import QDBusArgument
            self.iface.call("CloseNotification",
                            QDBusArgument(self.last_id, QMetaType.Type.UInt.value))
            self.last_id = 0


class Notifier(QObject):
    """
    Posts desktop notifications for the main window.

    `notify` can be called as often as convenient; bursts are merged and only
    one notification is ever shown.
    """

    def __init__(self, host: QWidget, app_name: str = "DumpScope",
                 desktop: bool = True, parent=None):
        super().__init__(parent or host)
        self.host = host
        self.app_name = app_name
        self.desktop_enabled = desktop
        self._is_dark = True
        self._pending: list[tuple[str, str, str]] = []
        self._flush_timer = QTimer(self)
        self._flush_timer.setSingleShot(True)
        self._flush_timer.setInterval(_MERGE_MS)
        self._flush_timer.timeout.connect(self._flush)
        self._freedesktop: _FreedesktopChannel | None = None
        self._tray: QSystemTrayIcon | None = None
        self.posted: list[tuple[str, str, str]] = []    # what went out, newest last

    # ── Public ────────────────────────────────────────────────────────────────

    def notify(self, title: str, body: str = "", level: str = "info"):
        """Queue one message. `level` is info, success, warning or error."""
        if not self.desktop_enabled:
            return
        self._pending.append((title, body, level if level in _RANK else "info"))
        self._flush_timer.start()

    def flush(self):
        """Send what is queued now (the timer would send it shortly)."""
        self._flush_timer.stop()
        self._flush()

    def set_dark(self, is_dark: bool):
        self._is_dark = is_dark

    def set_desktop_enabled(self, enabled: bool):
        self.desktop_enabled = enabled
        if not enabled:
            self._pending.clear()
            self._flush_timer.stop()
            self._close()

    def shutdown(self):
        self._flush_timer.stop()
        self._pending.clear()
        self._close()

    # ── Merging ───────────────────────────────────────────────────────────────

    @staticmethod
    def merge(messages: list[tuple[str, str, str]]) -> tuple[str, str, str]:
        """One notification for several messages; the most severe leads."""
        if len(messages) == 1:
            return messages[0]
        lead = max(messages, key=lambda m: (_RANK[m[2]], messages.index(m)))
        others = [m for m in messages if m is not lead]
        lines = [lead[1]] if lead[1] else []
        lines += [f"{title}: {body}" if body else title for title, body, _ in others]
        return lead[0], "\n".join(lines), lead[2]

    def _flush(self):
        if not self._pending:
            return
        title, body, level = self.merge(self._pending)
        self._pending.clear()
        self.posted.append((title, body, level))
        del self.posted[:-20]
        self._post(title, body, level)

    # ── Channels ──────────────────────────────────────────────────────────────

    def _post(self, title: str, body: str, level: str):
        if sys.platform.startswith("linux"):
            if self._freedesktop is None:
                self._freedesktop = _FreedesktopChannel(self.host, self.app_name)
            if self._freedesktop.available and self._freedesktop.post(title, body, level):
                return
        tray = self._tray_icon()
        if tray is None:
            return
        kind = {
            "error": QSystemTrayIcon.MessageIcon.Critical,
            "warning": QSystemTrayIcon.MessageIcon.Warning,
        }.get(level, QSystemTrayIcon.MessageIcon.Information)
        try:
            tray.showMessage(title, body, kind, _DURATION.get(level, 5000))
        except Exception as exc:
            log.debug("Could not post a desktop notification: %s", exc)

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
            tray.messageClicked.connect(self._raise_host)
            tray.show()
        except Exception as exc:              # a tray is never worth failing over
            log.debug("No system tray available: %s", exc)
            return None
        self._tray = tray
        return tray

    def _raise_host(self):
        window = self.host.window()
        window.show()
        window.raise_()
        window.activateWindow()

    def _close(self):
        if self._freedesktop is not None:
            self._freedesktop.close()
        if self._tray is not None:
            self._tray.hide()
            self._tray.deleteLater()
            self._tray = None
