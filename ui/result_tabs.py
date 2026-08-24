"""
The result tabs, with pinning.

Two things a plain QTabWidget does not give an examiner working a case:

* A tab that cannot be closed by accident. The Case tab, and any result an
  examiner marks as one they are working from, should survive a stray click on
  a close button or a "close others". Pinned tabs lose their close button and
  sit at the front, ahead of the churn of throwaway runs.

* A close affordance you can actually see. Qt's default close button is styled
  down to nothing by the theme; here every unpinned tab carries a real ✕ drawn
  from the icon set, and a pinned one carries a pin glyph in its place.

Pinning is right-click on the tab. The order is kept stable: pinned tabs on the
left in the order they were pinned, unpinned ones after them.
"""

from __future__ import annotations

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import QMenu, QPushButton, QTabBar, QTabWidget

from ui import icons


class _TabIconButton(QPushButton):
    """The small button at the end of a tab: a close ✕, or a pin when pinned."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("tabCloseButton")
        self.setFixedSize(16, 16)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFlat(True)


class ResultTabs(QTabWidget):
    """A QTabWidget whose tabs can be pinned and carry a visible close button."""

    pin_changed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMovable(True)
        # The built-in close buttons are off: this widget manages its own, so
        # pinned tabs can drop theirs and the glyph can be themed.
        self.setTabsClosable(False)
        self._pinned: set = set()          # the *widgets* that are pinned
        self._is_dark = True
        self.tabBar().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tabBar().customContextMenuRequested.connect(self._show_menu)
        self.tabBar().tabMoved.connect(lambda *_: self.pin_changed.emit())

    # ── Public API ────────────────────────────────────────────────────────────

    def add_result_tab(self, widget, title: str, closable: bool = True,
                       pinned: bool = False) -> int:
        index = self.addTab(widget, title)
        if pinned or not closable:
            self._pinned.add(widget)
        self._decorate(index)
        if pinned or not closable:
            self._reorder()
        return index

    def is_pinned(self, widget) -> bool:
        return widget in self._pinned

    def set_pinned(self, widget, pinned: bool):
        if pinned:
            self._pinned.add(widget)
        else:
            self._pinned.discard(widget)
        self._reorder()
        for index in range(self.count()):
            self._decorate(index)
        self.pin_changed.emit()

    def closable_widgets(self) -> list:
        """Every tab that is not pinned, in tab order."""
        return [self.widget(i) for i in range(self.count())
                if self.widget(i) not in self._pinned]

    def apply_theme(self, is_dark: bool):
        self._is_dark = is_dark
        for index in range(self.count()):
            self._decorate(index)

    # ── Decoration ────────────────────────────────────────────────────────────

    def _decorate(self, index: int):
        """Give tab `index` the right end button for its pinned state."""
        widget = self.widget(index)
        pinned = widget in self._pinned
        side = self.tabBar().ButtonPosition.RightSide

        button = _TabIconButton()
        colour = _colour(self._is_dark, "text_dim")
        if pinned:
            button.setIcon(icons.icon("pin", 11, colour))
            button.setToolTip("Unpin this tab")
            button.clicked.connect(lambda _=False, w=widget: self.set_pinned(w, False))
        else:
            button.setIcon(icons.icon("cross", 11, colour))
            button.setToolTip("Close this tab")
            button.clicked.connect(lambda _=False, w=widget: self._request_close(w))
        button.setIconSize(QSize(11, 11))
        self.tabBar().setTabButton(index, side, button)

    def _reorder(self):
        """Pinned tabs to the front, each group keeping its relative order."""
        order = list(range(self.count()))
        widgets = [self.widget(i) for i in order]
        pinned = [w for w in widgets if w in self._pinned]
        rest = [w for w in widgets if w not in self._pinned]
        target = pinned + rest

        # moveTab goes through the tab bar: QTabWidget keeps its page list in
        # sync by listening to the bar's tabMoved, so blocking that signal here
        # would move the tab but leave its page behind. The reorder is idempotent
        # and does not itself react to tabMoved, so letting it through is safe.
        bar = self.tabBar()
        for new_index, widget in enumerate(target):
            current = self.indexOf(widget)
            if current != new_index:
                bar.moveTab(current, new_index)

    # ── Interaction ───────────────────────────────────────────────────────────

    def _request_close(self, widget):
        index = self.indexOf(widget)
        if index >= 0:
            self.tabCloseRequested.emit(index)

    def _show_menu(self, point):
        index = self.tabBar().tabAt(point)
        if index < 0:
            return
        widget = self.widget(index)
        pinned = widget in self._pinned

        menu = QMenu(self)
        if pinned:
            menu.addAction("Unpin Tab", lambda: self.set_pinned(widget, False))
        else:
            menu.addAction("Pin Tab", lambda: self.set_pinned(widget, True))
        menu.addSeparator()
        close = menu.addAction("Close Tab",
                               lambda: self._request_close(widget))
        close.setEnabled(not pinned)
        others = menu.addAction("Close Other Tabs",
                                lambda: self._close_others(widget))
        others.setEnabled(len(self.closable_widgets()) > (0 if pinned else 1))
        menu.addAction("Close All Unpinned", self._close_all)
        menu.exec(self.tabBar().mapToGlobal(point))

    def _close_others(self, keep):
        for widget in self.closable_widgets():
            if widget is not keep:
                self._request_close(widget)

    def _close_all(self):
        for widget in self.closable_widgets():
            self._request_close(widget)


def _colour(is_dark: bool, token: str) -> str:
    from ui.theme import palette
    return palette(dark=is_dark)[token]
