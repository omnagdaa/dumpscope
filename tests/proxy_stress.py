"""
Drive a result table the way a live analysis session does, in a subprocess.

Run as a script; exits 0 if it survived. It lives outside the test modules
because the failure it guards against is a segmentation fault, which takes the
whole test runner down with it — the only way to assert on it is to watch a
child process's exit code.
"""

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtCore import QEvent, QPoint, QPointF, Qt          # noqa: E402
from PyQt6.QtGui import QMouseEvent                            # noqa: E402
from PyQt6.QtWidgets import QApplication, QTableView           # noqa: E402


def main() -> int:
    app = QApplication([])
    from ui.result_model import ResultFilterProxy, ResultTableModel

    model = ResultTableModel()
    proxy = ResultFilterProxy()
    proxy.setSourceModel(model)
    view = QTableView()
    view.setModel(proxy)
    view.resize(900, 600)
    view.show()

    model.set_columns([f"C{i}" for i in range(8)])
    for batch in range(40):
        model.append_rows(
            [[f"r{batch}-{row}-{col}" for col in range(8)] for row in range(250)]
        )
    proxy.set_filter("r3")
    view.sortByColumn(2, Qt.SortOrder.AscendingOrder)
    app.processEvents()

    for step in range(60):
        # A theme change repaints cells the stylesheet cannot reach. Announced
        # wrongly, it invalidates the proxy's index mapping underneath the view.
        model.apply_theme(dark=(step % 2 == 0))
        proxy.set_filter(f"r{step % 40}")
        view.scrollTo(proxy.index(min(step, proxy.rowCount() - 1), 0))
        for y in range(0, 560, 7):
            view.indexAt(QPoint(120, y))
            app.sendEvent(view.viewport(), QMouseEvent(
                QEvent.Type.MouseMove, QPointF(120, y),
                Qt.MouseButton.NoButton, Qt.MouseButton.NoButton,
                Qt.KeyboardModifier.NoModifier,
            ))
        app.processEvents()
    return 0


if __name__ == "__main__":
    sys.exit(main())
