"""
The Timeline, Insights and Report surfaces, on their own and end to end
through the main window against the fixture-driven vol3 stub.
"""
import os
import sys
import time
from datetime import timedelta

import pytest
from PyQt6.QtCore import QPoint, QPointF, Qt
from PyQt6.QtGui import QWheelEvent
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QMessageBox

from core import vol_runner
from core.case import Case
from core.insights import analyse
from core.plugins import PluginRegistry
from core.timeline import build_events, parse_time
from tests.vol_fixtures import all_payloads

STUB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stub_vol.py")


def _pump(predicate, timeout=30.0):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(0.01)
    QApplication.processEvents()
    return predicate()


# ── Timeline view ─────────────────────────────────────────────────────────────

def test_timeline_empty_state(qapp):
    from ui.timeline_view import TimelineView
    view = TimelineView()
    view.set_events([], missing=["a", "b"])
    assert view.stack.currentIndex() == 0
    assert view.collect_btn.isEnabled() and "(2)" in view.collect_btn.text()
    assert not view.export_btn.isEnabled()
    view.chart.repaint()                     # painting an empty chart must not raise


def test_timeline_lists_every_event(timeline):
    assert timeline.stack.currentIndex() == 1
    assert timeline.model.rowCount() == 25
    assert timeline.model.data(timeline.model.index(0, 0)) == "2024-03-14 08:00:01 UTC"


def test_legend_hides_kinds_without_events(timeline):
    assert timeline._chips["dll"].isVisibleTo(timeline)
    assert not timeline._chips["driver"].isVisibleTo(timeline)
    assert "6" in timeline._chips["dll"].text()


def test_toggling_a_kind_filters_table_and_chart(timeline):
    timeline._chips["dll"].setChecked(False)
    assert all(e.kind != "dll" for e in timeline.visible_events())
    assert timeline.model.rowCount() == 19
    assert "dll" not in timeline.chart._kinds
    timeline._chips["dll"].setChecked(True)
    assert timeline.model.rowCount() == 25


def test_search_filters_events(timeline):
    timeline.search.setText("185.220.101.4")
    assert timeline.model.rowCount() == 2
    timeline.search.setText("nothing-matches-this")
    assert timeline.model.rowCount() == 0
    assert not timeline.export_btn.isEnabled()


def test_zoom_and_reset(timeline):
    start = parse_time("2024-03-14 09:41:00")
    timeline.zoom_to(start, start + timedelta(minutes=2))
    assert 0 < timeline.model.rowCount() < 25
    assert timeline.reset_btn.isEnabled()
    timeline.reset_zoom()
    assert timeline.model.rowCount() == 25 and not timeline.reset_btn.isEnabled()


def test_zoom_with_reversed_or_empty_range(timeline):
    moment = parse_time("2024-03-14 09:41:32")
    timeline.zoom_to(moment, moment)                     # widened, not empty
    assert timeline.model.rowCount() >= 1
    timeline.zoom_to(None, moment)                       # ignored
    timeline.zoom_to(moment, moment - timedelta(hours=1))
    assert timeline.model.rowCount() >= 0


def test_dragging_across_the_chart_zooms(timeline):
    chart = timeline.chart
    rect = chart._plot_rect()
    y = int(rect.center().y())
    left, right = int(rect.right() - rect.width() * 0.05), int(rect.right() - 1)
    QTest.mousePress(chart, Qt.MouseButton.LeftButton, pos=QPoint(left, y))
    QTest.mouseMove(chart, QPoint(right, y))
    QTest.mouseRelease(chart, Qt.MouseButton.LeftButton, pos=QPoint(right, y))
    assert timeline._range[0] is not None
    assert timeline.model.rowCount() < 25
    QTest.mouseDClick(chart, Qt.MouseButton.LeftButton, pos=QPoint(left, y))
    assert timeline._range == (None, None)


def test_clicking_a_bar_lists_its_events(timeline):
    chart = timeline.chart
    rect = chart._plot_rect()
    x = int(rect.left() + 1)                              # the 08:00 boot burst
    QTest.mouseClick(chart, Qt.MouseButton.LeftButton, pos=QPoint(x, int(rect.center().y())))
    shown = timeline.visible_events()
    assert shown and all(e.time < parse_time("2024-03-14 08:30:00") for e in shown)


def test_wheel_zooms_in(timeline):
    chart = timeline.chart
    rect = chart._plot_rect()
    position = QPointF(rect.center().x(), rect.center().y())
    event = QWheelEvent(position, chart.mapToGlobal(position), QPoint(0, 0), QPoint(0, 120),
                        Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier,
                        Qt.ScrollPhase.NoScrollPhase, False)
    QApplication.sendEvent(chart, event)
    start, end = timeline._range
    assert start is not None and (end - start) < timedelta(hours=2)


def test_hovering_the_chart_never_raises(timeline):
    chart = timeline.chart
    for x in range(0, chart.width(), 37):
        QTest.mouseMove(chart, QPoint(x, chart.height() // 2))


def test_chart_with_one_event_and_tiny_size(qapp):
    from ui.timeline_view import TimelineChart
    chart = TimelineChart()
    chart.resize(20, 20)
    chart.set_events(build_events(all_payloads())[:1])
    chart.repaint()
    chart.set_dark(False)
    chart.repaint()


def test_export_csv(timeline, tmp_path):
    timeline.search.setText("powershell")
    path = tmp_path / "t.csv"
    written = timeline.export_csv(str(path))
    text = path.read_text(encoding="utf-8-sig")
    assert written == timeline.model.rowCount() > 0
    assert text.splitlines()[0].startswith("Time (UTC),Type,PID")


def test_double_click_reports_the_event(timeline):
    seen = []
    timeline.event_activated.connect(seen.append)
    timeline._activated(timeline.model.index(2, 0))
    timeline._activated(timeline.model.index(999, 0))
    assert len(seen) == 1 and seen[0].pid == "420"


def test_collect_button_reports_what_is_missing(timeline):
    asked = []
    timeline.collect_requested.connect(asked.append)
    timeline.collect_btn.click()
    assert asked == [["windows.netscan.NetScan"]]


def test_timeline_zoom_survives_new_data_outside_it(timeline):
    start = parse_time("2024-03-14 09:41:00")
    timeline.zoom_to(start, start + timedelta(minutes=1))
    timeline.set_events([e for e in timeline.events if e.time < start])
    assert timeline._range == (None, None)


# ── Insights view ─────────────────────────────────────────────────────────────

@pytest.fixture
def insights(qapp):
    from ui.insights_view import InsightsView
    view = InsightsView()
    view.resize(1200, 700)
    view.set_payloads(all_payloads())
    yield view
    view.close()


def test_insights_cards_and_table(insights):
    findings = analyse(all_payloads())
    assert insights.model.rowCount() == len(findings)
    high = sum(f.severity == "high" for f in findings)
    assert insights.cards["high"].count_lbl.text() == str(high)
    assert insights.stack.currentIndex() == 1
    assert insights.current() == findings[0]
    assert findings[0].title in insights.detail.toPlainText()


def test_severity_card_toggles_the_filter(insights):
    insights.cards["medium"].clicked.emit("medium")
    assert {f.severity for f in insights.visible_findings()} == {"medium"}
    insights.cards["medium"].clicked.emit("medium")
    assert len(insights.visible_findings()) == len(insights.findings)


def test_insight_search_and_empty_result(insights):
    insights.search.setText("scvhost")
    assert insights.visible_findings() and all(
        "scvhost" in " ".join(f.as_row()).lower() for f in insights.visible_findings())
    insights.search.setText("zzz-nothing")
    assert insights.visible_findings() == []
    assert not insights.bookmark_btn.isEnabled()


def test_bookmark_signal_carries_the_finding(insights):
    asked = []
    insights.bookmark_requested.connect(asked.append)
    insights.table.selectRow(2)
    insights.bookmark_btn.click()
    assert asked == [insights.model.findings[2]]


def test_insights_empty_state(qapp):
    from ui.insights_view import InsightsView
    view = InsightsView()
    view.set_findings([], missing=["windows.pslist.PsList"])
    assert view.stack.currentIndex() == 0 and view.collect_btn.isEnabled()
    view.set_findings([], missing=[])
    assert not view.collect_btn.isEnabled()
    view.set_dark(False)


# ── Report dialog ─────────────────────────────────────────────────────────────

@pytest.fixture
def stored_case(tmp_path):
    from core.database import Database
    image = tmp_path / "host.raw"
    image.write_bytes(b"\0" * 64)
    case = Case.create(str(tmp_path), "Report Case", image_path=str(image))
    db = Database(case.directory, case.case_name)
    db.attach_case(case.to_dict())
    source_id = db.get_data_sources()[0]["id"]
    for p in all_payloads():
        db.save_analysis(p["plugin"], p, source_id=source_id)
    return case, db


def test_report_dialog_generates_a_bundle(qapp, stored_case):
    from ui.report_dialog import ReportDialog
    case, db = stored_case
    dialog = ReportDialog(case, db)
    produced = []
    dialog.generated.connect(produced.append)
    dialog.copy_radio.setChecked(True)
    assert dialog.options().dump_mode == "copy"
    dialog.start()
    dialog.start()                                      # a second click is ignored
    assert _pump(lambda: dialog.worker is None)
    assert produced and os.path.isfile(produced[0].index)
    assert dialog.open_btn.isVisible() or not dialog.isVisible()
    assert "Report written" in dialog.status_lbl.text()
    assert len(os.listdir(os.path.join(case.directory, "reports"))) == 1


def test_report_dialog_cancel_leaves_nothing(qapp, stored_case, monkeypatch):
    from core import report_bundle
    from ui.report_dialog import ReportDialog
    case, db = stored_case
    real = report_bundle._write_manifest
    def slow_manifest(folder, result, report, stop):
        deadline = time.monotonic() + 5
        while not stop() and time.monotonic() < deadline:
            time.sleep(0.01)
        real(folder, result, report, stop)
    monkeypatch.setattr(report_bundle, "_write_manifest", slow_manifest)
    dialog = ReportDialog(case, db)
    dialog.start()
    assert _pump(lambda: dialog.progress.value() >= 75, 10)
    dialog._close_or_cancel()
    assert _pump(lambda: dialog.worker is None)
    assert "Cancelled" in dialog.status_lbl.text()
    assert os.listdir(os.path.join(case.directory, "reports")) == []


def test_report_dialog_shows_failures(qapp, stored_case, monkeypatch):
    from core import report_bundle
    from ui.report_dialog import ReportDialog
    case, db = stored_case
    def explode(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(report_bundle, "build_html", explode)
    dialog = ReportDialog(case, db)
    dialog.start()
    assert _pump(lambda: dialog.worker is None)
    assert "disk full" in dialog.status_lbl.text()
    assert dialog.generate_btn.isEnabled(), "a failed report can be retried"


# ── Symbols dialog ────────────────────────────────────────────────────────────

def test_symbol_dialog_modes(qapp, tmp_path):
    from ui.symbol_dialog import SymbolDialog
    quick = SymbolDialog(str(tmp_path), image_path="", case_mode=False)
    assert not quick.fetch_btn.isEnabled() and not quick.dl_btn.isEnabled()
    image = tmp_path / "i.raw"
    image.write_bytes(b"\0")
    (tmp_path / "symbols" / "windows").mkdir(parents=True)
    (tmp_path / "symbols" / "windows" / "a.json.xz").write_bytes(b"x" * 2048)
    (tmp_path / "yara").mkdir()
    (tmp_path / "yara" / "r.YAR").write_text("rule x { condition: true }")
    dialog = SymbolDialog(str(tmp_path), image_path=str(image))
    assert dialog.fetch_btn.isEnabled()
    assert dialog.sym_list.count() == 1 and "1 symbol table" in dialog.sym_status.text()
    assert dialog.get_yara_files() == [str(tmp_path / "yara" / "r.YAR")]
    dialog.close()


# ── End to end through the main window ────────────────────────────────────────

@pytest.fixture
def window(qapp, tmp_path, monkeypatch):
    from ui.main_window import MainWindow
    monkeypatch.setattr(vol_runner, "find_vol3_command", lambda: [sys.executable, STUB])
    monkeypatch.setenv("STUB_VOL_FIXTURES", "1")
    for kind in ("warning", "critical", "information", "question"):
        monkeypatch.setattr(QMessageBox, kind, staticmethod(
            lambda *a, **k: QMessageBox.StandardButton.No))
    image = tmp_path / "host.raw"
    image.write_bytes(b"\0" * 4096)
    case = Case.create(str(tmp_path), "E2E", image_path=str(image))
    win = MainWindow(case, registry=PluginRegistry.load())
    if win._os_probe is not None:
        win._os_probe.cancel()
        win._os_probe.wait(5000)
    yield win
    win.close()


def test_new_case_starts_with_empty_analysis_tabs(window):
    assert window.timeline_view.events == [] and window.insights_view.findings == []
    assert window.timeline_view.missing and window.insights_view.missing
    assert window.tabs.is_pinned(window.timeline_view)
    assert window.tabs.is_pinned(window.insights_view)


def test_collect_fills_timeline_and_insights(window):
    plugins = list(dict.fromkeys(window.timeline_view.missing + window.insights_view.missing))
    window._collect(plugins)
    assert _pump(lambda: not window._runners, 60)
    assert len(window.timeline_view.events) == 25
    assert window.insights_view.findings
    assert window.timeline_view.missing == [] and window.insights_view.missing == []
    high = sum(f.severity == "high" for f in window.insights_view.findings)
    index = window.tabs.indexOf(window.insights_view)
    assert window.tabs.tabText(index) == f"Insights ({high})"
    assert window.tabs.currentWidget() is window.tabs.widget(0), "collect keeps your place"


def test_collect_skips_running_and_unknown_plugins(window):
    window._collect(["windows.does_not.Exist"])
    assert window._runners == {}


def test_collect_without_an_image_does_nothing(window):
    os.unlink(window.case.image_path)
    window._collect(["windows.pslist.PsList"])
    assert window._runners == {}


def test_bookmarking_an_insight(window):
    window._collect(["windows.pslist.PsList", "windows.psscan.PsScan"])
    assert _pump(lambda: not window._runners, 60)
    finding = next(f for f in window.insights_view.findings if f.category == "Hidden process")
    window._bookmark_insight(finding)
    [bookmark] = window.db.get_bookmarks()
    assert bookmark["tag"] == "Suspicious" and bookmark["label"] == finding.title


def test_deleting_a_result_updates_the_views(window):
    window._collect(["windows.pslist.PsList"])
    assert _pump(lambda: not window._runners, 60)
    assert window.timeline_view.events
    from PyQt6.QtWidgets import QMessageBox as Box
    import ui.main_window as mw
    mw.QMessageBox.question = staticmethod(lambda *a, **k: Box.StandardButton.Yes)
    result_id = window.db.get_results()[0]["id"]
    window._delete_stored_result(result_id)
    assert window.timeline_view.events == []


def test_quick_analysis_timeline_uses_open_tabs(qapp, tmp_path, monkeypatch):
    from ui.main_window import MainWindow
    monkeypatch.setattr(vol_runner, "find_vol3_command", lambda: [sys.executable, STUB])
    monkeypatch.setenv("STUB_VOL_FIXTURES", "1")
    image = tmp_path / "host.raw"
    image.write_bytes(b"\0")
    case = Case.quick(str(tmp_path))
    case.image_path = str(image)
    window = MainWindow(case, registry=PluginRegistry.load())
    if window._os_probe is not None:
        window._os_probe.cancel()
        window._os_probe.wait(5000)
    window._collect(["windows.pslist.PsList"])
    assert _pump(lambda: not window._runners, 60)
    assert len(window.timeline_view.events) == 13
    window._bookmark_insight(analyse(all_payloads())[0])      # no database: no crash
    window.close()


def test_email_is_gone(window):
    texts = [a.text() for menu in window.menuBar().actions() if menu.menu()
             for a in menu.menu().actions()]
    assert not any("mail" in t.lower() for t in texts)
    assert not any("mail" in c.title.lower() for c in window._commands())
    import importlib.util
    assert importlib.util.find_spec("core.mailer") is None
    assert importlib.util.find_spec("ui.email_dialog") is None


def test_generate_report_from_the_window(window, monkeypatch):
    from ui import report_dialog
    window._collect(["windows.pslist.PsList"])
    assert _pump(lambda: not window._runners, 60)
    opened = []
    def run_inline(dialog):
        opened.append(dialog)
        dialog.start()
        _pump(lambda: dialog.worker is None)
        return 1
    monkeypatch.setattr(report_dialog.ReportDialog, "exec", run_inline)
    window._generate_report()
    assert opened and opened[0].result is not None
    assert any(a["action"] == "report_generated" for a in window.db.get_audit_log())


def test_quick_analysis_cannot_generate_a_report(qapp, tmp_path, monkeypatch):
    from ui.main_window import MainWindow
    told = []
    monkeypatch.setattr(QMessageBox, "information",
                        staticmethod(lambda *a, **k: told.append(a[1])))
    window = MainWindow(Case.quick(str(tmp_path)), registry=PluginRegistry(None))
    window._generate_report()
    assert told == ["No Case"]
    window.close()


def test_palette_has_analysis_commands(window):
    titles = [c.title for c in window._commands()]
    for title in ("Show Insights", "Show Timeline", "Collect Timeline and Insight Data"):
        assert title in titles
