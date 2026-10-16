"""The timeline's time range picker: quick ranges and an absolute From/To."""
from datetime import timedelta

from core.timeline import parse_time
from tests.test_ui_analysis import timeline  # noqa: F401  (fixture)
from ui.timeline_view import quick_range, range_text

FIRST = parse_time("2024-03-14 08:00:00")
LAST = parse_time("2024-03-14 09:43:00")


def test_quick_ranges_are_anchored_to_the_capture_and_clamped():
    assert quick_range(FIRST, LAST, "last", timedelta(minutes=15)) == (
        LAST - timedelta(minutes=15), LAST)
    assert quick_range(FIRST, LAST, "first", timedelta(hours=1)) == (
        FIRST, FIRST + timedelta(hours=1))
    # Longer than the capture: never reaches outside it.
    assert quick_range(FIRST, LAST, "last", timedelta(days=1)) == (FIRST, LAST)
    assert quick_range(FIRST, LAST, "all", None) == (None, None)


def test_range_text():
    assert range_text(None, None) == "Whole capture"
    assert range_text(FIRST, LAST) == "2024-03-14 08:00:00 – 09:43:00 UTC"
    assert "2024-03-15" in range_text(FIRST, LAST + timedelta(days=1))


def test_quick_select_and_whole_capture_drive_the_view(timeline):
    timeline._open_range_popup()
    timeline.range_popup.quick_buttons["Last 5 minutes"].click()
    assert not timeline.range_popup.isVisible()
    assert 0 < timeline.model.rowCount() < 25
    assert timeline.range_btn.text().endswith("09:43:00 UTC")
    timeline._open_range_popup()
    timeline.range_popup.quick_buttons["Whole capture"].click()
    assert timeline.model.rowCount() == 25 and timeline.range_btn.text() == "Whole capture"


def test_absolute_range_includes_the_whole_to_second(timeline):
    popup = timeline.range_popup
    timeline._open_range_popup()
    from ui.timeline_view import _to_qt
    popup.from_edit.setDateTime(_to_qt(parse_time("2024-03-14 08:00:01")))
    popup.to_edit.setDateTime(_to_qt(parse_time("2024-03-14 08:00:02")))
    popup.apply_btn.click()
    # Fixture events at 08:00:01 and 08:00:02 (System, smss.exe) both count.
    assert timeline.model.rowCount() == 2


def test_inverted_absolute_range_is_refused(timeline):
    popup = timeline.range_popup
    timeline._open_range_popup()
    popup.from_edit.setDateTime(popup.to_edit.maximumDateTime())
    popup.to_edit.setDateTime(popup.to_edit.minimumDateTime())
    popup.apply_btn.click()
    assert popup.error_lbl.isVisibleTo(popup) and timeline.model.rowCount() == 25
    popup.hide()


def test_picker_is_disabled_without_events(qapp):
    from ui.timeline_view import TimelineView
    view = TimelineView()
    view.set_events([])
    assert not view.range_btn.isEnabled()
    view._open_range_popup()                          # must not raise
