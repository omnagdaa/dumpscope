"""The launcher and the case-tree navigator."""

import pytest

from core.case import Case, remember_case
from ui.case_manager import CaseManager, _friendly_time
from ui.case_tree import CaseTree


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


def test_launcher_lists_recent_cases(qapp, tmp_path):
    first = Case.create(str(tmp_path), "First Case", case_number="1")
    second = Case.create(str(tmp_path), "Second Case", case_number="2")
    remember_case(first)
    remember_case(second)

    manager = CaseManager()
    labels = [
        manager.recent_list.item(i).text()
        for i in range(manager.recent_list.count())
    ]
    assert manager.recent_list.count() == 2
    assert "Second Case" in labels[0]
    assert "First Case" in labels[1]


def test_launcher_shows_a_hint_when_there_are_no_cases(qapp):
    manager = CaseManager()
    assert manager.recent_list.count() == 0
    assert manager.empty_lbl.isVisible() or not manager.recent_list.isVisible()


def test_quick_analysis_yields_a_throwaway_case(qapp):
    manager = CaseManager()
    manager._quick_analysis()
    assert manager.selected_case is not None
    assert manager.selected_case.quick_mode


def test_opening_a_recent_case_selects_it(qapp, tmp_path):
    case = Case.create(str(tmp_path), "Op Nightfall", case_number="2026-014")
    remember_case(case)

    manager = CaseManager()
    manager.recent_list.setCurrentRow(0)
    manager._open_selected()

    assert manager.selected_case is not None
    assert manager.selected_case.case_name == "Op Nightfall"


def test_friendly_time_renders_relative_ages():
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    assert _friendly_time("") == ""
    assert _friendly_time((now - timedelta(seconds=5)).isoformat()) == "just now"
    assert _friendly_time((now - timedelta(minutes=10)).isoformat()) == "10 min ago"
    assert _friendly_time((now - timedelta(hours=5)).isoformat()) == "5 h ago"


def test_case_tree_groups_and_counts(qapp, tmp_path):
    tree = CaseTree()
    tree.refresh(
        sources=[{"id": 1, "path": str(tmp_path / "a.raw"), "display_name": "a.raw",
                  "size_bytes": 1024, "os_hint": "windows", "md5": "x"}],
        results=[{"id": 5, "plugin": "windows.pslist.PsList", "row_count": 42,
                  "source_name": "a.raw", "created_at": "2026-01-01"}],
        bookmarks=[{"id": 9, "label": "svchost.exe", "tag": "Suspicious",
                    "tag_color": "#f85149", "artifact_type": "windows.pslist.PsList",
                    "notes": "odd", "description": "PID 820"}],
        active_source_id=1,
    )

    assert "Data Sources  (1)" in tree.sources_group.text(0)
    assert "Results  (1)" in tree.results_group.text(0)
    assert "Bookmarks  (1)" in tree.bookmarks_group.text(0)
    assert tree.results_group.child(0).text(0) == "PsList   42 rows"


def test_case_tree_flags_a_missing_image(qapp, tmp_path):
    tree = CaseTree()
    tree.refresh(
        sources=[{"id": 1, "path": str(tmp_path / "gone.raw"),
                  "display_name": "gone.raw", "size_bytes": 0}],
        results=[], bookmarks=[],
    )
    assert "FILE MISSING" in tree.sources_group.child(0).toolTip(0)


def test_case_tree_marks_the_active_source(qapp, tmp_path):
    image = tmp_path / "a.raw"
    image.write_bytes(b"\0")
    tree = CaseTree()
    tree.refresh(
        sources=[
            {"id": 1, "path": str(image), "display_name": "a.raw", "size_bytes": 1},
            {"id": 2, "path": str(image), "display_name": "b.raw", "size_bytes": 1},
        ],
        results=[], bookmarks=[], active_source_id=2,
    )
    assert "active" in tree.sources_group.child(1).text(0)
    assert "active" not in tree.sources_group.child(0).text(0)


def test_empty_groups_show_placeholders(qapp):
    tree = CaseTree()
    tree.refresh(sources=[], results=[], bookmarks=[])
    assert tree.sources_group.child(0).text(0) == "No image loaded"
    assert tree.results_group.child(0).text(0) == "Nothing saved yet"
    assert tree.bookmarks_group.child(0).text(0) == "No bookmarks"
