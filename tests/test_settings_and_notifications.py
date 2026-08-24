"""
Preferences that outlive a case, and the two channels that report completion.
"""

import json
import os

import pytest

from core import settings
from ui import theme


@pytest.fixture(autouse=True)
def _isolated_config(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "config_dir", lambda: str(tmp_path))
    settings._cache = None
    yield
    settings._cache = None
    theme.set_fonts()


# ── Settings ──────────────────────────────────────────────────────────────────

def test_defaults_apply_when_nothing_is_stored():
    assert settings.get("ui_font") == ""
    assert settings.get("desktop_notifications") is True


def test_a_saved_setting_survives_a_reload(tmp_path):
    settings.save(ui_font="Fira Sans", font_size=15)
    settings._cache = None
    assert settings.get("ui_font") == "Fira Sans"
    assert json.load(open(os.path.join(tmp_path, "settings.json")))["font_size"] == 15


def test_unknown_keys_are_ignored(tmp_path):
    with open(os.path.join(tmp_path, "settings.json"), "w") as handle:
        json.dump({"ui_font": "Inter", "rm": "-rf"}, handle)
    values = settings.load(refresh=True)
    assert values["ui_font"] == "Inter"
    assert "rm" not in values


def test_unreadable_settings_fall_back_rather_than_raising(tmp_path):
    with open(os.path.join(tmp_path, "settings.json"), "w") as handle:
        handle.write("{ this is not json")
    assert settings.load(refresh=True)["ui_font"] == ""


# ── Fonts in the stylesheet ───────────────────────────────────────────────────

def test_a_chosen_family_goes_in_front_of_the_stack_not_over_it():
    # An uninstalled family must fall back the way the default stack does.
    theme.set_fonts(ui_font="Fira Sans")
    sheet = theme.build(dark=True)
    assert "'Fira Sans', 'Inter'" in sheet


def test_the_size_scales_every_rule_together():
    plain = theme.build(dark=True)
    theme.set_fonts(size=theme.BASE_FONT_SIZE * 2)
    doubled = theme.build(dark=True)
    assert f"font-size: {theme.BASE_FONT_SIZE * 2}px" in doubled
    assert plain.count("font-size") == doubled.count("font-size")
    assert "font-size: 0px" not in doubled


def test_resetting_restores_the_built_in_stacks():
    theme.set_fonts(ui_font="Fira Sans", mono_font="Iosevka", size=20)
    theme.set_fonts()
    assert theme.fonts() == {"ui_font": "", "mono_font": "", "size": theme.BASE_FONT_SIZE}
    assert theme.mono_family() == "JetBrains Mono"


# ── Notifications ─────────────────────────────────────────────────────────────

def test_toasts_stack_and_are_capped(qapp):
    from PyQt6.QtWidgets import QWidget
    from ui.notifications import Notifier

    host = QWidget()
    host.resize(800, 600)
    notifier = Notifier(host, desktop=False)
    for index in range(8):
        notifier.notify(f"Plugin {index} finished", "1,000 rows", "success")

    assert len(notifier._toasts) == 4, "a burst of runs must not bury the window"
    tops = [toast.y() for toast in notifier._toasts]
    assert tops == sorted(tops), "newest sits lowest"
    assert all(t.y() + t.height() <= host.height() for t in notifier._toasts)
    notifier.shutdown()


def test_turning_desktop_notifications_off_keeps_the_in_app_ones(qapp):
    from PyQt6.QtWidgets import QWidget
    from ui.notifications import Notifier

    notifier = Notifier(QWidget(), desktop=True)
    notifier.set_desktop_enabled(False)
    notifier.notify("Done", "", "success")
    assert notifier._tray is None
    assert len(notifier._toasts) == 1
    notifier.shutdown()


def test_a_finished_batch_is_announced_once(qapp, tmp_path, monkeypatch):
    from core.case import Case
    from ui.main_window import MainWindow

    window = MainWindow(Case.create(str(tmp_path), "Batch Case"))
    posted = []
    monkeypatch.setattr(window.notifier, "notify",
                        lambda title, body="", level="info": posted.append(title))

    window._batch_size = 3
    window._runners.clear()
    window._announce_idle()
    window._announce_idle()          # the batch is reported once, not per call

    assert [p for p in posted if p.startswith("All ")] == ["All 3 plugins finished"]
    window.close()


def test_a_single_run_is_not_announced_as_a_batch(qapp, tmp_path, monkeypatch):
    from core.case import Case
    from ui.main_window import MainWindow

    window = MainWindow(Case.create(str(tmp_path), "Single Case"))
    posted = []
    monkeypatch.setattr(window.notifier, "notify",
                        lambda title, body="", level="info": posted.append(title))
    window._batch_size = 1
    window._announce_idle()
    assert posted == []
    window.close()


def test_a_stored_font_is_applied_when_the_window_opens(qapp, tmp_path):
    """The choice has to reach the first stylesheet, not the second."""
    from PyQt6.QtWidgets import QApplication
    from core.case import Case
    from ui.main_window import MainWindow

    settings.save(ui_font="Fira Sans", font_size=15)
    case_dir = tmp_path / "case"
    window = MainWindow(Case.create(str(case_dir), "Font Case"))
    sheet = QApplication.instance().styleSheet()
    assert "'Fira Sans'" in sheet
    assert "font-size: 15px" in sheet
    window.close()
