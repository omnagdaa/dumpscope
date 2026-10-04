"""
The command palette: ranking, and the window's own command list.

The palette is the only surface that reaches every plugin without scrolling the
ribbon, so the ranking is load-bearing — a query that puts "Big Pools" above
"Process List" for "psl" would make it useless.
"""

import os
import tempfile

import pytest

from ui.command_palette import Command, CommandPalette, score


def _noop():
    return None


def _palette(qapp, commands):
    return CommandPalette(commands, is_dark=True)


def test_an_abbreviation_finds_the_plugin(qapp):
    palette = _palette(qapp, [
        Command("Big Pools", _noop, group="Run"),
        Command("Process List", _noop, group="Run"),
        Command("PsXView", _noop, group="Run"),
    ])
    palette._apply_filter("psl")
    assert palette._shown[0].title == "Process List"


def test_a_title_match_outranks_a_description_match(qapp):
    palette = _palette(qapp, [
        Command("Handles", _noop, subtitle="list open handles for each process"),
        Command("Process List", _noop, subtitle="running processes"),
    ])
    palette._apply_filter("process list")
    assert palette._shown[0].title == "Process List"


def test_a_query_matching_nothing_shows_the_empty_state(qapp):
    palette = _palette(qapp, [Command("Toggle Theme", _noop)])
    palette._apply_filter("zzzz")
    assert palette._shown == []
    assert not palette.list.isVisibleTo(palette)


def test_an_empty_query_keeps_the_callers_order(qapp):
    titles = ["Open Image…", "Export", "Toggle Theme"]
    palette = _palette(qapp, [Command(t, _noop) for t in titles])
    palette._apply_filter("")
    assert [c.title for c in palette._shown] == titles


def test_scoring_rejects_a_non_subsequence():
    assert score("xyz", Command("Process List", _noop)) is None
    assert score("plist", Command("Process List", _noop)) is not None


def test_running_a_command_closes_the_palette_first(qapp):
    """A command that opens a dialog must not open it underneath this one."""
    order = []
    palette = _palette(qapp, [Command("Do It", lambda: order.append("ran"))])
    palette.finished.connect(lambda _code: order.append("closed"))
    palette._apply_filter("")
    palette._activate_current()
    assert order == ["closed", "ran"]


def test_the_window_offers_its_verbs_and_its_plugins(qapp, tmp_path):
    from core.case import Case
    from ui.main_window import MainWindow

    case = Case.create(str(tmp_path), "Palette Case")
    window = MainWindow(case)
    commands = window._commands()
    titles = [command.title for command in commands]

    assert "Toggle Light / Dark Theme" in titles
    assert "Symbols & YARA…" in titles
    # Every plugin the ribbon is showing is reachable from the palette too.
    assert len([c for c in commands if c.group == "Run"]) == window.ribbon.plugin_count()
    window.close()
