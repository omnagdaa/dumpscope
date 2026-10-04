"""
The theme's contract: two palettes that cannot drift apart, and no colour left
hardcoded in a widget where the stylesheet cannot reach it.
"""

import pathlib
import re

import pytest

from ui import theme

UI_DIR = pathlib.Path(__file__).resolve().parent.parent / "ui"


def test_both_palettes_define_the_same_tokens():
    """
    The reason the light theme was broken: the two blocks were maintained by
    hand and one had rules the other did not.
    """
    assert set(theme.DARK) == set(theme.LIGHT)


def test_every_token_is_a_colour():
    for name, palette in (("dark", theme.DARK), ("light", theme.LIGHT)):
        for key, value in palette.items():
            assert re.fullmatch(r"#[0-9a-f]{6}", value), f"{name}.{key} = {value}"


@pytest.mark.parametrize("dark", [True, False])
def test_stylesheet_has_no_unsubstituted_placeholders(dark):
    sheet = theme.build(dark=dark)
    assert "$" not in sheet
    assert sheet.strip()


def test_the_two_stylesheets_differ_only_in_colour():
    """Structure comes from one template, so the rule text must be identical."""
    strip = lambda sheet: re.sub(r"#[0-9a-f]{6}", "#", sheet)
    assert strip(theme.build(dark=True)) == strip(theme.build(dark=False))


def test_results_table_is_styled():
    """
    QTableWidget selectors do not match a plain QTableView, and the results
    grid is a QTableView — it went unthemed for exactly this reason.
    """
    assert "QTableView" in theme.build(dark=True)


def test_widgets_do_not_hardcode_colours():
    """
    An inline stylesheet outranks the application one, so a literal colour in
    a widget is a permanent theme override. The few that remain are colours
    that come from data rather than from the palette, and are listed here.
    """
    allowed = {
        "theme.py",           # the palettes themselves
        "plugin_ribbon.py",   # a plugin category's colour, which is data
        "wizard.py",          # the "required field" asterisk
        "icons.py",           # the neutral ink a glyph falls back to
    }
    offenders = {}
    for path in UI_DIR.glob("*.py"):
        if path.name in allowed:
            continue
        found = re.findall(r"#[0-9a-fA-F]{6}", path.read_text())
        if found:
            offenders[path.name] = found
    assert not offenders, f"hardcoded colours outside the theme: {offenders}"


def test_restyle_repolishes(qapp):
    from PyQt6.QtWidgets import QLabel

    label = QLabel("x")
    label.setProperty("state", "done")
    theme.restyle(label)          # must not raise without a parent or a sheet
    assert label.property("state") == "done"
