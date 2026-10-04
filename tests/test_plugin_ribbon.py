"""
The ribbon: OS scoping, search, and the fact that a run in flight survives
both of them.
"""

import pytest

from core.plugins import PluginRegistry
from ui.plugin_ribbon import PluginRibbon


@pytest.fixture(scope="module")
def registry():
    reg = PluginRegistry.load()
    if not reg.available or not reg.for_os("windows"):
        pytest.skip("volatility3 is not installed in this environment")
    return reg


@pytest.fixture
def ribbon(qapp, registry):
    widget = PluginRibbon(registry)
    widget.set_os("windows", "Windows")
    yield widget
    widget.deleteLater()


def test_tiles_are_scoped_to_the_operating_system(ribbon, registry):
    assert ribbon.plugin_count() == len(
        [p for _c, _col, group in registry.ribbon("windows") for p in group]
    )
    for plugin_id in ribbon._buttons:
        # "generic" plugins (banners, layerwriter) run against any image.
        assert registry.get(plugin_id).os in ("windows", "generic", "any")


def test_switching_os_replaces_the_tiles(ribbon, registry):
    before = set(ribbon._buttons)
    ribbon.set_os("linux", "Linux")
    after = set(ribbon._buttons)
    assert before != after
    assert not any(pid.startswith("windows.") for pid in after)


def test_setting_the_same_os_twice_is_a_no_op(ribbon):
    buttons = dict(ribbon._buttons)
    ribbon.set_os("windows", "Windows")
    # Same widget objects, so a tile's running badge is not silently discarded.
    assert ribbon._buttons == buttons


def test_search_hides_everything_that_does_not_match(ribbon):
    ribbon.search.setText("pslist")
    visible = [pid for pid, b in ribbon._buttons.items() if not b.isHidden()]
    assert visible, "pslist should match something"
    assert all("pslist" in pid.lower() for pid in visible)


def test_search_matches_words_in_any_order(ribbon):
    ribbon.search.setText("list process")
    visible = [pid for pid, b in ribbon._buttons.items() if not b.isHidden()]
    assert any("pslist" in pid.lower() for pid in visible)


def test_clearing_the_search_restores_every_tile(ribbon):
    total = ribbon.plugin_count()
    ribbon.search.setText("zzzz-no-such-plugin")
    assert all(b.isHidden() for b in ribbon._buttons.values())
    assert ribbon.empty_lbl.isVisibleTo(ribbon), "the empty state should be shown"
    ribbon.search.clear()
    assert sum(not b.isHidden() for b in ribbon._buttons.values()) == total


def test_a_running_tile_keeps_its_state_through_a_search(ribbon):
    """
    The old ribbon was destroyed and rebuilt on every change, which threw away
    the badge on whatever was still running.
    """
    plugin_id = next(iter(ribbon._buttons))
    ribbon.set_running(plugin_id, True)
    ribbon.search.setText("a")
    ribbon.search.clear()
    assert ribbon._buttons[plugin_id].property("state") == "running"
    ribbon.set_running(plugin_id, False)
    assert ribbon._buttons[plugin_id].property("state") == "idle"


def test_density_toggle_resizes_every_tile(ribbon):
    tile = next(iter(ribbon._buttons.values()))
    compact_height = tile.height()
    ribbon.set_compact(False)
    assert tile.height() > compact_height
    ribbon.set_compact(True)
    assert tile.height() == compact_height


def test_clicking_a_tile_emits_its_plugin_id(ribbon):
    received = []
    ribbon.plugin_clicked.connect(received.append)
    plugin_id = next(iter(ribbon._buttons))
    ribbon._buttons[plugin_id].clicked.emit(plugin_id)
    assert received == [plugin_id]
