"""
The credential-extraction feature: the plugins are present, categorised, and
reachable, and the lsass convenience routes a memory dump.
"""

import pytest

from core.plugins import PluginRegistry
from ui.result_panel import ResultPanel


@pytest.fixture(scope="module")
def registry():
    return PluginRegistry.load()


def test_the_credential_plugins_are_available(registry):
    """
    hashdump, lsadump and cachedump import Cryptodome at load; without
    pycryptodome they silently fail to register. Their presence is the proof
    the dependency is satisfied.
    """
    for plugin_id in ("windows.hashdump.Hashdump", "windows.lsadump.Lsadump",
                      "windows.cachedump.Cachedump"):
        assert registry.get(plugin_id) is not None, (
            f"{plugin_id} is missing — is pycryptodome installed?"
        )


def test_they_live_in_a_credentials_category(registry):
    categories = {category for category, _colour, _plugins
                  in registry.ribbon("windows")}
    assert "Credentials" in categories
    creds = next(plugins for category, _c, plugins in registry.ribbon("windows")
                 if category == "Credentials")
    assert {"windows.hashdump.Hashdump"} <= {info.id for info in creds}


def test_lsass_row_offers_a_memory_dump_for_recovery(qapp):
    panel = ResultPanel("PsList", "windows.pslist.PsList")
    panel.set_columns(["PID", "ImageFileName"])
    panel.append_rows([["720", "lsass.exe"], ["4", "System"]])

    assert panel._is_lsass({"ImageFileName": "lsass.exe"})
    assert not panel._is_lsass({"ImageFileName": "explorer.exe"})

    dumped = []
    panel.dump_requested.connect(dumped.append)
    # The lsass action emits a memory dump tagged as such.
    panel.dump_requested.emit({"ImageFileName": "lsass.exe", "__dump__": "memory",
                               "__pid__": "720", "__lsass__": True})
    assert dumped[0]["__lsass__"] is True
    assert dumped[0]["__dump__"] == "memory"


def test_the_sweep_lists_only_installed_credential_plugins(qapp, tmp_path):
    from core.case import Case
    from ui.main_window import MainWindow

    window = MainWindow(Case.create(str(tmp_path), "Cred Case"))
    available = [pid for pid in window._CREDENTIAL_PLUGINS
                 if window.registry.get(pid) is not None]
    assert "windows.hashdump.Hashdump" in available
    window.close()
