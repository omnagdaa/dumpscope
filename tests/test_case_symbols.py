"""
Symbols belong to the case: every vol3 run reads and writes the case's own
symbols folder and identifier cache, never the per-user shared cache.
"""
import os
import subprocess
import sys

import pytest
from PyQt6.QtCore import QEventLoop, QTimer

from core import vol_runner
from core.case import CASE_SUBDIRS, Case
from core.symbol_downloader import SymbolFetcher, list_symbols
from core.vol_runner import (
    _CLI_ENTRY, RunSpec, build_environment, case_symbol_args,
)

STUB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stub_vol.py")


def test_case_symbol_args():
    assert case_symbol_args([], "") == []
    assert case_symbol_args(None) == []
    assert case_symbol_args(["", None and "x"]) == []
    args = case_symbol_args(["/c/symbols", "/extra"], "/c/cache")
    assert args == ["-s", os.path.abspath("/c/symbols") + ";" + os.path.abspath("/extra"),
                    "--cache-path", os.path.abspath("/c/cache")]


def test_relative_dirs_are_made_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    args = case_symbol_args(["symbols"], "cache")
    assert args[1] == str(tmp_path / "symbols") and args[3] == str(tmp_path / "cache")


def test_global_options_precede_the_plugin(monkeypatch):
    monkeypatch.setattr(vol_runner, "find_vol3_command", lambda: ["vol"])
    command = RunSpec("/i.raw", "windows.pslist.PsList", ["/c/symbols"], ["--pid", "4"],
                      output_dir="/c/dumps", cache_dir="/c/cache", clear_cache=True).command()
    plugin = command.index("windows.pslist.PsList")
    for flag in ("-s", "--cache-path", "-o", "-f", "--clear-cache", "-r"):
        assert command.index(flag) < plugin, flag
    assert command[plugin + 1:] == ["--pid", "4"]


def test_quick_analysis_spec_has_no_case_symbols(monkeypatch):
    monkeypatch.setattr(vol_runner, "find_vol3_command", lambda: ["vol"])
    command = RunSpec("/i.raw", "p", [], []).command()
    assert "-s" not in command and "--cache-path" not in command


def test_new_cases_have_a_cache_folder(tmp_path):
    case = Case.create(str(tmp_path), "C")
    assert "cache" in CASE_SUBDIRS
    assert os.path.isdir(os.path.join(case.directory, "cache"))
    assert case.vol_cache_dir == os.path.join(case.directory, "cache")


@pytest.fixture
def vol3_available():
    pytest.importorskip("volatility3")


def _symbol_paths(env):
    """Run the real CLI prelude and report vol3's symbol search path."""
    prelude = _CLI_ENTRY.rsplit("\n", 1)[0]
    code = prelude + ("\nfrom volatility3.framework import constants as k\n"
                      "import volatility3.symbols as s\n"
                      "print(repr((k.SYMBOL_BASEPATHS, list(s.__path__), k.CACHE_PATH)))")
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                         text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return eval(out.stdout.strip())


def test_cli_prelude_hides_the_shared_symbol_cache(vol3_available, tmp_path):
    base, path, cache = _symbol_paths(build_environment([str(tmp_path)]))
    shared = os.path.realpath(os.path.join(cache, "symbols"))
    assert shared not in [os.path.realpath(p) for p in base]
    assert shared not in [os.path.realpath(p) for p in path], \
        "symbols.__path__ must be the same trimmed list"


def test_cli_prelude_leaves_vol3_alone_without_case_symbols(vol3_available):
    base, _, cache = _symbol_paths(build_environment([]))
    assert os.path.realpath(os.path.join(cache, "symbols")) in [os.path.realpath(p) for p in base]


def test_runner_creates_the_cache_folder_and_passes_it(qapp, tmp_path, monkeypatch):
    monkeypatch.setattr(vol_runner, "find_vol3_command", lambda: [sys.executable, STUB])
    monkeypatch.setenv("STUB_VOL_FIXTURES", "1")
    log = tmp_path / "argv.log"
    monkeypatch.setenv("STUB_VOL_ARGV_LOG", str(log))
    symbols, cache = tmp_path / "case" / "symbols", tmp_path / "case" / "cache"
    runner = vol_runner.VolatilityRunner(
        RunSpec(str(tmp_path / "i.raw"), "windows.pslist.PsList", [str(symbols)], [],
                cache_dir=str(cache)), gate=vol_runner.RunGate(1))
    loop = QEventLoop()
    done = []
    runner.run_finished.connect(lambda code: (done.append(code), loop.quit()))
    QTimer.singleShot(20000, loop.quit)
    runner.start()
    loop.exec()
    runner.wait(5000)
    assert done == [0]
    assert cache.is_dir() and symbols.is_dir()
    argv = log.read_text().split("\t")
    assert argv[argv.index("-s") + 1] == str(symbols)
    assert argv[argv.index("--cache-path") + 1] == str(cache)


def test_os_probe_uses_the_case_symbols(qapp, tmp_path, monkeypatch):
    from core import os_detect
    seen = []
    monkeypatch.setattr(os_detect, "find_vol3_command", lambda: ["vol"])
    probe = os_detect.ImageProbe(str(tmp_path / "i.raw"), [str(tmp_path / "symbols")],
                                 cache_dir=str(tmp_path / "cache"))
    monkeypatch.setattr(probe, "_guarded",
                        lambda command, timeout: (seen.append(command), (1, "", ""))[1])
    probe._probe_windows(str(tmp_path / "i.raw"))
    probe._probe_banners(str(tmp_path / "i.raw"))
    for command in seen:
        assert command[command.index("-s") + 1] == str(tmp_path / "symbols")
        assert command[command.index("--cache-path") + 1] == str(tmp_path / "cache")


# ── Fetching symbols for one image ────────────────────────────────────────────

def _fetch(qapp, base, image, monkeypatch, **env):
    monkeypatch.setattr(vol_runner, "find_vol3_command", lambda: [sys.executable, STUB])
    monkeypatch.setenv("STUB_VOL_FIXTURES", "1")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    fetcher = SymbolFetcher(str(image), str(base))
    out = []
    loop = QEventLoop()
    fetcher.done.connect(lambda ok, msg, added: (out.append((ok, msg, added)), loop.quit()))
    QTimer.singleShot(20000, loop.quit)
    fetcher.start()
    loop.exec()
    fetcher.wait(5000)
    assert out, "SymbolFetcher never reported"
    return out[0]


def test_fetch_writes_the_isf_into_the_case(qapp, tmp_path, monkeypatch):
    image = tmp_path / "i.raw"
    image.write_bytes(b"\0")
    ok, message, added = _fetch(qapp, tmp_path / "case", image, monkeypatch, STUB_FETCH_ISF="1")
    assert ok and "Fetched 1" in message
    assert added == [os.path.join("windows", "ntkrnlmp.pdb",
                                  "3844DBB920174967BE7AA4A2C20430FA-2.json.xz")]
    assert list_symbols(str(tmp_path / "case"))[0][0] == added[0]


def test_fetch_when_symbols_are_already_present(qapp, tmp_path, monkeypatch):
    image = tmp_path / "i.raw"
    image.write_bytes(b"\0")
    ok, message, added = _fetch(qapp, tmp_path / "case", image, monkeypatch)
    assert ok and added == [] and "already" in message


def test_fetch_failure_is_explained(qapp, tmp_path, monkeypatch):
    image = tmp_path / "i.raw"
    image.write_bytes(b"\0")
    ok, message, _ = _fetch(qapp, tmp_path / "case", image, monkeypatch, STUB_INFO_FAIL="1")
    assert not ok and "msdl.microsoft.com" in message


def test_fetch_without_an_image(qapp, tmp_path, monkeypatch):
    ok, message, _ = _fetch(qapp, tmp_path / "case", tmp_path / "missing.raw", monkeypatch)
    assert not ok and "No memory image" in message


def test_list_symbols(tmp_path):
    assert list_symbols(str(tmp_path)) == []
    folder = tmp_path / "symbols" / "windows" / "nt.pdb"
    folder.mkdir(parents=True)
    (folder / "A-1.json.xz").write_bytes(b"12345")
    (folder / "notes.txt").write_text("not a symbol")
    assert list_symbols(str(tmp_path)) == [(os.path.join("windows", "nt.pdb", "A-1.json.xz"), 5)]


# ── The window ────────────────────────────────────────────────────────────────

def test_quick_analysis_never_seeds_the_home_folder(qapp, tmp_path, monkeypatch):
    from core.plugins import PluginRegistry
    from ui.main_window import MainWindow
    home = tmp_path / "home"
    home.mkdir()
    window = MainWindow(Case.quick(str(home)), registry=PluginRegistry(None))
    assert window.symbol_dirs == [] and window.vol_cache_dir == ""
    assert os.listdir(home) == []
    window.close()


def test_case_window_points_vol3_at_the_case(qapp, tmp_path):
    from core.plugins import PluginRegistry
    from ui.main_window import MainWindow
    case = Case.create(str(tmp_path), "Sym Case")
    window = MainWindow(case, registry=PluginRegistry(None))
    assert window.symbol_dirs == [os.path.join(case.directory, "symbols")]
    assert window.vol_cache_dir == os.path.join(case.directory, "cache")
    window.close()
