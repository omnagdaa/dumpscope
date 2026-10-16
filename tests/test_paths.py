"""Per-user directories resolve to the platform's own location, not ~/.config."""

import os


from core import paths


def test_linux_follows_xdg(monkeypatch):
    monkeypatch.setattr(paths.sys, "platform", "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/xdg/config")
    monkeypatch.setenv("XDG_CACHE_HOME", "/xdg/cache")
    assert paths.config_dir() == os.path.join("/xdg/config", "dumpscope")
    assert paths.cache_dir() == os.path.join("/xdg/cache", "dumpscope")


def test_windows_uses_appdata_not_a_dotted_home_folder(monkeypatch):
    monkeypatch.setattr(paths.sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", r"C:\Users\admin\AppData\Roaming")
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\admin\AppData\Local")
    config, cache = paths.config_dir(), paths.cache_dir()
    assert config.startswith(r"C:\Users\admin\AppData\Roaming")
    assert cache.startswith(r"C:\Users\admin\AppData\Local")
    assert ".config" not in config and ".cache" not in cache


def test_windows_falls_back_when_appdata_is_unset(monkeypatch):
    monkeypatch.setattr(paths.sys, "platform", "win32")
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    assert "AppData" in paths.config_dir()


def test_macos_uses_application_support(monkeypatch):
    monkeypatch.setattr(paths.sys, "platform", "darwin")
    assert "Application Support" in paths.config_dir()
    assert "Caches" in paths.cache_dir()
