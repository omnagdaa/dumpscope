"""
Application preferences, shared by every case.

Case-level settings (the theme a case was last viewed in) live in case.json,
because they describe that investigation. Fonts and notification preferences
describe the examiner's machine, so they belong to the user rather than to any
one case and are written once, here.

Reads are cached; a write goes through to disk immediately, so preferences
survive a crash rather than only a clean exit.
"""

from __future__ import annotations

import json
import logging
import os

from core.paths import config_dir

log = logging.getLogger("dumpscope.settings")

DEFAULTS = {
    "ui_font": "",              # empty means the stylesheet's own stack
    "mono_font": "",
    "font_size": 13,            # the base size every other size scales from
    "desktop_notifications": True,
    # SMTP, for emailing a finished report. The password is deliberately absent:
    # it is asked for at send time and never written down.
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_from": "",
    "smtp_security": "starttls",
    "report_include_output": True,
}

_cache: dict | None = None


def settings_file() -> str:
    return os.path.join(config_dir(), "settings.json")


def load(refresh: bool = False) -> dict:
    global _cache
    if _cache is not None and not refresh:
        return _cache
    values = dict(DEFAULTS)
    try:
        with open(settings_file(), encoding="utf-8") as handle:
            stored = json.load(handle)
        if isinstance(stored, dict):
            # Unknown keys are dropped rather than kept: they are either from a
            # newer version or corruption, and neither should reach the UI.
            values.update({k: v for k, v in stored.items() if k in DEFAULTS})
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        log.warning("Could not read %s: %s", settings_file(), exc)
    _cache = values
    return values


def get(key: str, default=None):
    return load().get(key, DEFAULTS.get(key, default))


def save(**changes) -> dict:
    """Update and persist. Returns the full settings."""
    values = dict(load())
    values.update({k: v for k, v in changes.items() if k in DEFAULTS})
    global _cache
    _cache = values
    try:
        os.makedirs(config_dir(), exist_ok=True)
        with open(settings_file(), "w", encoding="utf-8") as handle:
            json.dump(values, handle, indent=2)
    except OSError as exc:
        log.warning("Could not write %s: %s", settings_file(), exc)
    return values


def reset() -> dict:
    """Back to the defaults, on disk as well as in memory."""
    return save(**DEFAULTS)
