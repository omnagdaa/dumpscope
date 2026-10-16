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
    "report_include_output": True,
    # How many volatility3 processes may run at once. 1 serialises them, which
    # protects vol3's shared cache and keeps memory use predictable.
    "max_parallel_runs": 1,
    "sidebar_visible": True,
}

# Bounds on numeric settings; anything outside is treated as invalid.
_RANGES = {
    "font_size": (6, 48),
    "max_parallel_runs": (1, 8),
}

_INVALID = object()

_cache: dict | None = None


def _coerce(key: str, value):
    """`value` as the type its default has, or _INVALID when it cannot be."""
    default = DEFAULTS[key]
    if isinstance(default, bool):
        return value if isinstance(value, bool) else _INVALID
    if isinstance(default, int):
        if isinstance(value, bool):
            return _INVALID
        try:
            number = int(value)
        except (TypeError, ValueError):
            return _INVALID
        low, high = _RANGES.get(key, (None, None))
        if low is not None and not low <= number <= high:
            return _INVALID
        return number
    if isinstance(default, str):
        return value if isinstance(value, str) else _INVALID
    return value


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
            # So are values of the wrong type — `int("big")` on a hand-edited
            # font size would otherwise crash the window at startup.
            for key, value in stored.items():
                if key in DEFAULTS:
                    coerced = _coerce(key, value)
                    if coerced is not _INVALID:
                        values[key] = coerced
                    else:
                        log.warning("Ignoring invalid %s=%r in settings", key, value)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, RecursionError) as exc:   # nested-JSON bomb
        log.warning("Could not read %s: %s", settings_file(), exc)
    _cache = values
    return values


def get(key: str, default=None):
    return load().get(key, DEFAULTS.get(key, default))


def save(**changes) -> dict:
    """Update and persist. Returns the full settings."""
    values = dict(load())
    for key, value in changes.items():
        if key in DEFAULTS:
            coerced = _coerce(key, value)
            if coerced is not _INVALID:
                values[key] = coerced
    global _cache
    _cache = values
    try:
        os.makedirs(config_dir(), exist_ok=True)
        # Atomic, like case.json: a crash mid-write must not leave half a file.
        temporary = settings_file() + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(values, handle, indent=2)
        os.replace(temporary, settings_file())
    except OSError as exc:
        log.warning("Could not write %s: %s", settings_file(), exc)
    return values


