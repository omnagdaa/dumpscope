"""
Per-user directories, resolved per platform.

XDG variables are a Linux convention. On Windows they are unset, so
``~/.config`` and ``~/.cache`` would be created inside the user profile as
literal dotted folders — invisible in Explorer, outside every backup and
roaming policy, and not where anything else on the system looks. On macOS the
equivalent is ``~/Library/Application Support``.
"""

from __future__ import annotations

import os
import sys

APP = "dumpscope"



def config_dir() -> str:
    """Where settings live: %APPDATA%, ~/Library/Application Support, or $XDG_CONFIG_HOME."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Roaming")
    elif sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, APP)


def cache_dir() -> str:
    """Where regenerable data lives: %LOCALAPPDATA%, ~/Library/Caches, or $XDG_CACHE_HOME."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local")
    elif sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Caches")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, APP)
