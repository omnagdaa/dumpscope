"""
Plugin registry for DumpScope.

Two sources of truth, layered:

1. INTROSPECTED — the real plugin list is read out of the installed volatility3
   at runtime (in a subprocess, so vol3 never gets imported into the GUI
   process). This yields every plugin id plus, crucially, which *required*
   arguments each one takes. A plugin with an unsatisfied required argument
   cannot be launched from a one-click button; it needs a parameter prompt.

2. CURATED — a hand-maintained catalog that assigns category, icon, colour and
   a short display name to the plugins worth surfacing on the ribbon. Anything
   introspected but not curated is still reachable from the full plugin browser.

The introspected result is cached to disk keyed by the volatility3 version, so
the multi-second import cost is paid once per vol3 upgrade rather than per
launch.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass

from core.paths import cache_dir

log = logging.getLogger("dumpscope.plugins")

# Requirement names that the CLI satisfies automatically from -f/--single-location.
# A required requirement with one of these names is not a user-facing argument.
_IMPLICIT_REQUIREMENTS = {
    "primary", "kernel", "nt_symbols", "vmlinux", "darwin", "memory_layer",
}

# Requirement classes that express an inter-plugin dependency rather than input.
_NON_INPUT_REQUIREMENT_TYPES = {
    "VersionRequirement", "PluginRequirement", "ModuleRequirement",
    "TranslationLayerRequirement", "SymbolTableRequirement",
}


@dataclass(frozen=True)
class PluginArg:
    """A single user-supplied argument to a volatility3 plugin."""
    name: str
    kind: str          # Int | String | URI | Boolean | List | Choice | Bytes
    required: bool
    description: str = ""
    default: object = None

    @property
    def cli_flag(self) -> str:
        return "--" + self.name.replace("_", "-")


@dataclass(frozen=True)
class PluginInfo:
    """Everything DumpScope knows about one volatility3 plugin."""
    id: str                                  # e.g. windows.pslist.PsList
    os: str                                  # windows | linux | mac | generic
    args: tuple[PluginArg, ...] = ()
    description: str = ""

    # Curated presentation fields; empty when the plugin is not on the ribbon.
    name: str = ""
    category: str = ""
    icon: str = ""
    color: str = ""

    @property
    def short_name(self) -> str:
        return self.name or self.id.rsplit(".", 1)[-1]

    @property
    def required_args(self) -> tuple[PluginArg, ...]:
        return tuple(a for a in self.args if a.required)

    @property
    def optional_args(self) -> tuple[PluginArg, ...]:
        return tuple(a for a in self.args if not a.required)

    @property
    def needs_input(self) -> bool:
        """True when the plugin cannot run without the user supplying something."""
        return bool(self.required_args)


# ── Introspection ─────────────────────────────────────────────────────────────

# Run inside a throwaway subprocess. Imports all 180+ plugin modules, which is
# slow and pollutes sys.modules — neither belongs in the GUI process.
_INTROSPECT_SRC = r"""
import json, sys
import volatility3
import volatility3.plugins
from volatility3 import framework

framework.import_files(volatility3.plugins, True)

IMPLICIT = %(implicit)r
NON_INPUT = %(non_input)r

from volatility3.framework import constants
out = {"version": constants.PACKAGE_VERSION, "plugins": {}}
for pid, cls in framework.list_plugins().items():
    args = []
    try:
        requirements = cls.get_requirements()
    except Exception:
        requirements = []
    for req in requirements:
        kind = type(req).__name__
        if kind in NON_INPUT or req.name in IMPLICIT:
            continue
        args.append({
            "name": req.name,
            "kind": kind.replace("Requirement", ""),
            "required": not req.optional,
            "description": (req.description or ""),
            "default": req.default if isinstance(
                req.default, (int, float, str, bool, type(None))) else None,
        })
    out["plugins"][pid] = {
        "args": args,
        "description": (cls.__doc__ or "").strip().split("\n")[0],
    }
json.dump(out, sys.stdout)
""" % {"implicit": sorted(_IMPLICIT_REQUIREMENTS),
       "non_input": sorted(_NON_INPUT_REQUIREMENT_TYPES)}


def _cache_path() -> str:
    return os.path.join(cache_dir(), "plugin_registry.json")


def introspect(python: str | None = None, timeout: int = 180) -> dict:
    """
    Import volatility3 in a subprocess and return
    {"version": str, "plugins": {id: {"args": [...], "description": str}}}.

    Raises on failure; callers should fall back to the curated catalog.
    """
    python = python or sys.executable
    proc = subprocess.run(
        [python, "-P", "-c", _INTROSPECT_SRC],     # -P: no imports from the cwd
        capture_output=True, encoding="utf-8", errors="replace", timeout=timeout,
        creationflags=(subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0),
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"volatility3 introspection failed (exit {proc.returncode}): "
            f"{proc.stderr.strip()[:400]}"
        )
    return json.loads(proc.stdout)


def installed_version() -> str | None:
    """volatility3's version without importing any plugin modules. None if absent."""
    try:
        from volatility3.framework import constants
        return constants.PACKAGE_VERSION
    except Exception:
        return None


def load_introspected(refresh: bool = False) -> dict | None:
    """
    Cached introspect(). The cache is invalidated whenever the installed
    volatility3 version differs from the one that produced it, so upgrading
    vol3 picks up new and relocated plugins without a manual refresh.

    Returns None when volatility3 cannot be inspected.
    """
    path = _cache_path()
    current = installed_version()
    if not refresh and os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                cached = json.load(fh)
            if current is None or cached.get("version") == current:
                return cached
            log.info(
                "Plugin cache was built for volatility3 %s, installed is %s — refreshing",
                cached.get("version"), current,
            )
        except Exception as exc:
            log.warning("Ignoring unreadable plugin cache %s: %s", path, exc)
    try:
        data = introspect()
    except Exception as exc:
        log.warning("Plugin introspection unavailable: %s", exc)
        return None
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
    except Exception as exc:
        log.debug("Could not write plugin cache: %s", exc)
    return data


# ── Curated ribbon catalog ────────────────────────────────────────────────────
#
# Plugin ids here are the CURRENT volatility3 names. Several analysis plugins
# were relocated into the windows.malware.* / windows.registry.* namespaces;
# the pre-migration ids still resolve today as deprecated aliases but are not
# guaranteed to survive, so the new path is used throughout.

CATEGORIES: tuple[tuple[str, str], ...] = (
    ("Processes", "#7fbfa6"),
    ("Network",   "#8fbf7f"),
    ("Memory",    "#e0a06a"),
    ("Registry",  "#b39ddb"),
    ("System",    "#d9c07a"),
    ("Credentials", "#d98fb0"),
    ("Malware",   "#e0796f"),
)

CATEGORY_COLORS = dict(CATEGORIES)

# (id, display name, icon, category)
_CATALOG: dict[str, tuple[tuple[str, str, str, str], ...]] = {
    "windows": (
        ("windows.pslist.PsList",                     "Process List",   "🗂", "Processes"),
        ("windows.pstree.PsTree",                     "Process Tree",   "🌲", "Processes"),
        ("windows.psscan.PsScan",                     "Process Scan",   "🔎", "Processes"),
        ("windows.cmdline.CmdLine",                   "Command Line",   "💬", "Processes"),
        ("windows.dlllist.DllList",                   "DLL List",       "📦", "Processes"),
        ("windows.handles.Handles",                   "Handles",        "🔗", "Processes"),
        ("windows.getsids.GetSIDs",                   "Process SIDs",   "🪪", "Processes"),
        ("windows.privileges.Privs",                  "Privileges",     "🔐", "Processes"),
        ("windows.envars.Envars",                     "Env Vars",       "🌱", "Processes"),

        ("windows.netscan.NetScan",                   "Net Scan",       "📡", "Network"),
        ("windows.netstat.NetStat",                   "Net Stat",       "🌐", "Network"),

        ("windows.memmap.Memmap",                     "Memory Map",     "🗺", "Memory"),
        ("windows.vadinfo.VadInfo",                   "VAD Info",       "🧩", "Memory"),
        ("windows.vadwalk.VadWalk",                   "VAD Walk",       "🚶", "Memory"),
        ("windows.dumpfiles.DumpFiles",               "Dump Files",     "💾", "Memory"),
        ("windows.filescan.FileScan",                 "File Scan",      "🔍", "Memory"),
        ("windows.mutantscan.MutantScan",             "Mutants",        "🔒", "Memory"),
        ("windows.bigpools.BigPools",                 "Big Pools",      "🫧", "Memory"),

        ("windows.registry.hivelist.HiveList",        "Hive List",      "📋", "Registry"),
        ("windows.registry.printkey.PrintKey",        "Print Key",      "🔑", "Registry"),
        ("windows.registry.userassist.UserAssist",    "User Assist",    "👤", "Registry"),
        ("windows.registry.amcache.Amcache",          "Amcache",        "🧾", "Registry"),
        ("windows.registry.certificates.Certificates","Certificates",   "📜", "Registry"),
        ("windows.registry.scheduled_tasks.ScheduledTasks", "Sched Tasks", "⏰", "Registry"),

        ("windows.info.Info",                         "System Info",    "ℹ", "System"),
        ("windows.modules.Modules",                   "Modules",        "⚙", "System"),
        ("windows.modscan.ModScan",                   "Module Scan",    "🧰", "System"),
        ("windows.driverscan.DriverScan",             "Driver Scan",    "🚗", "System"),
        ("windows.svcscan.SvcScan",                   "Services",       "🛠", "System"),
        ("windows.ssdt.SSDT",                         "SSDT",           "🛡", "System"),
        ("windows.sessions.Sessions",                 "Sessions",       "🖥", "System"),
        ("windows.unloadedmodules.UnloadedModules",   "Unloaded Mods",  "📤", "System"),
        ("windows.callbacks.Callbacks",               "Callbacks",      "📞", "System"),
        ("windows.timers.Timers",                     "Timers",         "⏱", "System"),

        ("windows.hashdump.Hashdump",                 "Password Hashes", "🔓", "Credentials"),
        ("windows.lsadump.Lsadump",                   "LSA Secrets",     "🗝", "Credentials"),
        ("windows.cachedump.Cachedump",               "Cached Domain",   "🎫", "Credentials"),

        ("windows.malware.malfind.Malfind",           "Malfind",        "🦠", "Malware"),
        ("windows.malware.psxview.PsXView",           "PsXView",        "👻", "Malware"),
        ("windows.malware.ldrmodules.LdrModules",     "Ldr Modules",    "🧬", "Malware"),
        ("windows.malware.hollowprocesses.HollowProcesses", "Hollowing", "🕳", "Malware"),
        ("windows.malware.processghosting.ProcessGhosting", "Ghosting",  "🫥", "Malware"),
        ("windows.malware.suspicious_threads.SuspiciousThreads", "Susp Threads", "🧵", "Malware"),
        ("windows.malware.unhooked_system_calls.UnhookedSystemCalls", "Unhooked Calls", "🪝", "Malware"),
        ("windows.malware.svcdiff.SvcDiff",           "Service Diff",   "🔀", "Malware"),
        ("windows.malware.drivermodule.DriverModule", "Driver Module",  "🔌", "Malware"),
        ("windows.malware.skeleton_key_check.Skeleton_Key_Check", "Skeleton Key", "🗝", "Malware"),
        ("windows.malware.pebmasquerade.PebMasquerade", "PEB Masquerade", "🎭", "Malware"),
        ("windows.etwpatch.EtwPatch",                 "ETW Patch",      "🩹", "Malware"),
    ),
    "linux": (
        ("linux.pslist.PsList",             "Process List",  "🗂", "Processes"),
        ("linux.pstree.PsTree",             "Process Tree",  "🌲", "Processes"),
        ("linux.psscan.PsScan",             "Process Scan",  "🔎", "Processes"),
        ("linux.psaux.PsAux",               "Ps Aux",        "💬", "Processes"),
        ("linux.envars.Envars",             "Env Vars",      "🌱", "Processes"),
        ("linux.lsof.Lsof",                 "Open Files",    "🔗", "Processes"),
        ("linux.capabilities.Capabilities", "Capabilities",  "🔐", "Processes"),
        ("linux.ptrace.Ptrace",             "Ptrace",        "🪢", "Processes"),

        ("linux.sockstat.Sockstat",         "Sock Stat",     "📡", "Network"),
        ("linux.ip.Addr",                   "IP Addr",       "🌐", "Network"),
        ("linux.ip.Link",                   "IP Link",       "🔌", "Network"),
        ("linux.sockscan.Sockscan",         "Sock Scan",     "🛰", "Network"),

        ("linux.proc.Maps",                 "Proc Maps",     "🧩", "Memory"),
        ("linux.elfs.Elfs",                 "ELF Files",     "📦", "Memory"),
        ("linux.library_list.LibraryList",  "Libraries",     "📚", "Memory"),
        ("linux.pagecache.Files",           "Page Cache",    "🗂", "Memory"),
        ("linux.mountinfo.MountInfo",       "Mounts",        "💽", "Memory"),

        ("linux.lsmod.Lsmod",               "Modules",       "⚙", "System"),
        ("linux.bash.Bash",                 "Bash History",  "📜", "System"),
        ("linux.boottime.Boottime",         "Boot Time",     "🕰", "System"),
        ("linux.kmsg.Kmsg",                 "Kernel Log",    "📰", "System"),
        ("linux.iomem.IOMem",               "IO Memory",     "🧮", "System"),
        ("linux.kthreads.Kthreads",         "Kernel Threads", "🧵", "System"),

        ("linux.malware.malfind.Malfind",           "Malfind",        "🦠", "Malware"),
        ("linux.malware.hidden_modules.Hidden_modules", "Hidden Mods", "👻", "Malware"),
        ("linux.malware.check_syscall.Check_syscall",   "Syscall Check", "🛡", "Malware"),
        ("linux.malware.check_modules.Check_modules",   "Module Check",  "🔍", "Malware"),
        ("linux.malware.check_creds.Check_creds",       "Cred Check",    "🪪", "Malware"),
        ("linux.malware.process_spoofing.ProcessSpoofing", "Ps Spoofing", "🎭", "Malware"),
        ("linux.malware.tty_check.Tty_Check",           "TTY Check",     "⌨", "Malware"),
        ("linux.malware.netfilter.Netfilter",           "Netfilter",     "🧱", "Malware"),
        ("linux.malware.modxview.Modxview",             "Modxview",      "🧬", "Malware"),
    ),
    "mac": (
        ("mac.pslist.PsList",       "Process List", "🗂", "Processes"),
        ("mac.pstree.PsTree",       "Process Tree", "🌲", "Processes"),
        ("mac.psaux.Psaux",         "Ps Aux",       "💬", "Processes"),
        ("mac.lsof.Lsof",           "Open Files",   "🔗", "Processes"),

        ("mac.netstat.Netstat",     "Net Stat",     "🌐", "Network"),
        ("mac.ifconfig.Ifconfig",   "Ifconfig",     "📡", "Network"),
        ("mac.socket_filters.Socket_filters", "Socket Filters", "🧱", "Network"),

        ("mac.proc_maps.Maps",      "Proc Maps",    "🧩", "Memory"),
        ("mac.list_files.List_Files", "File List",  "🔍", "Memory"),
        ("mac.mount.Mount",         "Mounts",       "💽", "Memory"),

        ("mac.lsmod.Lsmod",         "Modules",      "⚙", "System"),
        ("mac.bash.Bash",           "Bash History", "📜", "System"),
        ("mac.dmesg.Dmesg",         "Kernel Log",   "📰", "System"),
        ("mac.timers.Timers",       "Timers",       "⏱", "System"),
        ("mac.kevents.Kevents",     "Kevents",      "📌", "System"),

        ("mac.malfind.Malfind",             "Malfind",       "🦠", "Malware"),
        ("mac.check_syscall.Check_syscall", "Syscall Check", "🛡", "Malware"),
        ("mac.check_trap_table.Check_trap_table", "Trap Table", "🪤", "Malware"),
        ("mac.trustedbsd.Trustedbsd",       "TrustedBSD",    "🔐", "Malware"),
        ("mac.kauth_scopes.Kauth_scopes",   "Kauth Scopes",  "🧿", "Malware"),
    ),
}

# Plugins worth offering regardless of the detected OS.
_CATALOG_GENERIC: tuple[tuple[str, str, str, str], ...] = (
    ("banners.Banners",     "Banners",   "🏷", "System"),
    ("timeliner.Timeliner", "Timeline",  "📅", "System"),
    ("regexscan.RegExScan", "RegEx Scan", "🎯", "Malware"),
)


def plugin_os(plugin_id: str) -> str:
    head = plugin_id.split(".", 1)[0]
    return head if head in ("windows", "linux", "mac") else "generic"


class PluginRegistry:
    """
    The merged view of curated presentation data and introspected truth.

    Built once and shared. When introspection is unavailable (volatility3 not
    importable), the registry still works from the curated catalog alone — it
    just cannot report argument requirements, so `available` is False and
    callers should warn rather than silently offering plugins that may not run.
    """

    def __init__(self, introspected: dict | None = None):
        self._raw = introspected or {}
        self.vol_version: str = self._raw.get("version", "unknown")
        self.available: bool = bool(self._raw.get("plugins"))
        self._plugins: dict[str, PluginInfo] = {}
        self._build()

    @classmethod
    def load(cls, refresh: bool = False) -> "PluginRegistry":
        return cls(load_introspected(refresh=refresh))

    def _build(self):
        introspected = self._raw.get("plugins", {})

        # Every introspected plugin is known, even if not curated.
        for pid, meta in introspected.items():
            self._plugins[pid] = PluginInfo(
                id=pid,
                os=plugin_os(pid),
                args=tuple(
                    PluginArg(
                        name=a["name"], kind=a["kind"], required=a["required"],
                        description=a.get("description", ""), default=a.get("default"),
                    )
                    for a in meta.get("args", ())
                ),
                description=meta.get("description", ""),
            )

        # Overlay curated presentation data.
        curated: list[tuple[str, tuple[str, str, str, str]]] = []
        for os_name, entries in _CATALOG.items():
            curated += [(os_name, e) for e in entries]
        curated += [("generic", e) for e in _CATALOG_GENERIC]

        for os_name, (pid, name, icon, category) in curated:
            existing = self._plugins.get(pid)
            if existing is None:
                if self.available:
                    # Curated id that the installed volatility3 does not have.
                    log.warning(
                        "Catalog plugin %s is not present in volatility3 %s — hiding it",
                        pid, self.vol_version,
                    )
                    continue
                existing = PluginInfo(id=pid, os=os_name)
            self._plugins[pid] = PluginInfo(
                id=pid,
                os=os_name,
                args=existing.args,
                description=existing.description,
                name=name,
                icon=icon,
                category=category,
                color=CATEGORY_COLORS.get(category, "#95a09b"),
            )

    # ── Lookup ────────────────────────────────────────────────────────────────

    def get(self, plugin_id: str) -> PluginInfo | None:
        return self._plugins.get(plugin_id)

    def all(self) -> list[PluginInfo]:
        return sorted(self._plugins.values(), key=lambda p: p.id)

    def for_os(self, os_name: str, curated_only: bool = True) -> list[PluginInfo]:
        """Plugins applicable to `os_name`, plus the OS-agnostic ones."""
        out = [
            p for p in self._plugins.values()
            if p.os in (os_name, "generic") and (p.name or not curated_only)
        ]
        return out

    def ribbon(self, os_name: str) -> list[tuple[str, str, list[PluginInfo]]]:
        """
        Ribbon layout: [(category, colour, [plugins...])] in CATEGORIES order,
        preserving catalog order within each category and dropping empties.
        """
        order = {pid: i for i, (pid, *_) in enumerate(
            _CATALOG.get(os_name, ()) + _CATALOG_GENERIC
        )}
        groups = []
        for category, color in CATEGORIES:
            members = [
                p for p in self.for_os(os_name) if p.category == category
            ]
            members.sort(key=lambda p: order.get(p.id, 10_000))
            if members:
                groups.append((category, color, members))
        return groups

    def search(self, text: str, os_name: str | None = None) -> list[PluginInfo]:
        text = text.strip().lower()
        pool = self.all() if os_name is None else self.for_os(os_name, curated_only=False)
        if not text:
            return sorted(pool, key=lambda p: p.id)
        scored = [
            p for p in pool
            if text in p.id.lower()
            or text in p.short_name.lower()
            or text in p.description.lower()
        ]
        return sorted(scored, key=lambda p: (text not in p.id.lower(), p.id))


def build_command_args(info: PluginInfo, values: dict[str, object]) -> list[str]:
    """
    Turn user-supplied argument values into volatility3 CLI tokens.

    Booleans become bare flags when true and are omitted when false; lists are
    space-separated after their flag; None and empty strings are dropped so an
    untouched optional field never reaches the command line.
    """
    tokens: list[str] = []
    by_name = {a.name: a for a in info.args}
    for name, value in values.items():
        arg = by_name.get(name)
        if arg is None or value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, (list, tuple)) and not value:
            continue
        if arg.kind == "Boolean":
            if value:
                tokens.append(arg.cli_flag)
            continue
        tokens.append(arg.cli_flag)
        if isinstance(value, (list, tuple)):
            tokens += [str(v) for v in value]
        else:
            tokens.append(str(value))
    return tokens
