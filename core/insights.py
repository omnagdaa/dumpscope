"""
Automatic triage of stored plugin output.

Each rule encodes one thing an experienced examiner checks by eye on a Windows
image — a process hidden from the active list, an svchost.exe whose parent is
not services.exe, a PowerShell command line carrying an encoded payload — and
reports it as a Finding with a severity and the evidence behind it.

These are leads, not verdicts. Every finding says which plugin output it came
from so it can be checked, and a rule that lacks the output it needs simply
produces nothing; it never guesses.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field

SEVERITIES = ("high", "medium", "low", "info")
SEVERITY_ORDER = {name: i for i, name in enumerate(SEVERITIES)}
SEVERITY_COLORS = {"high": "#e0796f", "medium": "#e0a06a", "low": "#d9c07a",
                   "info": "#6aa9e0"}

# The plugins the rules read. Running these gives every rule its input.
INSIGHT_PLUGINS: tuple[str, ...] = (
    "windows.pslist.PsList",
    "windows.psscan.PsScan",
    "windows.cmdline.CmdLine",
    "windows.dlllist.DllList",
    "windows.netscan.NetScan",
    "windows.malware.malfind.Malfind",
    "windows.svcscan.SvcScan",
)


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    pid: str = ""
    process: str = ""
    plugin: str = ""
    evidence: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def as_row(self) -> list[str]:
        return [self.severity.title(), self.category, self.title, self.pid,
                self.process, self.detail, self.plugin.rsplit(".", 1)[-1]]


FINDING_COLUMNS = ["Severity", "Category", "Finding", "PID", "Process", "Detail", "Source"]


# ── Input normalisation ───────────────────────────────────────────────────────

@dataclass
class _Proc:
    pid: str
    ppid: str = ""
    name: str = ""
    create: str = ""
    exit: str = ""
    path: str = ""
    cmdline: str = ""
    in_pslist: bool = False
    in_psscan: bool = False


def _suffix(plugin_id: str) -> str:
    parts = (plugin_id or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (plugin_id or "").lower()


def _rows(payload: dict) -> list[dict[str, str]]:
    """A payload's rows as dicts keyed by column name; malformed rows dropped."""
    columns = [str(c).strip() for c in (payload.get("columns") or [])]
    out = []
    for row in payload.get("rows") or []:
        if not isinstance(row, (list, tuple)):
            continue
        record = {}
        for i, name in enumerate(columns):
            value = row[i] if i < len(row) else ""
            text = "" if value is None else str(value).strip()
            record[name] = "" if text in ("N/A", "-") else text
        out.append(record)
    return out


def _by_plugin(payloads: list[dict]) -> dict[str, list[dict[str, str]]]:
    tables: dict[str, list[dict[str, str]]] = {}
    for payload in payloads or []:
        if not isinstance(payload, dict):
            continue
        key = _suffix(str(payload.get("plugin") or ""))
        # The newest run wins; payloads arrive newest first from the database.
        tables.setdefault(key, _rows(payload))
    return tables


def _processes(tables) -> dict[str, _Proc]:
    procs: dict[str, _Proc] = {}
    for key, flag in (("pslist.pslist", "in_pslist"), ("psscan.psscan", "in_psscan"),
                      ("pstree.pstree", "in_pslist")):
        for row in tables.get(key, []):
            pid = row.get("PID", "")
            if not pid:
                continue
            proc = procs.setdefault(pid, _Proc(pid=pid))
            proc.ppid = proc.ppid or row.get("PPID", "")
            proc.name = proc.name or row.get("ImageFileName", "")
            proc.create = proc.create or row.get("CreateTime", "")
            proc.exit = proc.exit or row.get("ExitTime", "")
            setattr(proc, flag, True)
    for row in tables.get("cmdline.cmdline", []):
        pid = row.get("PID", "")
        if pid:
            proc = procs.setdefault(pid, _Proc(pid=pid, name=row.get("Process", "")))
            proc.cmdline = row.get("Args", "")
    # The first module dlllist reports for a process is its executable.
    seen = set()
    for row in tables.get("dlllist.dlllist", []):
        pid = row.get("PID", "")
        if pid and pid not in seen and row.get("Path"):
            seen.add(pid)
            proc = procs.setdefault(pid, _Proc(pid=pid, name=row.get("Process", "")))
            proc.path = row["Path"]
    for proc in procs.values():
        if not proc.path and proc.cmdline:
            proc.path = _exe_from_cmdline(proc.cmdline)
    return procs


def _exe_from_cmdline(cmdline: str) -> str:
    text = cmdline.strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        return text[1:end] if end > 0 else text[1:]
    match = re.match(r"(\S+?\.exe)\b", text, re.IGNORECASE)
    return match.group(1) if match else text.split(" ", 1)[0]


# ── Knowledge ─────────────────────────────────────────────────────────────────

# Expected parents of core Windows processes. A parent that has exited (and so
# is not in the list) is normal for several of these, so only a parent that is
# present *and* wrong is reported.
_EXPECTED_PARENT = {
    "smss.exe": {"system", "smss.exe"},
    "csrss.exe": {"smss.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "lsaiso.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe", "msmpeng.exe"},
    "spoolsv.exe": {"services.exe"},
    "taskhostw.exe": {"svchost.exe"},
    "runtimebroker.exe": {"svchost.exe"},
    "userinit.exe": {"winlogon.exe"},
    "explorer.exe": {"userinit.exe", "winlogon.exe"},
}

# Exactly one of each should exist per boot (or per session for none of these).
_SINGLETONS = ("lsass.exe", "services.exe", "wininit.exe", "lsaiso.exe", "smss.exe")

# Names malware imitates. A process within one edit of these, but not equal to
# one, is a typo-squat.
_CRITICAL_NAMES = ("svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
                   "winlogon.exe", "explorer.exe", "smss.exe", "wininit.exe",
                   "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe",
                   "rundll32.exe", "iexplore.exe", "chrome.exe")

# Core binaries that only ever run from System32 (or SysWOW64).
_SYSTEM32_ONLY = ("svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
                  "winlogon.exe", "wininit.exe", "smss.exe", "spoolsv.exe",
                  "taskhostw.exe", "dllhost.exe", "conhost.exe", "lsaiso.exe")

_SUSPICIOUS_DIRS = (
    (r"\\appdata\\local\\temp\\", "a user temp folder"),
    (r"\\windows\\temp\\", "the Windows temp folder"),
    (r"\\appdata\\roaming\\", "a roaming profile folder"),
    (r"\\users\\public\\", "the Public profile"),
    (r"\\programdata\\[^\\]+\.exe$", "the root of ProgramData"),
    (r"\\\$recycle\.bin\\", "the Recycle Bin"),
    (r"\\downloads\\", "a Downloads folder"),
    (r"\\perflogs\\", "PerfLogs"),
    (r"^\\\\[^\\]+\\", "a network share"),
)

# (pattern, title, severity)
_CMDLINE_RULES = (
    (r"powershell.*\s-(e|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+[A-Za-z0-9+/=]{16,}",
     "PowerShell with an encoded command", "high"),
    (r"powershell.*(iex|invoke-expression)\b", "PowerShell Invoke-Expression", "high"),
    (r"(downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer)",
     "Command downloads content from the network", "high"),
    (r"powershell.*-(w|windowstyle)\s+hidden", "PowerShell with a hidden window", "medium"),
    (r"powershell.*-(nop|noprofile).*-(ep|exec|executionpolicy)\s+bypass",
     "PowerShell bypassing execution policy", "medium"),
    (r"certutil(\.exe)?\s.*-(urlcache|decode|encode)", "certutil used to fetch or decode", "high"),
    (r"bitsadmin(\.exe)?\s.*/transfer", "bitsadmin download", "high"),
    (r"mshta(\.exe)?\s+(https?:|javascript:|vbscript:)", "mshta running remote or inline script", "high"),
    (r"rundll32(\.exe)?\s+.*javascript:", "rundll32 running script", "high"),
    (r"regsvr32(\.exe)?\s.*/i:\s*https?:", "regsvr32 remote scriptlet (Squiblydoo)", "high"),
    (r"(vssadmin|wmic)(\.exe)?\s.*(delete\s+shadows|shadowcopy\s+delete)",
     "Shadow copies deleted", "high"),
    (r"bcdedit(\.exe)?\s.*recoveryenabled\s+no", "Recovery disabled", "high"),
    (r"wmic(\.exe)?\s.*process\s+call\s+create", "WMIC process creation", "medium"),
    (r"schtasks(\.exe)?\s.*/create", "Scheduled task created from the command line", "medium"),
    (r"\bnet1?(\.exe)?\s+(user|localgroup)\s+.*\s/add", "Account or group membership added", "high"),
    (r"reg(\.exe)?\s+(add|save)\s+.*(\\run\b|\\runonce\b|hklm\\sam|hklm\\security)",
     "Registry persistence or hive export", "high"),
    (r"(mimikatz|sekurlsa|lsadump::|procdump.*lsass|comsvcs(\.dll)?.*minidump)",
     "Credential dumping tooling", "high"),
    (r"\bcmd(\.exe)?\s+/c\s+.*(\^|%comspec%)", "Obfuscated cmd invocation", "medium"),
)

# Programs that have no business holding a socket on most hosts.
_UNEXPECTED_NETWORK = ("notepad.exe", "calc.exe", "mspaint.exe", "rundll32.exe",
                       "regsvr32.exe", "mshta.exe", "cscript.exe", "wscript.exe",
                       "powershell.exe", "pwsh.exe", "cmd.exe", "certutil.exe",
                       "bitsadmin.exe", "winword.exe", "excel.exe", "powerpnt.exe",
                       "msbuild.exe", "installutil.exe", "wmic.exe", "lsass.exe")

_SUSPICIOUS_PORTS = {4444: "Metasploit default", 1337: "common backdoor",
                     31337: "common backdoor", 6666: "IRC/backdoor",
                     6667: "IRC (botnet C2)", 8443: None, 9001: "Tor ORPort",
                     9050: "Tor SOCKS"}


def _edit_distance_one(a: str, b: str) -> bool:
    """
    True when a and b are exactly one edit apart, counting an adjacent
    transposition as one edit ("scvhost" vs "svchost") — the commonest
    lookalike trick, which plain Levenshtein distance scores as two.
    """
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    rows, cols = len(a) + 1, len(b) + 1
    d = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        d[i][0] = i
    for j in range(cols):
        d[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1] == 1


def _is_public(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


# ── Rules ─────────────────────────────────────────────────────────────────────

def _hidden_processes(procs, tables):
    if "pslist.pslist" not in tables or "psscan.psscan" not in tables:
        return []
    out = []
    for proc in procs.values():
        if proc.in_psscan and not proc.in_pslist and not proc.exit:
            out.append(Finding(
                "high", "Hidden process",
                f"{proc.name or 'PID ' + proc.pid} is not in the active process list",
                "Found by psscan's pool scan but missing from pslist's linked list "
                "while still running — the signature of DKOM unlinking.",
                proc.pid, proc.name, "windows.psscan.PsScan",
                (("PPID", proc.ppid), ("Created", proc.create)),
            ))
    return out


def _parentage(procs, tables):
    out = []
    for proc in procs.values():
        name = proc.name.lower()
        expected = _EXPECTED_PARENT.get(name)
        if not expected or not proc.ppid:
            continue
        parent = procs.get(proc.ppid)
        if parent is None:
            continue                      # parent exited: normal for several of these
        parent_name = parent.name.lower() or ("system" if parent.pid == "4" else "")
        if parent_name and parent_name not in expected:
            severity = "high" if name in ("lsass.exe", "services.exe", "svchost.exe",
                                          "csrss.exe", "smss.exe", "wininit.exe") \
                else "medium"
            out.append(Finding(
                severity, "Unexpected parent",
                f"{proc.name} started by {parent.name}",
                f"{proc.name} is normally started by "
                f"{' or '.join(sorted(expected))}.",
                proc.pid, proc.name, "windows.pslist.PsList",
                (("PPID", proc.ppid), ("Parent", parent.name)),
            ))
    return out


def _singletons(procs, tables):
    running = defaultdict(list)
    for proc in procs.values():
        if not proc.exit and proc.name.lower() in _SINGLETONS:
            running[proc.name.lower()].append(proc)
    out = []
    for name, group in running.items():
        # smss.exe spawns a child copy per session that exits; only running
        # duplicates are odd, and for smss only beyond the master instance.
        if len(group) > 1:
            pids = ", ".join(p.pid for p in group)
            out.append(Finding(
                "high", "Duplicate system process",
                f"{len(group)} instances of {group[0].name} are running",
                f"Only one {group[0].name} should exist. PIDs: {pids}.",
                group[1].pid, group[1].name, "windows.pslist.PsList",
                (("PIDs", pids),),
            ))
    return out


def _masquerading(procs, tables):
    out = []
    for proc in procs.values():
        name = proc.name.lower()
        if not name or name in _CRITICAL_NAMES:
            continue
        for real in _CRITICAL_NAMES:
            if _edit_distance_one(name, real):
                out.append(Finding(
                    "high", "Masquerading name",
                    f"{proc.name} imitates {real}",
                    f"The name is one character away from {real}, a classic "
                    "way to hide in a process list.",
                    proc.pid, proc.name, "windows.pslist.PsList",
                ))
                break
    return out


def _paths(procs, tables):
    out = []
    for proc in procs.values():
        path = proc.path.lower().replace("/", "\\")
        if not path:
            continue
        name = (proc.name or path.rsplit("\\", 1)[-1]).lower()
        if name in _SYSTEM32_ONLY and "\\" in path and not re.search(
                r"\\windows\\(system32|syswow64)\\", path) and not path.startswith(
                ("\\systemroot\\system32\\", "\\??\\c:\\windows\\system32\\")):
            out.append(Finding(
                "high", "System binary in the wrong place",
                f"{proc.name} running from {proc.path}",
                f"{name} only ever runs from System32.",
                proc.pid, proc.name, "windows.dlllist.DllList",
                (("Path", proc.path),),
            ))
            continue
        for pattern, where in _SUSPICIOUS_DIRS:
            if re.search(pattern, path):
                out.append(Finding(
                    "medium", "Suspicious location",
                    f"{proc.name or name} running from {where}",
                    proc.path, proc.pid, proc.name, "windows.dlllist.DllList",
                    (("Path", proc.path),),
                ))
                break
    return out


def _cmdlines(procs, tables):
    out = []
    for proc in procs.values():
        line = proc.cmdline
        if not line:
            continue
        for pattern, title, severity in _CMDLINE_RULES:
            if re.search(pattern, line, re.IGNORECASE):
                out.append(Finding(
                    severity, "Suspicious command line", title,
                    line if len(line) <= 400 else line[:400] + "…",
                    proc.pid, proc.name, "windows.cmdline.CmdLine",
                    (("Command line", line),),
                ))
                break
    return out


def _network(procs, tables):
    rows = tables.get("netscan.netscan") or tables.get("netstat.netstat") or []
    out = []
    flagged = set()
    for row in rows:
        pid = row.get("PID", "")
        owner = (row.get("Owner") or procs.get(pid, _Proc(pid)).name).lower()
        foreign = row.get("ForeignAddr", "")
        state = row.get("State", "").upper()
        try:
            port = int(row.get("ForeignPort") or 0)
            local_port = int(row.get("LocalPort") or 0)
        except ValueError:
            port = local_port = 0
        remote = f"{foreign}:{port}"
        if owner in _UNEXPECTED_NETWORK and (pid, owner) not in flagged \
                and state != "LISTENING" and foreign not in ("", "*", "0.0.0.0", "::"):
            flagged.add((pid, owner))
            public = _is_public(foreign)
            out.append(Finding(
                "high" if public else "medium", "Unusual network activity",
                f"{row.get('Owner') or owner} connected to {remote}",
                f"{owner} rarely needs the network"
                + ("; the remote address is public." if public else "."),
                pid, row.get("Owner", owner), "windows.netscan.NetScan",
                (("Remote", remote), ("State", state)),
            ))
        for p, which in ((port, "remote"), (local_port, "local")):
            if p in _SUSPICIOUS_PORTS and _SUSPICIOUS_PORTS[p]:
                out.append(Finding(
                    "medium", "Suspicious port",
                    f"{which.title()} port {p} ({_SUSPICIOUS_PORTS[p]})",
                    f"{row.get('Proto', '')} {row.get('LocalAddr', '')}:{local_port} → "
                    f"{remote} {state}".strip(),
                    pid, row.get("Owner", ""), "windows.netscan.NetScan",
                ))
    return out


def _injection(procs, tables):
    out = []
    by_pid = defaultdict(list)
    for row in tables.get("malfind.malfind", []):
        by_pid[row.get("PID", "")].append(row)
    for pid, regions in by_pid.items():
        if not pid:
            continue
        pe = any(r.get("Hexdump", "").replace(" ", "").lower().startswith("4d5a")
                 or "MZ" in r.get("Hexdump", "")[:120] for r in regions)
        rwx = any("EXECUTE_READWRITE" in r.get("Protection", "").upper() for r in regions)
        name = regions[0].get("Process", "") or procs.get(pid, _Proc(pid)).name
        out.append(Finding(
            "high" if pe or rwx else "medium", "Code injection",
            f"{len(regions)} suspicious memory region(s) in {name or 'PID ' + pid}",
            ("An executable (MZ) image sits in private memory. "
             if pe else "") + ("Pages are writable and executable. " if rwx else "")
            + "Dump the regions with malfind --dump and scan them.",
            pid, name, "windows.malware.malfind.Malfind",
            tuple(("Region", f"{r.get('Start VPN', '')}-{r.get('End VPN', '')} "
                   f"{r.get('Protection', '')}") for r in regions[:5]),
        ))
    return out


def _services(procs, tables):
    out = []
    for row in tables.get("svcscan.svcscan", []):
        binary = row.get("Binary") or row.get("Binary (Registry)") or ""
        lowered = binary.lower().replace("/", "\\")
        for pattern, where in _SUSPICIOUS_DIRS:
            if re.search(pattern, lowered):
                out.append(Finding(
                    "high", "Suspicious service",
                    f"Service {row.get('Name', '?')} runs from {where}",
                    binary, row.get("PID", ""), row.get("Name", ""),
                    "windows.svcscan.SvcScan", (("Binary", binary),),
                ))
                break
        else:
            if re.search(r"(cmd(\.exe)?\s+/c|powershell|mshta|rundll32.*,)", lowered):
                out.append(Finding(
                    "medium", "Suspicious service",
                    f"Service {row.get('Name', '?')} launches a script host",
                    binary, row.get("PID", ""), row.get("Name", ""),
                    "windows.svcscan.SvcScan", (("Binary", binary),),
                ))
    return out


def _credentials(procs, tables):
    out = []
    for key, what in (("hashdump.hashdump", "NTLM password hashes"),
                      ("lsadump.lsadump", "LSA secrets"),
                      ("cachedump.cachedump", "cached domain credentials")):
        rows = tables.get(key)
        if rows:
            out.append(Finding(
                "info", "Credential material",
                f"{len(rows)} {what} recovered",
                "Handle under the case's evidence-handling rules.",
                plugin=key,
            ))
    return out


_RULES = (_hidden_processes, _parentage, _singletons, _masquerading, _paths,
          _cmdlines, _network, _injection, _services, _credentials)


def analyse(payloads: list[dict]) -> list[Finding]:
    """
    Findings for the given stored payloads, most severe first.

    A rule that raises on unexpected input is skipped; the others still run.
    """
    tables = _by_plugin(payloads)
    procs = _processes(tables)
    findings: list[Finding] = []
    for rule in _RULES:
        try:
            findings.extend(rule(procs, tables))
        except Exception:
            continue
    unique = list(dict.fromkeys(findings))
    unique.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.category,
                               _pid_key(f.pid), f.title))
    return unique


def _pid_key(pid: str):
    return (0, int(pid)) if pid.isdecimal() else (1, pid)


def counts(findings: list[Finding]) -> dict[str, int]:
    tally = {name: 0 for name in SEVERITIES}
    for finding in findings:
        tally[finding.severity] = tally.get(finding.severity, 0) + 1
    return tally


def missing_inputs(available_plugins: set[str]) -> list[str]:
    """INSIGHT_PLUGINS that have no stored output yet."""
    have = {_suffix(p) for p in available_plugins}
    return [p for p in INSIGHT_PLUGINS if _suffix(p) not in have]
