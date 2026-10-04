"""
Realistic volatility3 output for one small, compromised Windows host.

The scenario: a user opens an invoice in Word, which spawns an encoded
PowerShell that downloads a payload into AppData, launches a lookalike
"scvhost.exe", injects into explorer and calls home. A second lsass.exe is
started by the wrong parent, and one process has been unlinked from the active
list. Every insight rule and every timeline extractor has something to find.

Columns match what vol3 2.x's CSV renderer emits (the leading TreeDepth column
included); timestamps use its "%Y-%m-%d %H:%M:%S.%f %Z" format.
"""

T = "2024-03-14 {}.000000 UTC".format

PSLIST_COLUMNS = ["TreeDepth", "PID", "PPID", "ImageFileName", "Offset(V)", "Threads",
                  "Handles", "SessionId", "Wow64", "CreateTime", "ExitTime", "File output"]


def _proc(pid, ppid, name, created, exited="N/A", session="1"):
    return ["0", str(pid), str(ppid), name, "0xfa80", "4", "100", session, "False",
            T(created), exited if exited == "N/A" else T(exited), "Disabled"]


PSLIST_ROWS = [
    _proc(4, 0, "System", "08:00:01", session="N/A"),
    _proc(300, 4, "smss.exe", "08:00:02", session="N/A"),
    _proc(420, 300, "wininit.exe", "08:00:05", session="0"),
    _proc(480, 420, "services.exe", "08:00:06", session="0"),
    _proc(500, 420, "lsass.exe", "08:00:06", session="0"),
    _proc(620, 480, "svchost.exe", "08:00:09", session="0"),
    _proc(1800, 1700, "explorer.exe", "09:10:00"),
    _proc(2400, 1800, "WINWORD.EXE", "09:41:10"),
    _proc(2520, 2400, "powershell.exe", "09:41:32"),
    _proc(2600, 2520, "scvhost.exe", "09:41:50"),
    _proc(2700, 2600, "lsass.exe", "09:42:05"),
    _proc(2800, 1800, "notepad.exe", "09:30:00", exited="09:35:00"),
]

# psscan sees everything pslist does, plus one unlinked process.
PSSCAN_ROWS = PSLIST_ROWS + [_proc(3100, 2600, "rootkit.exe", "09:43:00")]

DLLLIST_COLUMNS = ["TreeDepth", "PID", "Process", "Base", "Size", "Name", "Path",
                   "LoadCount", "LoadTime", "File output"]
DLLLIST_ROWS = [
    ["0", "620", "svchost.exe", "0x7ff6", "0x1000", "svchost.exe",
     r"C:\Windows\System32\svchost.exe", "-1", T("08:00:09"), "Disabled"],
    ["0", "2520", "powershell.exe", "0x7ff7", "0x1000", "powershell.exe",
     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-1", T("09:41:32"),
     "Disabled"],
    ["0", "2520", "powershell.exe", "0x7ff8", "0x1000", "System.Management.Automation.dll",
     r"C:\Windows\assembly\System.Management.Automation.dll", "1", T("09:41:33"), "Disabled"],
    ["0", "2600", "scvhost.exe", "0x400000", "0x2000", "scvhost.exe",
     r"C:\Users\alice\AppData\Roaming\scvhost.exe", "-1", T("09:41:50"), "Disabled"],
    ["0", "2700", "lsass.exe", "0x400000", "0x2000", "lsass.exe",
     r"C:\Users\Public\lsass.exe", "-1", T("09:42:05"), "Disabled"],
    ["0", "1800", "explorer.exe", "0x7ff9", "0x1000", "explorer.exe",
     r"C:\Windows\explorer.exe", "-1", T("09:10:00"), "Disabled"],
]

CMDLINE_COLUMNS = ["TreeDepth", "PID", "Process", "Args"]
CMDLINE_ROWS = [
    ["0", "620", "svchost.exe", r"C:\Windows\system32\svchost.exe -k netsvcs"],
    ["0", "2400", "WINWORD.EXE",
     r'"C:\Program Files\Microsoft Office\WINWORD.EXE" /n "C:\Users\alice\Downloads\invoice.docm"'],
    ["0", "2520", "powershell.exe",
     "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"],
    ["0", "2600", "scvhost.exe", r"C:\Users\alice\AppData\Roaming\scvhost.exe"],
]

NETSCAN_COLUMNS = ["TreeDepth", "Offset", "Proto", "LocalAddr", "LocalPort",
                   "ForeignAddr", "ForeignPort", "State", "PID", "Owner", "Created"]
NETSCAN_ROWS = [
    ["0", "0x1", "TCPv4", "0.0.0.0", "135", "0.0.0.0", "0", "LISTENING", "620",
     "svchost.exe", T("08:00:10")],
    ["0", "0x2", "TCPv4", "10.0.0.5", "49712", "185.220.101.4", "443", "ESTABLISHED",
     "2520", "powershell.exe", T("09:41:40")],
    ["0", "0x3", "TCPv4", "10.0.0.5", "49713", "185.220.101.4", "4444", "ESTABLISHED",
     "2600", "scvhost.exe", T("09:42:00")],
    ["0", "0x4", "UDPv4", "10.0.0.5", "5353", "*", "0", "", "1800", "explorer.exe", "N/A"],
]

MALFIND_COLUMNS = ["TreeDepth", "PID", "Process", "Start VPN", "End VPN", "Tag",
                   "Protection", "CommitCharge", "PrivateMemory", "File output", "Notes",
                   "Hexdump", "Disasm"]
MALFIND_ROWS = [
    ["0", "1800", "explorer.exe", "0x3a0000", "0x3a1fff", "VadS",
     "PAGE_EXECUTE_READWRITE", "2", "1", "Disabled", "MZ header",
     "4d 5a 90 00 03 00 00 00 MZ......", "dec ebp"],
]

SVCSCAN_COLUMNS = ["TreeDepth", "Offset", "Order", "PID", "Start", "State", "Type",
                   "Name", "Display", "Binary", "Binary (Registry)", "Dll"]
SVCSCAN_ROWS = [
    ["0", "0x1", "1", "620", "SERVICE_AUTO_START", "SERVICE_RUNNING", "SERVICE_WIN32",
     "Dnscache", "DNS Client", r"C:\Windows\system32\svchost.exe -k NetworkService",
     "", ""],
    ["0", "0x2", "2", "N/A", "SERVICE_AUTO_START", "SERVICE_STOPPED", "SERVICE_WIN32",
     "UpdaterSvc", "Updater", r"C:\Windows\Temp\upd.exe", "", ""],
]

SESSIONS_COLUMNS = ["TreeDepth", "Session ID", "Session Type", "Process ID", "Process",
                    "User Name", "Create Time"]
SESSIONS_ROWS = [
    ["0", "1", "Console", "1800", "explorer.exe", "CORP/alice", T("09:09:58")],
]

USERASSIST_COLUMNS = ["TreeDepth", "Hive Offset", "Hive Name", "Path", "Last Write Time",
                      "Type", "Name", "ID", "Count", "Focus Count", "Time Focused",
                      "Last Updated", "Raw Data"]
USERASSIST_ROWS = [
    ["0", "0x1", "ntuser.dat", "Software\\...\\UserAssist", T("09:41:09"), "Value",
     r"%ProgramFiles%\Microsoft Office\WINWORD.EXE", "N/A", "3", "1", "0:00:10",
     T("09:41:09"), ""],
]

HASHDUMP_COLUMNS = ["TreeDepth", "User", "rid", "lmhash", "nthash"]
HASHDUMP_ROWS = [["0", "alice", "1001", "aad3b435", "31d6cfe0"]]

FIXTURES = {
    "windows.pslist.PsList": (PSLIST_COLUMNS, PSLIST_ROWS),
    "windows.psscan.PsScan": (PSLIST_COLUMNS, PSSCAN_ROWS),
    "windows.dlllist.DllList": (DLLLIST_COLUMNS, DLLLIST_ROWS),
    "windows.cmdline.CmdLine": (CMDLINE_COLUMNS, CMDLINE_ROWS),
    "windows.netscan.NetScan": (NETSCAN_COLUMNS, NETSCAN_ROWS),
    "windows.malware.malfind.Malfind": (MALFIND_COLUMNS, MALFIND_ROWS),
    "windows.svcscan.SvcScan": (SVCSCAN_COLUMNS, SVCSCAN_ROWS),
    "windows.sessions.Sessions": (SESSIONS_COLUMNS, SESSIONS_ROWS),
    "windows.registry.userassist.UserAssist": (USERASSIST_COLUMNS, USERASSIST_ROWS),
    "windows.hashdump.Hashdump": (HASHDUMP_COLUMNS, HASHDUMP_ROWS),
}


def payload(plugin: str) -> dict:
    columns, rows = FIXTURES[plugin]
    return {"plugin": plugin, "columns": list(columns), "rows": [list(r) for r in rows]}


def all_payloads() -> list[dict]:
    return [payload(p) for p in FIXTURES]
