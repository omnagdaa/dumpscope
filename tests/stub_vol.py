"""
Stands in for the vol3 CLI.

Emits CSV through the same writer configuration vol3's CSVRenderer uses, so the
values exercised here — embedded commas, embedded newlines, empty cells — are
shaped exactly as the real renderer would shape them. Progress is written to
stderr in vol3's \r-terminated format.

Modes: `rows` (default), `chatty` (megabytes of stderr), `fail` (non-zero exit),
`slow` (rows with a delay, writing a start/end marker to --stub-trace),
`corrupt` (fails with a corrupted-cache error unless --clear-cache is passed),
`corrupt_always`, `garbage` (invalid UTF-8), `empty` (no output),
`header_only`, `ragged` (rows shorter and longer than the header),
`flood` (more rows than a pipe buffer, for cancel-while-blocked).
"""
import csv
import os
import sys
import time

mode = "rows"
for index, arg in enumerate(sys.argv):
    if arg == "--stub-mode":
        mode = sys.argv[index + 1]


def _arg(name, default=""):
    for index, arg in enumerate(sys.argv):
        if arg == name and index + 1 < len(sys.argv):
            return sys.argv[index + 1]
    return default


# STUB_VOL_FIXTURES=1: answer as vol3 would for the plugin named on the command
# line, from tests/vol_fixtures.py — the end-to-end tests run real windows
# against this. STUB_VOL_ARGV_LOG records each command line for inspection.
if os.environ.get("STUB_VOL_FIXTURES"):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from vol_fixtures import FIXTURES
    log = os.environ.get("STUB_VOL_ARGV_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as handle:
            handle.write("\t".join(sys.argv[1:]) + "\n")
    if "windows.info.Info" in sys.argv:
        # A real run downloads the kernel PDB and writes its ISF into the first
        # -s folder; STUB_FETCH_ISF=1 imitates that.
        symbol_dirs = _arg("-s").split(";") if _arg("-s") else []
        if os.environ.get("STUB_FETCH_ISF") and symbol_dirs:
            target = os.path.join(symbol_dirs[0], "windows", "ntkrnlmp.pdb")
            os.makedirs(target, exist_ok=True)
            with open(os.path.join(target, "3844DBB920174967BE7AA4A2C20430FA-2.json.xz"),
                      "wb") as handle:
                handle.write(b"\xfd7zXZ\x00stub")
        elif os.environ.get("STUB_INFO_FAIL"):
            sys.stderr.write("Unable to validate the plugin requirements: "
                             "symbol table not found\n")
            sys.exit(1)
        print("Variable,Value")
        print("NTBuildLab,19041.1.amd64fre.vb_release.191206-1406")
        print("Is64Bit,True")
        sys.exit(0)
    plugin = next((a for a in sys.argv if a in FIXTURES), None)
    if plugin is None:
        sys.stderr.write("Unsatisfied requirement: stub has no fixture for this plugin\n")
        sys.exit(1)
    columns, rows = FIXTURES[plugin]
    writer = csv.writer(sys.stdout, lineterminator="\n", escapechar="\\")
    writer.writerow(columns)
    writer.writerows(rows)
    sys.exit(0)

if mode == "slow":
    trace = _arg("--stub-trace")
    if trace:
        with open(trace, "a") as handle:
            handle.write(f"start {os.getpid()} {time.monotonic()}\n")
    print("PID,Name")
    for i in range(3):
        print(f"{i},slow{i}", flush=True)
        time.sleep(float(_arg("--stub-delay", "0.3")))
    if trace:
        with open(trace, "a") as handle:
            handle.write(f"end {os.getpid()} {time.monotonic()}\n")
    sys.exit(0)

if mode == "corrupt" and "--clear-cache" in sys.argv:
    print("PID,Name")
    print("4,System")
    sys.exit(0)

if mode in ("corrupt", "corrupt_always"):
    sys.stderr.write("Traceback (most recent call last):\n")
    sys.stderr.write("sqlite3.DatabaseError: database disk image is malformed\n")
    sys.exit(1)

if mode == "garbage":
    sys.stdout.buffer.write(b"PID,Name\n4,\xff\xfe\xfdbad\n5,ok\n")
    sys.exit(0)

if mode == "empty":
    sys.exit(0)

if mode == "header_only":
    print("PID,Name")
    sys.exit(0)

if mode == "ragged":
    print("A,B,C")
    print("1")                 # short: padded
    print("1,2,3,4,5")         # long: folded into the last column
    print(",,")                # blank: skipped
    print("x,y,z")
    sys.exit(0)

if mode == "flood":
    print("PID,Name")
    for i in range(200000):
        sys.stdout.write(f"{i},{'x' * 60}\n")
    sys.exit(0)

if mode == "fail":
    sys.stderr.write("Unsatisfied requirement plugins.PsList.kernel\n")
    sys.exit(1)

if mode == "chatty":
    writer = csv.DictWriter(sys.stdout, ["PID", "Name"], lineterminator="\n",
                            escapechar="\\")
    writer.writeheader()
    for i in range(2000):
        sys.stderr.write("noise " * 20 + "\n")
        writer.writerow({"PID": str(i), "Name": f"proc{i}"})
    sys.exit(0)

writer = csv.DictWriter(
    sys.stdout, ["TreeDepth", "PID", "ImageFileName", "Path", "Note"],
    lineterminator="\n", escapechar="\\",
)
writer.writeheader()
sys.stderr.write("\rProgress:   12.50\t\tScanning primary2 using PdbSignatureScanner\r")
sys.stderr.flush()
writer.writerow({"TreeDepth": "0", "PID": "4", "ImageFileName": "System",
                 "Path": "", "Note": "ok"})
writer.writerow({"TreeDepth": "1", "PID": "820", "ImageFileName": "svchost.exe",
                 "Path": r"C:\Program Files\Some App\thing.exe", "Note": "has spaces"})
writer.writerow({"TreeDepth": "1", "PID": "900", "ImageFileName": "weird.exe",
                 "Path": "C:\\a,b\\c", "Note": "comma, inside"})
writer.writerow({"TreeDepth": "2", "PID": "1000", "ImageFileName": "multi.exe",
                 "Path": "line1\nline2", "Note": "embedded newline"})
sys.stdout.flush()
sys.stderr.write("\rProgress:   99.00\t\tAlmost done\r")
sys.stderr.write("A real warning message\n")
sys.exit(0)
