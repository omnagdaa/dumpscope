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
