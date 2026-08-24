"""
Stands in for the vol3 CLI.

Emits CSV through the same writer configuration vol3's CSVRenderer uses, so the
values exercised here — embedded commas, embedded newlines, empty cells — are
shaped exactly as the real renderer would shape them. Progress is written to
stderr in vol3's \r-terminated format.

Modes: `rows` (default), `chatty` (megabytes of stderr), `fail` (non-zero exit).
"""
import csv
import sys

mode = "rows"
for index, arg in enumerate(sys.argv):
    if arg == "--stub-mode":
        mode = sys.argv[index + 1]

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
