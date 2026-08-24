"""
Sending a report: what is checked before a connection is opened, what is
remembered, and what is deliberately not.
"""

import os

import pytest

from core import mailer, settings
from core.mailer import Account, MailError, Message, build_message


@pytest.fixture(autouse=True)
def _isolated_config(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "config_dir", lambda: str(tmp_path / "config"))
    settings._cache = None
    yield
    settings._cache = None


def _account(**kwargs):
    return Account(host="smtp.example.org", username="examiner@example.org",
                   **kwargs)


# ── Addresses ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("address,expected", [
    ("a@example.org", True),
    ("Name <a@example.org>", True),
    ("a@example", False),
    ("a@@example.org", False),
    ("no-at-sign", False),
    ("", False),
    ("a b@example.org", False),
])
def test_address_validation(address, expected):
    assert mailer.valid_address(address) is expected


def test_recipients_may_be_separated_by_commas_or_semicolons():
    assert mailer.split_addresses("a@x.org; b@y.org , c@z.org") == [
        "a@x.org", "b@y.org", "c@z.org"]


# ── Refusals that happen before a connection ─────────────────────────────────

def test_a_message_with_no_recipient_is_refused():
    with pytest.raises(MailError, match="No recipient"):
        build_message(_account(), Message(subject="Report"))


def test_a_message_with_no_subject_is_refused():
    with pytest.raises(MailError, match="no subject"):
        build_message(_account(), Message(to=["a@x.org"]))


def test_an_unconfigured_server_is_refused():
    with pytest.raises(MailError, match="No SMTP server"):
        build_message(Account(), Message(to=["a@x.org"], subject="S"))


def test_a_missing_attachment_is_refused(tmp_path):
    message = Message(to=["a@x.org"], subject="S",
                      attachments=[str(tmp_path / "gone.html")])
    with pytest.raises(MailError, match="missing"):
        build_message(_account(), message)


def test_oversized_attachments_are_refused_with_the_size(tmp_path, monkeypatch):
    monkeypatch.setattr(mailer, "ATTACHMENT_LIMIT", 1024)
    big = tmp_path / "dump.bin"
    big.write_bytes(b"\0" * 4096)
    message = Message(to=["a@x.org"], subject="S", attachments=[str(big)])
    with pytest.raises(MailError, match="over the"):
        build_message(_account(), message)


# ── The message itself ────────────────────────────────────────────────────────

def test_the_report_is_attached_under_its_own_name(tmp_path):
    report = tmp_path / "Op_Seaward-20260825.html"
    report.write_text("<html>report</html>")
    mail = build_message(_account(), Message(
        to=["dest@example.org"], cc=["lead@example.org"],
        subject="Case report", body="Attached.", attachments=[str(report)],
    ))
    names = [part.get_filename() for part in mail.iter_attachments()]
    assert names == ["Op_Seaward-20260825.html"]
    assert mail["To"] == "dest@example.org"
    assert mail["Cc"] == "lead@example.org"
    assert mail["From"] == "examiner@example.org"


def test_the_sender_falls_back_to_the_username():
    assert _account().from_address == "examiner@example.org"
    assert _account(sender="reports@example.org").from_address == "reports@example.org"


# ── What is remembered ────────────────────────────────────────────────────────

def test_the_password_is_never_a_stored_setting():
    assert not [key for key in settings.DEFAULTS if "pass" in key.lower()]


def test_the_account_is_remembered_but_the_password_is_not(qapp, tmp_path):
    from unittest import mock

    from core.case import Case
    from ui.email_dialog import EmailReportDialog

    case = Case.create(str(tmp_path / "case"), "Op Seaward")
    report = tmp_path / "r.html"
    report.write_text("<html/>")

    dialog = EmailReportDialog(case, str(report))
    dialog.host_edit.setText("smtp.example.org")
    dialog.user_edit.setText("examiner@example.org")
    dialog.password_edit.setText("hunter2")
    dialog.to_edit.setText("dest@example.org")

    # Stopped at the point a connection would be opened; everything up to it,
    # including the settings write, has already happened.
    with mock.patch.object(mailer.MailSender, "start", lambda self: None):
        dialog._send()

    stored = settings.load(refresh=True)
    assert stored["smtp_host"] == "smtp.example.org"
    assert stored["smtp_user"] == "examiner@example.org"
    assert stored["smtp_port"] == 587
    on_disk = open(settings.settings_file(), encoding="utf-8").read()
    assert "hunter2" not in on_disk
    assert "password" not in on_disk.lower()


def test_extracted_files_start_unattached_and_carry_a_warning(qapp, tmp_path):
    """A process dump is potentially live malware; attaching it is a decision."""
    from PyQt6.QtCore import Qt

    from core.case import Case
    from ui.email_dialog import EmailReportDialog

    case = Case.create(str(tmp_path / "case"), "Op Seaward")
    report = tmp_path / "r.html"
    report.write_text("<html/>")
    carved = tmp_path / "pid.820.dmp"
    carved.write_bytes(b"MZ")

    dialog = EmailReportDialog(case, str(report), extras=[str(carved)])
    assert dialog.attachments() == [str(report)]
    assert "malicious" not in dialog.size_lbl.text()

    dialog.attachment_list.item(1).setCheckState(Qt.CheckState.Checked)
    assert dialog.attachments() == [str(report), str(carved)]
    assert "malicious code" in dialog.size_lbl.text()
