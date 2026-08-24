"""
Send a finished report to whoever asked for it.

The recipient is prefilled from the case — the email collected when the case
was opened — because that is nearly always the answer, and retyping an address
from another window is how reports reach the wrong person.

The password field is not saved and not remembered. Everything else about the
account is, so a second report costs one field.
"""

from __future__ import annotations

import os

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMessageBox,
    QPushButton, QSpinBox, QTextEdit, QVBoxLayout, QWidget,
)

from core import mailer, settings
from core.mailer import Account, MailSender, Message


def _size_label(paths: list[str]) -> str:
    total = mailer.total_size(paths)
    if total < 1024:
        return f"{total} B"
    for unit in ("KB", "MB", "GB"):
        total /= 1024
        if total < 1024:
            return f"{total:.1f} {unit}"
    return f"{total:.1f} TB"


class EmailReportDialog(QDialog):
    """Compose and send one report. Emits `sent` when the server accepted it."""

    sent = pyqtSignal()

    def __init__(self, case, report_path: str, extras: list[str] | None = None,
                 parent=None):
        super().__init__(parent)
        self.setWindowTitle("Email Report")
        self.setMinimumWidth(560)
        self.case = case
        self.report_path = report_path
        self.extras = [p for p in (extras or []) if os.path.isfile(p)]
        self.settings = settings.load()
        self._sender: MailSender | None = None
        self._build()

    # ── Construction ──────────────────────────────────────────────────────────

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        layout.addWidget(self._message_group())
        layout.addWidget(self._attachments_group())
        layout.addWidget(self._account_group())

        self.status = QLabel("")
        self.status.setObjectName("fieldHint")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        buttons = QDialogButtonBox()
        self.send_btn = buttons.addButton("Send", QDialogButtonBox.ButtonRole.AcceptRole)
        self.send_btn.setObjectName("primaryBtn")
        buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._send)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _message_group(self) -> QWidget:
        group = QGroupBox("Message")
        form = QFormLayout(group)

        self.to_edit = QLineEdit(self.case.examiner_email or "")
        self.to_edit.setPlaceholderText("recipient@example.org, second@example.org")
        self.cc_edit = QLineEdit()
        self.cc_edit.setPlaceholderText("optional")

        label = self.case.display_label
        self.subject_edit = QLineEdit(f"Case report — {label}")
        self.body_edit = QTextEdit()
        # setPlainText, not the constructor: the constructor runs rich-text
        # auto-detection, which folds the line breaks out of the summary.
        self.body_edit.setPlainText(self._default_body())
        self.body_edit.setFixedHeight(120)

        form.addRow("To", self.to_edit)
        form.addRow("Cc", self.cc_edit)
        form.addRow("Subject", self.subject_edit)
        form.addRow("Message", self.body_edit)
        return group

    def _default_body(self) -> str:
        lines = [
            f"Case: {self.case.display_label}",
            f"Examiner: {self.case.examiner_name or '—'}",
            f"Image: {os.path.basename(self.case.image_path) or '—'}",
            "",
            "The case report is attached.",
        ]
        return "\n".join(lines)

    def _attachments_group(self) -> QWidget:
        group = QGroupBox("Attachments")
        column = QVBoxLayout(group)

        self.attachment_list = QListWidget()
        self.attachment_list.setFixedHeight(96)
        self._add_attachment(self.report_path, checked=True)
        for path in self.extras:
            self._add_attachment(path, checked=False)
        column.addWidget(self.attachment_list)

        self.size_lbl = QLabel("")
        self.size_lbl.setObjectName("fieldHint")
        self.size_lbl.setWordWrap(True)
        self.attachment_list.itemChanged.connect(lambda _item: self._update_size())
        column.addWidget(self.size_lbl)
        self._update_size()
        return group

    def _add_attachment(self, path: str, checked: bool):
        item = QListWidgetItem(f"{os.path.basename(path)}   ·   {_size_label([path])}")
        item.setToolTip(path)
        item.setData(Qt.ItemDataRole.UserRole, path)
        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        item.setCheckState(
            Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
        self.attachment_list.addItem(item)

    def attachments(self) -> list[str]:
        return [
            self.attachment_list.item(row).data(Qt.ItemDataRole.UserRole)
            for row in range(self.attachment_list.count())
            if self.attachment_list.item(row).checkState() == Qt.CheckState.Checked
        ]

    def _update_size(self):
        chosen = self.attachments()
        total = mailer.total_size(chosen)
        message = f"{len(chosen)} attachment(s), {_size_label(chosen)} total."
        if total > mailer.ATTACHMENT_LIMIT:
            message += (
                f"  Over the {mailer.ATTACHMENT_LIMIT // 1048576} MB most servers "
                "accept — the send will be refused."
            )
        if any(path != self.report_path for path in chosen):
            message += ("\nExtracted files can contain live malicious code. Send "
                        "them only to a recipient equipped to handle them.")
        self.size_lbl.setText(message)

    def _account_group(self) -> QWidget:
        group = QGroupBox("Sending Account")
        form = QFormLayout(group)

        self.host_edit = QLineEdit(self.settings.get("smtp_host", ""))
        self.host_edit.setPlaceholderText("smtp.example.org")
        self.user_edit = QLineEdit(self.settings.get("smtp_user", ""))
        self.from_edit = QLineEdit(self.settings.get("smtp_from", ""))
        self.from_edit.setPlaceholderText("defaults to the username")

        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(int(self.settings.get("smtp_port") or 587))

        self.security_box = QComboBox()
        for value, label in (("starttls", "STARTTLS"), ("ssl", "SSL/TLS"),
                             ("none", "None (not encrypted)")):
            self.security_box.addItem(label, value)
        current = self.settings.get("smtp_security", "starttls")
        self.security_box.setCurrentIndex(max(0, self.security_box.findData(current)))
        self.security_box.currentIndexChanged.connect(self._sync_port)

        transport = QHBoxLayout()
        transport.addWidget(self.security_box, 1)
        transport.addWidget(QLabel("Port"))
        transport.addWidget(self.port_spin)
        transport_row = QWidget()
        transport_row.setLayout(transport)

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("not saved — asked for each send")

        self.remember_box = QCheckBox("Remember the server, port and username")
        self.remember_box.setChecked(True)

        form.addRow("Server", self.host_edit)
        form.addRow("Security", transport_row)
        form.addRow("Username", self.user_edit)
        form.addRow("From", self.from_edit)
        form.addRow("Password", self.password_edit)
        form.addRow("", self.remember_box)

        hint = QLabel(
            "An account with two-factor authentication needs an app password."
        )
        hint.setObjectName("fieldHint")
        hint.setWordWrap(True)
        form.addRow("", hint)
        return group

    def _sync_port(self):
        """Follow the transport's usual port, unless it was set by hand."""
        chosen = self.security_box.currentData()
        if self.port_spin.value() in mailer.DEFAULT_PORTS.values():
            self.port_spin.setValue(mailer.DEFAULT_PORTS[chosen])

    # ── Sending ───────────────────────────────────────────────────────────────

    def account(self) -> Account:
        return Account(
            host=self.host_edit.text().strip(),
            port=self.port_spin.value(),
            username=self.user_edit.text().strip(),
            sender=self.from_edit.text().strip(),
            security=self.security_box.currentData(),
        )

    def message(self) -> Message:
        return Message(
            to=mailer.split_addresses(self.to_edit.text()),
            cc=mailer.split_addresses(self.cc_edit.text()),
            subject=self.subject_edit.text().strip(),
            body=self.body_edit.toPlainText(),
            attachments=self.attachments(),
        )

    def _send(self):
        account, message = self.account(), self.message()
        try:
            account.validate()
            message.validate()
        except mailer.MailError as exc:
            QMessageBox.warning(self, "Cannot Send", str(exc))
            return
        if not message.attachments:
            answer = QMessageBox.question(
                self, "No Attachment",
                "Nothing is attached — send the message anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        if self.remember_box.isChecked():
            self.settings = settings.save(
                smtp_host=account.host, smtp_port=account.port,
                smtp_user=account.username, smtp_from=account.sender,
                smtp_security=account.security,
            )

        self.send_btn.setEnabled(False)
        self.status.setText("Sending…")
        sender = MailSender(account, self.password_edit.text(), message, parent=self)
        sender.note.connect(self.status.setText)
        sender.sent.connect(self._on_sent)
        sender.failed.connect(self._on_failed)
        sender.finished.connect(sender.deleteLater)
        self._sender = sender
        sender.start()

    def _on_sent(self):
        self._sender = None
        self.sent.emit()
        QMessageBox.information(
            self, "Report Sent",
            "The report was accepted by the server for delivery to:\n\n"
            + "\n".join(self.message().recipients()),
        )
        self.accept()

    def _on_failed(self, reason: str):
        self._sender = None
        self.send_btn.setEnabled(True)
        self.status.setText("Not sent.")
        QMessageBox.critical(self, "Send Failed", reason)

    def reject(self):
        if self._sender is not None and self._sender.isRunning():
            self._sender.wait(3000)
        super().reject()
