"""
Sending a finished report by email.

A report that stays in the case folder still has to reach the person who asked
for it, and the address is usually already in the case — the examiner's own, or
whoever the case was opened for. This sends it over SMTP, from the examiner's
own account.

Deliberately not stored: the password. It is asked for at send time and lives
only as long as the send does. An application that keeps SMTP credentials in a
JSON file next to the case is one stolen laptop away from being a mail relay,
and a forensics tool cannot be that. Everything else about the account — host,
port, user, transport — is remembered, so only the password is re-typed.

Attachments are read at send time and streamed straight into the message; the
size guard exists because a full process memory dump is measured in gigabytes
and no mail server will take it.
"""

from __future__ import annotations

import logging
import mimetypes
import os
import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr

from PyQt6.QtCore import QThread, pyqtSignal

log = logging.getLogger("dumpscope.mailer")

# Most providers reject anything past 25 MB; the check is here so the failure is
# a clear message rather than a timeout half way through an upload.
ATTACHMENT_LIMIT = 24 * 1024 * 1024

SECURITY = ("starttls", "ssl", "none")
DEFAULT_PORTS = {"starttls": 587, "ssl": 465, "none": 25}


class MailError(Exception):
    """Anything that stopped the message being sent, phrased for the examiner."""


@dataclass
class Account:
    """Where to send from. The password is never part of this."""
    host: str = ""
    port: int = 587
    username: str = ""
    sender: str = ""
    security: str = "starttls"

    def validate(self) -> None:
        if not self.host.strip():
            raise MailError("No SMTP server is configured.")
        if self.security not in SECURITY:
            raise MailError(f"Unknown transport security: {self.security}")
        if not valid_address(self.from_address):
            raise MailError(f"'{self.from_address}' is not a valid sender address.")

    @property
    def from_address(self) -> str:
        return (self.sender or self.username).strip()


@dataclass
class Message:
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    subject: str = ""
    body: str = ""
    attachments: list[str] = field(default_factory=list)

    def recipients(self) -> list[str]:
        return [address for address in (*self.to, *self.cc) if address.strip()]

    def validate(self) -> None:
        if not self.recipients():
            raise MailError("No recipient was given.")
        for address in self.recipients():
            if not valid_address(address):
                raise MailError(f"'{address}' is not a valid email address.")
        if not self.subject.strip():
            raise MailError("The message has no subject.")


def valid_address(address: str) -> bool:
    """A deliberately loose check: catches typos, not exotic-but-legal addresses."""
    _name, email = parseaddr(address or "")
    if not email or email.count("@") != 1:
        return False
    local, _, domain = email.partition("@")
    return bool(local) and "." in domain and not domain.endswith(".") \
        and " " not in email


def split_addresses(text: str) -> list[str]:
    """Parse a comma- or semicolon-separated recipient list."""
    parts = (text or "").replace(";", ",").split(",")
    return [part.strip() for part in parts if part.strip()]


def total_size(paths: list[str]) -> int:
    total = 0
    for path in paths:
        try:
            total += os.path.getsize(path)
        except OSError:
            pass
    return total


def build_message(account: Account, message: Message) -> EmailMessage:
    """Assemble the MIME message, attachments included."""
    account.validate()
    message.validate()

    mail = EmailMessage()
    mail["From"] = account.from_address
    mail["To"] = ", ".join(message.to)
    if message.cc:
        mail["Cc"] = ", ".join(message.cc)
    mail["Subject"] = message.subject
    mail["Date"] = formatdate(localtime=True)
    mail["Message-ID"] = make_msgid(domain=account.from_address.split("@")[-1])
    mail.set_content(message.body or "")

    oversized = total_size(message.attachments)
    if oversized > ATTACHMENT_LIMIT:
        raise MailError(
            f"The attachments come to {oversized / 1048576:.1f} MB, over the "
            f"{ATTACHMENT_LIMIT / 1048576:.0f} MB limit most mail servers "
            "accept. Send the report on its own, or share the large files "
            "another way."
        )

    for path in message.attachments:
        if not os.path.isfile(path):
            raise MailError(f"Attachment is missing:\n{path}")
        guessed, _encoding = mimetypes.guess_type(path)
        main, _, sub = (guessed or "application/octet-stream").partition("/")
        with open(path, "rb") as handle:
            mail.add_attachment(
                handle.read(), maintype=main, subtype=sub or "octet-stream",
                filename=os.path.basename(path),
            )
    return mail


def send(account: Account, password: str, message: Message, timeout: int = 60) -> None:
    """Send synchronously. Raises MailError with something readable."""
    mail = build_message(account, message)
    port = account.port or DEFAULT_PORTS.get(account.security, 587)
    context = ssl.create_default_context()

    try:
        if account.security == "ssl":
            server = smtplib.SMTP_SSL(account.host, port, timeout=timeout,
                                      context=context)
        else:
            server = smtplib.SMTP(account.host, port, timeout=timeout)
        with server:
            server.ehlo()
            if account.security == "starttls":
                server.starttls(context=context)
                server.ehlo()
            if account.username:
                server.login(account.username, password)
            server.send_message(mail, from_addr=account.from_address,
                                to_addrs=message.recipients())
    except smtplib.SMTPAuthenticationError as exc:
        raise MailError(
            "The server rejected those credentials.\n\n"
            "Accounts with two-factor authentication need an app password "
            "rather than the account password."
        ) from exc
    except smtplib.SMTPRecipientsRefused as exc:
        refused = ", ".join(exc.recipients)
        raise MailError(f"The server refused these recipients: {refused}") from exc
    except (smtplib.SMTPException, ssl.SSLError, OSError) as exc:
        raise MailError(f"{type(exc).__name__}: {exc}") from exc


class MailSender(QThread):
    """
    Sends one message off the GUI thread.

    An SMTP handshake plus a multi-megabyte attachment over a slow uplink takes
    long enough to freeze a window, and a frozen window during a send looks
    exactly like a crash.
    """

    sent = pyqtSignal()
    failed = pyqtSignal(str)
    note = pyqtSignal(str)

    def __init__(self, account: Account, password: str, message: Message, parent=None):
        super().__init__(parent)
        self.account = account
        self._password = password
        self.message = message

    def run(self):
        try:
            self.note.emit(f"Connecting to {self.account.host}…")
            send(self.account, self._password, self.message)
        except MailError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:                       # never take the app down
            log.exception("Unexpected failure sending mail")
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        else:
            self.sent.emit()
        finally:
            # The password is not kept a moment longer than the send needs it.
            self._password = ""
