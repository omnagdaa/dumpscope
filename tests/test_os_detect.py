"""
Image identification.

The point of these is the ordering rule: a container signature outranks
anything volatility3 concludes afterwards, and "banners found nothing" is not
evidence of failure — it is weak evidence of Windows, because banners only ever
looks for Linux and Mac kernels.
"""

import pytest

from core.os_detect import ImageProfile, parse_info_rows, sniff_header


def _image(tmp_path, name, head: bytes):
    path = tmp_path / name
    path.write_bytes(head + b"\x00" * 8192)
    return str(path)


@pytest.mark.parametrize("magic,expected,container", [
    (b"PAGEDU64", "windows", "64-bit Windows crash dump"),
    (b"PAGEDUMP", "windows", "32-bit Windows crash dump"),
    (b"HIBR",     "windows", "Windows hibernation file"),
    (b"\x7fELF",  "linux",   "ELF core dump"),
    (b"EMiL",     "linux",   "LiME capture"),
])
def test_container_signatures_are_certain(tmp_path, magic, expected, container):
    profile = sniff_header(_image(tmp_path, "image.bin", magic))
    assert profile.os == expected
    assert profile.confidence == "certain"
    assert profile.container == container


def test_raw_image_yields_no_os(tmp_path):
    """A raw dump carries no signature; guessing from one would be invention."""
    profile = sniff_header(_image(tmp_path, "memory.raw", b"\x00" * 16))
    assert profile.os == ""
    assert profile.container == "raw memory dump"
    assert not profile.is_confident


def test_vmware_container_is_recognised_without_claiming_an_os(tmp_path):
    profile = sniff_header(_image(tmp_path, "vm.vmss", b"\xd2\xbe\xd2\xbe"))
    assert profile.container == "VMware snapshot"
    assert profile.os == ""


def test_unreadable_file_is_not_an_error(tmp_path):
    profile = sniff_header(str(tmp_path / "does-not-exist.raw"))
    assert profile.os == ""
    assert profile.container == ""


def test_parse_info_rows_keeps_only_the_interesting_fields():
    stdout = (
        "Variable,Value\r\n"
        "Kernel Base,0xf80267a00000\r\n"
        "DTB,0x1ad000\r\n"
        "Is64Bit,True\r\n"
        "SystemTime,2024-03-01 09:12:44\r\n"
        "NeverHeardOfIt,42\r\n"
    )
    facts = parse_info_rows(stdout)
    assert facts["Kernel Base"] == "0xf80267a00000"
    assert facts["64-bit"] == "True"
    assert facts["Capture Time"] == "2024-03-01 09:12:44"
    assert "NeverHeardOfIt" not in facts
    assert "42" not in facts.values()


@pytest.mark.parametrize("stdout", ["", "not csv at all", "Wrong,Header\n1,2\n"])
def test_parse_info_rows_survives_unexpected_output(stdout):
    assert parse_info_rows(stdout) == {}


def test_summary_marks_a_guess_as_a_guess():
    """
    An assumed OS must not read like a detection — the examiner has to be able
    to tell "vol3 confirmed this" from "nothing ruled it out".
    """
    assumed = ImageProfile(os="windows", confidence="assumed", method="nothing else matched")
    certain = ImageProfile(os="windows", confidence="certain", method="crash dump signature")
    assert "assumed" in assumed.summary()
    assert not assumed.is_confident
    assert "assumed" not in certain.summary()
    assert certain.is_confident


def test_empty_profile_says_so():
    assert ImageProfile().summary() == "Unidentified image"
