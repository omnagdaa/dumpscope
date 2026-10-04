"""Case folders, portability and the recent-case list."""
import json
import os
import shutil

import pytest

from core.case import (
    Case, CaseError, forget_case, load_recent, remember_case, safe_dirname,
)


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """Keep the recent-case list out of the real user config directory."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


def test_create_lays_out_the_case_folder(tmp_path):
    case = Case.create(str(tmp_path), "Op Nightfall", case_number="2026-014")

    assert os.path.basename(case.directory) == "Op_Nightfall"
    assert os.path.isfile(case.case_file)
    for sub in ("symbols", "yara", "exports", "dumps", "reports", "logs"):
        assert os.path.isdir(os.path.join(case.directory, sub))


def test_create_refuses_to_reuse_an_existing_case(tmp_path):
    """A name collision must never silently merge two investigations."""
    Case.create(str(tmp_path), "Op Nightfall")
    with pytest.raises(CaseError):
        Case.create(str(tmp_path), "Op Nightfall")


def test_reopen_restores_metadata(tmp_path):
    Case.create(str(tmp_path), "Op Nightfall", case_number="2026-014",
                examiner_name="A. Nagda", notes="triage")
    reopened = Case.open(os.path.join(str(tmp_path), "Op_Nightfall"))

    assert reopened.case_number == "2026-014"
    assert reopened.examiner_name == "A. Nagda"
    assert reopened.notes == "triage"


def test_a_moved_case_folder_still_opens(tmp_path):
    """The folder is the case; a stored path must never override where it is."""
    case = Case.create(str(tmp_path), "Op Nightfall")
    moved = os.path.join(str(tmp_path), "archived-elsewhere")
    shutil.move(case.directory, moved)

    reopened = Case.open(moved)
    assert reopened.directory == moved
    assert reopened.case_name == "Op Nightfall"


def test_open_rejects_a_folder_that_is_not_a_case(tmp_path):
    plain = tmp_path / "just-a-folder"
    plain.mkdir()
    with pytest.raises(CaseError):
        Case.open(str(plain))


def test_corrupt_case_file_is_reported_not_crashed(tmp_path):
    case = Case.create(str(tmp_path), "Broken")
    with open(case.case_file, "w", encoding="utf-8") as handle:
        handle.write("{not json")
    with pytest.raises(CaseError):
        Case.open(case.directory)


def test_save_is_atomic_and_leaves_no_temporary(tmp_path):
    case = Case.create(str(tmp_path), "Op Nightfall")
    case.notes = "updated"
    case.save()

    assert not os.path.exists(case.case_file + ".tmp")
    with open(case.case_file, encoding="utf-8") as handle:
        assert json.load(handle)["notes"] == "updated"


def test_quick_case_writes_nothing(tmp_path):
    case = Case.quick(str(tmp_path))
    case.save()

    assert case.quick_mode
    assert not os.path.exists(case.case_file)


def test_recent_list_orders_by_last_opened(tmp_path):
    first = Case.create(str(tmp_path), "First")
    second = Case.create(str(tmp_path), "Second")
    remember_case(first)
    remember_case(second)
    assert [e["case_name"] for e in load_recent()] == ["Second", "First"]

    remember_case(first)
    assert [e["case_name"] for e in load_recent()] == ["First", "Second"]


def test_recent_list_hides_cases_whose_folder_is_gone(tmp_path):
    case = Case.create(str(tmp_path), "Vanishing")
    remember_case(case)
    shutil.rmtree(case.directory)

    assert load_recent() == []


def test_forget_case_leaves_the_folder_alone(tmp_path):
    case = Case.create(str(tmp_path), "Kept")
    remember_case(case)
    forget_case(case.directory)

    assert load_recent() == []
    assert os.path.isdir(case.directory)


def test_safe_dirname_strips_path_separators():
    assert safe_dirname("../../etc/passwd") == "etc_passwd"
    assert safe_dirname("Case: 2026/014") == "Case_2026_014"
    assert safe_dirname("///") == "case"
