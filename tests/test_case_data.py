"""Data sources, tags and bookmarks — the case-management layer of the database."""
import os

import pytest

from core.database import Database


@pytest.fixture
def db(tmp_path):
    image = tmp_path / "host-a.raw"
    image.write_bytes(b"\0" * 2048)
    database = Database(str(tmp_path), "Multi Source")
    database.attach_case({
        "case_name": "Multi Source", "case_number": "7",
        "base_dir": str(tmp_path), "image_path": str(image), "md5": "abc",
    })
    return database


def test_new_cases_start_with_a_tag_vocabulary(db):
    assert [t["name"] for t in db.get_tags()] == [
        "Suspicious", "Malicious", "Notable", "Benign", "Follow Up",
    ]


def test_the_case_image_is_registered_as_a_data_source(db):
    sources = db.get_data_sources()
    assert len(sources) == 1
    assert sources[0]["md5"] == "abc"
    assert sources[0]["size_bytes"] == 2048


def test_adding_the_same_image_twice_does_not_duplicate_it(db, tmp_path):
    existing = db.get_data_sources()[0]
    again = db.add_data_source(str(tmp_path / "host-a.raw"))

    assert again == existing["id"]
    assert len(db.get_data_sources()) == 1


def test_re_adding_an_image_never_clears_a_known_hash(db, tmp_path):
    """A later call without hashes must not wipe a digest already computed."""
    source_id = db.add_data_source(str(tmp_path / "host-a.raw"))
    assert db.get_data_source(source_id)["md5"] == "abc"


def test_results_and_bookmarks_carry_their_data_source(db, tmp_path):
    second = tmp_path / "host-b.mem"
    second.write_bytes(b"\0" * 4096)
    source_b = db.add_data_source(str(second), os_hint="linux")
    source_a = db.get_data_sources()[0]["id"]

    db.save_analysis("windows.pslist.PsList", {"columns": ["PID"], "rows": [["4"]]},
                     source_id=source_a)
    db.save_analysis("linux.pslist.PsList", {"columns": ["PID"], "rows": [["1"]]},
                     source_id=source_b)

    assert {r["source_name"] for r in db.get_results()} == {"host-a.raw", "host-b.mem"}
    assert len(db.get_results(source_id=source_b)) == 1


def test_bookmarks_resolve_their_tag_colour(db):
    db.save_bookmark("svchost.exe", "PID 820", "windows.pslist.PsList",
                     tag="Suspicious", notes="odd parent")
    bookmark = db.get_bookmarks()[0]

    assert bookmark["tag_color"] == "#f85149"
    assert bookmark["notes"] == "odd parent"
    assert len(db.get_bookmarks(tag="Suspicious")) == 1
    assert len(db.get_bookmarks(tag="Benign")) == 0


def test_removing_a_source_keeps_the_work_done_from_it(db, tmp_path):
    """
    Detaching an image must never destroy analysis already performed — that is
    evidence of work, and losing it silently would be worse than keeping an
    orphaned row.
    """
    second = tmp_path / "host-b.mem"
    second.write_bytes(b"\0" * 4096)
    source_b = db.add_data_source(str(second))
    db.save_analysis("linux.pslist.PsList", {"columns": ["PID"], "rows": [["1"]]},
                     source_id=source_b)
    db.save_bookmark("init", "PID 1", "linux.pslist.PsList", source_id=source_b)

    db.remove_data_source(source_b)

    assert len(db.get_data_sources()) == 1
    assert len(db.get_results()) == 1
    assert len(db.get_bookmarks()) == 1
    assert db.get_results()[0]["source_id"] is None


def test_deleting_a_stored_result_is_audited(db):
    result_id = db.save_analysis("windows.info.Info", {"columns": [], "rows": []})
    db.delete_result(result_id)

    assert db.get_results() == []
    assert any(e["action"] == "result_deleted" for e in db.get_audit_log())
