"""
Edge cases for the non-UI core: damaged files on disk, hostile or unusual
input, and boundary values. Each test names the crash or wrong answer it
guards against.
"""
import gc
import json
import os
import sqlite3
import warnings
import zipfile

import pytest

from core import settings
from core.case import Case, CaseError, forget_case, load_recent, remember_case, safe_dirname
from core.database import Database, db_filename
from core.mailer import Account, MailError, Message, split_addresses, valid_address
from core.os_detect import ImageProfile, parse_info_rows, sniff_header
from core.plugins import PluginArg, PluginInfo, PluginRegistry, build_command_args, plugin_os
from core.report import build_html, build_json
from core.symbol_downloader import SymbolDownloader, count_symbols, symbols_present
from core.vol_runner import build_environment, detect_os_from_banner


# ── Case folders ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name, expected", [
    ("../../etc/passwd", "etc_passwd"),
    ("..", "case"),
    ("...", "case"),
    ("   ", "case"),
    ("Op: Nightfall/2026", "Op_Nightfall_2026"),
    ("C:\\Windows\\System32", "C_Windows_System32"),
    ("名前", "case"),
])
def test_safe_dirname_never_escapes_or_empties(name, expected):
    assert safe_dirname(name) == expected
    assert os.sep not in safe_dirname(name)


def test_traversal_in_a_case_name_stays_inside_the_parent(tmp_path):
    case = Case.create(str(tmp_path), "../../outside")
    assert os.path.dirname(case.directory) == str(tmp_path)


@pytest.mark.parametrize("name", ["", "   ", "\t\n"])
def test_blank_case_name_is_refused(tmp_path, name):
    with pytest.raises(CaseError):
        Case.create(str(tmp_path), name)


def test_two_names_that_sanitise_alike_do_not_merge(tmp_path):
    Case.create(str(tmp_path), "Op/1")
    with pytest.raises(CaseError, match="already exists"):
        Case.create(str(tmp_path), "Op:1")


@pytest.mark.parametrize("content", [
    b"[1, 2, 3]",               # valid JSON, wrong shape — used to AttributeError
    b'"just a string"',
    b"null",
    b"{not json",
    b"\xff\xfe\x00garbage",     # not UTF-8 — used to escape as UnicodeDecodeError
    b"",
])
def test_damaged_case_file_raises_case_error_not_a_crash(tmp_path, content):
    (tmp_path / "case.json").write_bytes(content)
    with pytest.raises(CaseError):
        Case.open(str(tmp_path))


def test_case_file_with_wrong_field_types_still_opens(tmp_path):
    (tmp_path / "case.json").write_text(json.dumps({
        "case_name": None, "case_number": 42, "notes": None,
        "is_dark": "yes", "unknown_future_field": [1, 2],
    }))
    case = Case.open(str(tmp_path))
    assert case.case_name == tmp_path.name
    assert case.case_number == "42"
    assert case.notes == ""
    assert case.is_dark is True
    assert "42" in case.display_label


def test_open_missing_folder_is_a_case_error(tmp_path):
    with pytest.raises(CaseError):
        Case.open(str(tmp_path / "nope"))


def test_case_save_survives_a_read_only_folder(tmp_path, monkeypatch):
    case = Case.create(str(tmp_path), "RO")
    def refuse(*a, **k):
        raise PermissionError("read-only")
    monkeypatch.setattr("builtins.open", refuse)
    case.save()                         # logged, not raised
    monkeypatch.undo()
    assert not os.path.exists(case.case_file + ".tmp")


def test_quick_case_never_writes(tmp_path):
    case = Case.quick(str(tmp_path))
    case.save()
    assert not os.path.exists(os.path.join(str(tmp_path), "case.json"))


def test_case_db_path_matches_the_database_it_opens(tmp_path):
    """Regression: Case.db_path and Database used different sanitisers."""
    for name in ("My.Case", "Op Nightfall", "a-b_c", "x..y"):
        case = Case.create(str(tmp_path), name)
        db = Database(case.directory, case.case_name)
        assert db.db_path == case.db_path, name


def test_db_filename_edge_cases():
    assert db_filename("") == "case.db"
    assert db_filename(None) == "case.db"
    assert db_filename("___") == "case.db"
    assert "/" not in db_filename("a/b") and "\\" not in db_filename("a\\b")


# ── Recent list ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("content", ['{"a": 1}', "[1, null, \"x\"]", "{bad", ""])
def test_corrupt_recent_list_reads_as_empty(tmp_path, content):
    from core.case import recent_file
    os.makedirs(os.path.dirname(recent_file()), exist_ok=True)
    with open(recent_file(), "w") as handle:
        handle.write(content)
    assert load_recent() == []


def test_recent_list_is_capped_and_deduplicated(tmp_path):
    from core.case import MAX_RECENT
    cases = [Case.create(str(tmp_path), f"c{i}") for i in range(MAX_RECENT + 5)]
    for case in cases:
        remember_case(case)
    remember_case(cases[0])
    recent = load_recent()
    assert len(recent) == MAX_RECENT
    assert recent[0]["directory"] == cases[0].directory
    assert len({entry["directory"] for entry in recent}) == len(recent)


def test_forgetting_an_unknown_case_is_harmless(tmp_path):
    forget_case(str(tmp_path / "never-existed"))
    assert load_recent() == []


# ── Settings ──────────────────────────────────────────────────────────────────

def _write_settings(payload):
    os.makedirs(os.path.dirname(settings.settings_file()), exist_ok=True)
    with open(settings.settings_file(), "w", encoding="utf-8") as handle:
        handle.write(payload if isinstance(payload, str) else json.dumps(payload))
    settings._cache = None


@pytest.mark.parametrize("stored, key, expected", [
    ({"font_size": "big"}, "font_size", 13),         # used to crash int() at startup
    ({"font_size": 0}, "font_size", 13),
    ({"font_size": 999}, "font_size", 13),
    ({"font_size": "16"}, "font_size", 16),          # numeric strings are fine
    ({"font_size": True}, "font_size", 13),          # bool is not an int here
    ({"desktop_notifications": "no"}, "desktop_notifications", True),
    ({"smtp_port": 70000}, "smtp_port", 587),
    ({"smtp_host": 123}, "smtp_host", ""),
    ({"max_parallel_runs": 0}, "max_parallel_runs", 1),
    ({"max_parallel_runs": 100}, "max_parallel_runs", 1),
    ({"max_parallel_runs": 3}, "max_parallel_runs", 3),
])
def test_invalid_settings_fall_back_to_defaults(stored, key, expected):
    _write_settings(stored)
    assert settings.load(refresh=True)[key] == expected


@pytest.mark.parametrize("content", ["[]", "null", "{oops", "\x00\x01"])
def test_unreadable_settings_file_gives_defaults(content):
    _write_settings(content)
    assert settings.load(refresh=True) == settings.DEFAULTS


def test_save_rejects_invalid_values_and_unknown_keys():
    values = settings.save(font_size="huge", nonsense=1, max_parallel_runs=2)
    assert values["font_size"] == settings.DEFAULTS["font_size"]
    assert "nonsense" not in values
    assert values["max_parallel_runs"] == 2


def test_save_survives_an_unwritable_config_dir(monkeypatch, tmp_path):
    blocker = tmp_path / "file-not-dir"
    blocker.write_text("x")
    monkeypatch.setattr(settings, "config_dir", lambda: str(blocker / "sub"))
    settings._cache = None
    assert settings.save(font_size=14)["font_size"] == 14


# ── Database ──────────────────────────────────────────────────────────────────

@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path), "Edge")
    database.attach_case({"case_name": "Edge", "case_number": "1"})
    return database


def test_connections_are_closed(tmp_path):
    """Regression: sqlite3's context manager commits but never closes."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        database = Database(str(tmp_path), "Leak")
        database.attach_case({"case_name": "Leak"})
        for _ in range(5):
            database.get_results()
        del database
        gc.collect()
    leaks = [w for w in caught if issubclass(w.category, ResourceWarning)
             and "sqlite3" in str(w.message)]
    assert leaks == []


def test_failed_write_is_rolled_back(db):
    before = len(db.get_results())
    with pytest.raises(sqlite3.Error):
        with db._connect() as conn:
            conn.execute("INSERT INTO analysis_results (case_id, plugin) VALUES (?, ?)",
                         (db.case_id, "half-written"))
            conn.execute("SELECT * FROM no_such_table")
    assert len(db.get_results()) == before


def test_corrupt_database_file_raises_a_database_error(tmp_path):
    (tmp_path / "Broken.db").write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(sqlite3.DatabaseError):
        Database(str(tmp_path), "Broken")


def test_sql_metacharacters_are_stored_verbatim(db):
    nasty = "x'); DROP TABLE bookmarks; --"
    db.add_tag(nasty)
    db.save_bookmark(nasty, nasty, "p", tag=nasty, row={"k": nasty})
    assert any(t["name"] == nasty for t in db.get_tags())
    assert db.get_bookmarks(tag=nasty)[0]["label"] == nasty


def test_unicode_and_large_results_round_trip(db):
    rows = [[str(i), "процесс-😀-" + "x" * 200] for i in range(5000)]
    result_id = db.save_analysis("p", {"columns": ["PID", "Name"], "rows": rows})
    loaded = db.load_result(result_id)
    assert loaded["rows"] == rows


def test_unbound_database_ignores_writes(tmp_path):
    database = Database(str(tmp_path), "Unbound")
    assert database.save_analysis("p", {"columns": [], "rows": []}) is None
    assert database.get_case() is None
    database.update_case_image("/x")        # no case row: a no-op, not a crash


def test_missing_ids_are_handled(db):
    assert db.load_result(999999) is None
    db.delete_result(999999)
    db.delete_bookmark(999999)
    db.remove_data_source(999999)


def test_rename_tag_onto_an_existing_name_is_refused(db):
    db.add_tag("One")
    db.add_tag("Two")
    assert db.rename_tag("One", "Two") is False


def test_data_source_for_a_missing_file(db, tmp_path):
    source_id = db.add_data_source(str(tmp_path / "gone.raw"))
    assert db.get_data_source(source_id)["size_bytes"] == 0


def test_same_source_twice_is_one_row(db, tmp_path):
    image = tmp_path / "img.raw"
    image.write_bytes(b"\0" * 10)
    first = db.add_data_source(str(image))
    second = db.add_data_source(str(image))
    assert first == second
    assert len(db.get_data_sources()) == 1


# ── Mail ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("address, ok", [
    ("analyst@example.com", True),
    ("Analyst <analyst@example.com>", True),
    ("a@b.co", True),
    ("", False),
    ("no-at-sign", False),
    ("a@@b.com", False),
    ("@example.com", False),
    ("a@example", False),
    ("a@example.", False),
    ("a@.example.com", False),         # empty first label
    ("a@example..com", False),         # empty middle label
    ("a b@example.com", False),
    ("a@exa\tmple.com", False),       # parseaddr strips the tab silently
    ("a@example.com\r\nBcc: x@evil.com", False),   # header injection
    (None, False),
])
def test_valid_address(address, ok):
    assert valid_address(address) is ok


def test_split_addresses_tolerates_mess():
    assert split_addresses(" a@x.com ; ,, b@y.org,") == ["a@x.com", "b@y.org"]
    assert split_addresses("") == []
    assert split_addresses(None) == []


@pytest.mark.parametrize("account", [
    Account(host="", sender="a@x.com"),
    Account(host="smtp.x.com", sender="bad"),
    Account(host="smtp.x.com", sender="a@x.com", security="rot13"),
])
def test_bad_accounts_are_refused(account):
    with pytest.raises(MailError):
        account.validate()


@pytest.mark.parametrize("message", [
    Message(to=[], subject="s"),
    Message(to=["   "], subject="s"),
    Message(to=["a@x.com"], subject="   "),
    Message(to=["a@x.com"], cc=["broken"], subject="s"),
])
def test_bad_messages_are_refused(message):
    with pytest.raises(MailError):
        message.validate()


# ── Plugins ───────────────────────────────────────────────────────────────────

def _info(*args):
    return PluginInfo(id="windows.x.X", os="windows", args=tuple(args))


def test_build_command_args_drops_empty_values():
    info = _info(
        PluginArg("pid", "List", False), PluginArg("name", "String", False),
        PluginArg("dump", "Boolean", False), PluginArg("offset", "Int", False),
    )
    assert build_command_args(info, {"pid": [], "name": "   ", "dump": False,
                                     "offset": None}) == []


def test_build_command_args_keeps_zero_and_lists():
    info = _info(PluginArg("pid", "List", False), PluginArg("offset", "Int", False),
                 PluginArg("dump", "Boolean", False))
    assert build_command_args(info, {"pid": [4, 8], "offset": 0, "dump": True}) == [
        "--pid", "4", "8", "--offset", "0", "--dump"]


def test_build_command_args_ignores_unknown_names():
    assert build_command_args(_info(), {"--rm -rf": "x"}) == []


def test_registry_without_volatility_still_works():
    registry = PluginRegistry(None)
    assert registry.available is False
    assert registry.get("does.not.Exist") is None
    assert registry.search("") == registry.search("   ")
    assert registry.ribbon("windows"), "the curated catalog should still populate"
    assert registry.ribbon("no-such-os") == [] or all(
        p.os == "generic" for _, _, ps in registry.ribbon("no-such-os") for p in ps)


@pytest.mark.parametrize("pid, expected", [
    ("windows.pslist.PsList", "windows"), ("linux.bash.Bash", "linux"),
    ("mac.ps.PsList", "mac"), ("timeliner.Timeliner", "generic"), ("", "generic"),
])
def test_plugin_os(pid, expected):
    assert plugin_os(pid) == expected


# ── OS detection ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("content, os_name", [
    (b"", ""),
    (b"PAGE", ""),                     # truncated magic
    (b"PAGEDU64" + b"\0" * 100, "windows"),
    (b"\x7fELF\x02\x01", "linux"),
    (b"EMiL", "linux"),
    (b"\0" * 4096, ""),
])
def test_sniff_header_on_small_and_truncated_files(tmp_path, content, os_name):
    image = tmp_path / "img"
    image.write_bytes(content)
    assert sniff_header(str(image)).os == os_name


def test_sniff_header_on_a_directory_or_missing_file(tmp_path):
    assert sniff_header(str(tmp_path)).os == ""
    assert sniff_header(str(tmp_path / "missing")).os == ""


def test_profile_summary_never_raises():
    assert ImageProfile().summary() == "Unidentified image"
    assert ImageProfile(os="solaris").summary().startswith("Solaris")
    assert "likely" in ImageProfile(os="windows", confidence="likely").summary()


@pytest.mark.parametrize("stdout", [
    "", "\n\n", "Variable,Value\n", "garbage without columns",
    "Variable,Value\nKernel Base\n",           # short row
    'Variable,Value\n"unterminated,quote\n',
])
def test_parse_info_rows_tolerates_garbage(stdout):
    assert isinstance(parse_info_rows(stdout), dict)


def test_detect_os_from_banner():
    assert detect_os_from_banner("Linux version 5.15.0-91-generic") == "linux"
    assert detect_os_from_banner("Darwin Kernel Version 21.6.0") == "mac"
    assert detect_os_from_banner("") is None
    assert detect_os_from_banner("nothing to see") is None


def test_build_environment_puts_case_symbols_first(monkeypatch):
    monkeypatch.setenv("VOLATILITY_SYMBOL_DIRS", os.pathsep.join(["/existing", ""]))
    env = build_environment(["/case/symbols", "", "/existing"])
    assert env["VOLATILITY_SYMBOL_DIRS"].split(os.pathsep) == ["/case/symbols", "/existing"]
    assert env["PYTHONUNBUFFERED"] == "1"


# ── Symbols ───────────────────────────────────────────────────────────────────

def test_symbol_counting_on_missing_and_empty_dirs(tmp_path):
    assert symbols_present(str(tmp_path)) is False
    assert count_symbols(str(tmp_path / "nope")) == 0
    (tmp_path / "symbols" / "windows").mkdir(parents=True)
    (tmp_path / "symbols" / "windows" / "readme.txt").write_text("x")
    assert symbols_present(str(tmp_path)) is False
    (tmp_path / "symbols" / "windows" / "nt.json.xz").write_bytes(b"x")
    assert count_symbols(str(tmp_path)) == 1


def _zip(path, members):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)


def test_extract_refuses_path_traversal(tmp_path, qapp):
    archive = tmp_path / "pack.zip"
    _zip(archive, {"windows/ok.json": "{}", "../escape.json": "{}",
                   "/abs/evil.json": "{}", "windows/../../up.json": "{}"})
    target = tmp_path / "case" / "symbols"
    target.mkdir(parents=True)
    added = SymbolDownloader(str(tmp_path / "case"), "windows")._extract(str(archive), str(target))
    assert added == 1
    assert (target / "windows" / "ok.json").exists()
    assert not (tmp_path / "case" / "escape.json").exists()
    assert not (tmp_path / "up.json").exists()


def test_extract_into_a_relative_directory(tmp_path, qapp, monkeypatch):
    """Regression: a relative target rejected every member as traversal."""
    archive = tmp_path / "pack.zip"
    _zip(archive, {"windows/a.json": "{}", "windows/b.json": "{}"})
    monkeypatch.chdir(tmp_path)
    os.makedirs("rel/symbols")
    added = SymbolDownloader("rel", "windows")._extract(str(archive), "rel/symbols")
    assert added == 2


def test_unknown_symbol_pack_fails_cleanly(qapp, tmp_path):
    downloader = SymbolDownloader(str(tmp_path), "beos")
    results = []
    downloader.done.connect(lambda ok, msg: results.append((ok, msg)))
    downloader.run()
    assert results and results[0][0] is False


# ── Reports ───────────────────────────────────────────────────────────────────

def test_report_escapes_hostile_plugin_output(tmp_path):
    """Process names and command lines come from the suspect machine."""
    case = Case.create(str(tmp_path), "<script>alert(1)</script>",
                       notes="<img src=x onerror=alert(1)>")
    hostile = "<script>alert('pwn')</script>"
    results = [{"id": 1, "plugin": "windows.cmdline.CmdLine", "created_at": "now"}]
    html = build_html(case, [], results, [], [], outputs={
        1: {"columns": ["PID", hostile], "rows": [["4", hostile]]}})
    assert "<script>" not in html
    assert "onerror=alert" not in html.replace("onerror=alert(1)&gt;", "")
    assert "&lt;script&gt;" in html


def test_report_caps_huge_outputs(tmp_path):
    case = Case.create(str(tmp_path), "Big")
    rows = [[str(i), "p"] for i in range(10000)]
    results = [{"id": 1, "plugin": "p", "created_at": ""}]
    html = build_html(case, [], results, [], [], max_rows=50,
                      outputs={1: {"columns": ["PID", "Name"], "rows": rows}})
    assert html.count("<tr>") < 200
    assert "first 50 of 10,000" in html


def test_report_with_nothing_in_it(tmp_path):
    case = Case.create(str(tmp_path), "Empty")
    assert "Nothing recorded" in build_html(case, [], [], [], [])
    data = json.loads(build_json(case, [], [], [], []))
    assert data["results"] == [] and data["extracted_files"] == []


def test_json_report_handles_non_serialisable_values(tmp_path):
    case = Case.create(str(tmp_path), "Odd")
    data = json.loads(build_json(case, [{"added": object()}], [], [], []))
    assert isinstance(data["data_sources"][0]["added"], str)
