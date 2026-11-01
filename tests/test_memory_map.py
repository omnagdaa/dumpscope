"""The Memory Usage map: treemap layout, ProcMem parsing, report figure, view."""
import base64
import struct
import zlib

import pytest

from core import memory_map
from core.memory_map import (
    MEMORY_PLUGIN, format_bytes, latest_payload, programs_from_payload, ranked,
    treemap_svg,
)
from core.treemap import Rect, squarify

MB = 1024 * 1024
COLUMNS = ["PID", "PPID", "Name", "Path", "PrivateWorkingSet", "WorkingSet",
           "PeakWorkingSet", "Commit", "Virtual", "Threads", "CreateTime", "ExitTime",
           "Description", "Icon"]


def _png(size=4) -> bytes:
    """A tiny valid PNG, so the view has a real icon to decode."""
    raw = b"".join(b"\0" + b"\x4f\x8f\xd9\xff" * size for _ in range(size))

    def chunk(kind, data):
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


ICON = base64.b64encode(_png()).decode()


def _row(pid, name, path, private, ppid="1", exited="N/A", description="N/A", icon="N/A"):
    return [str(pid), ppid, name, path, str(private), str(private * 2), str(private * 3),
            str(private), str(private * 100), "12", "2024-03-14 09:00:00", exited,
            description, icon]


def procmem_payload():
    brave = r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
    return {
        "plugin": MEMORY_PLUGIN,
        "columns": COLUMNS,
        "rows": [
            _row(100, "brave.exe", brave, 1500 * MB, description="Brave Browser", icon=ICON),
            _row(101, "brave.exe", brave, 900 * MB),
            _row(102, "brave.exe", brave, 400 * MB),
            _row(200, "Code.exe", r"C:\Users\a\AppData\Local\Programs\VS Code\Code.exe",
                 700 * MB, description="Visual Studio Code"),
            _row(300, "svchost.exe", r"C:\Windows\System32\svchost.exe", 30 * MB),
            _row(301, "svchost.exe", r"C:\Windows\System32\svchost.exe", 20 * MB),
            # Same name, different folder: a separate program.
            _row(666, "svchost.exe", r"C:\Users\a\Temp\svchost.exe", 5 * MB),
            _row(400, "old.exe", r"C:\old.exe", 50 * MB, exited="2024-03-14 08:00:00"),
            ["bad", "row"],
            _row(500, "System", "", 0),
        ],
    }


# ── Squarified layout ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("values", [
    [10], [5, 5], [6, 6, 4, 3, 2, 2, 1], [100, 1, 1, 1, 1], list(range(40, 0, -1)),
])
def test_squarify_areas_are_proportional_and_inside(values):
    area = Rect(10, 20, 800, 500)
    rects = squarify(values, area)
    total = sum(values)
    assert len(rects) == len(values)
    for value, rect in zip(values, rects, strict=True):
        assert rect.w * rect.h == pytest.approx(value / total * 800 * 500, rel=1e-6)
        assert rect.x >= 10 - 1e-6 and rect.y >= 20 - 1e-6
        assert rect.x + rect.w <= 810 + 1e-6 and rect.y + rect.h <= 520 + 1e-6
    assert sum(r.w * r.h for r in rects) == pytest.approx(800 * 500)


def test_squarify_keeps_tiles_close_to_square():
    rects = squarify([6, 6, 4, 3, 2, 2, 1], Rect(0, 0, 600, 400))
    worst = max(max(r.w / r.h, r.h / r.w) for r in rects)
    assert worst < 3.5                       # a slice layout would give ~25


def test_squarify_tiles_do_not_overlap():
    rects = squarify([9, 7, 5, 4, 3, 2, 1, 1], Rect(0, 0, 300, 200))
    for i, a in enumerate(rects):
        for b in rects[i + 1:]:
            overlap_w = min(a.x + a.w, b.x + b.w) - max(a.x, b.x)
            overlap_h = min(a.y + a.h, b.y + b.h) - max(a.y, b.y)
            assert overlap_w <= 1e-6 or overlap_h <= 1e-6


def test_squarify_degenerate_input():
    assert squarify([], Rect(0, 0, 10, 10)) == []
    zero = squarify([0, 0], Rect(0, 0, 10, 10))
    assert all(r.w == 0 and r.h == 0 for r in zero)
    assert squarify([5, 0], Rect(0, 0, 10, 10))[1].w == 0
    assert all(r.w == 0 for r in squarify([1, 2], Rect(0, 0, 0, 10)))


def test_rect_inset_never_goes_negative():
    assert Rect(0, 0, 3, 3).inset(5).w == 0
    assert Rect(0, 0, 10, 10).contains(0, 0) and not Rect(0, 0, 10, 10).contains(10, 5)


# ── Parsing ───────────────────────────────────────────────────────────────────

def test_processes_are_grouped_by_path_not_name():
    programs = {p.key: p for p in programs_from_payload(procmem_payload())}
    system = programs[r"c:\windows\system32\svchost.exe"]
    impostor = programs[r"c:\users\a\temp\svchost.exe"]
    assert {p.pid for p in system.processes} == {"300", "301"}
    assert [p.pid for p in impostor.processes] == ["666"]


def test_title_icon_and_description_come_from_any_process():
    programs = {p.name: p for p in programs_from_payload(procmem_payload())}
    brave = programs["brave.exe"]
    assert brave.title == "Brave Browser"
    assert brave.icon and brave.icon.startswith(b"\x89PNG")
    assert brave.total("PrivateWorkingSet") == 2800 * MB
    assert programs["Code.exe"].icon is None


def test_exited_and_malformed_rows_are_dropped():
    names = {p.name for p in programs_from_payload(procmem_payload())}
    assert "old.exe" not in names
    assert "old.exe" in {p.name for p in programs_from_payload(procmem_payload(),
                                                                include_exited=True)}


def test_ranked_drops_empty_programs_and_sorts():
    shown = ranked(programs_from_payload(procmem_payload()), "PrivateWorkingSet")
    assert shown[0].name == "brave.exe"
    assert "System" not in {p.name for p in shown}
    assert [p.value("PrivateWorkingSet") for p in shown[0].processes] == \
        [1500 * MB, 900 * MB, 400 * MB]


def test_a_bad_icon_is_ignored_not_fatal():
    payload = procmem_payload()
    payload["rows"][0][-1] = "!!not base64!!"
    brave = next(p for p in programs_from_payload(payload) if p.name == "brave.exe")
    assert brave.icon is None


def test_latest_payload_picks_procmem():
    other = {"plugin": "windows.pslist.PsList", "columns": [], "rows": []}
    assert latest_payload([other, procmem_payload()])["plugin"] == MEMORY_PLUGIN
    assert latest_payload([other]) is None


def test_format_bytes():
    assert format_bytes(0) == "0 B"
    assert format_bytes(1536) == "2 KB"
    assert format_bytes(5 * MB) == "5.0 MB"
    assert format_bytes(3 * 1024 * MB) == "3.0 GB"


# ── Report figure ─────────────────────────────────────────────────────────────

def test_svg_has_a_box_per_process_icons_and_flags():
    svg = treemap_svg(programs_from_payload(procmem_payload()), flagged_pids={"666"})
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    assert svg.count("<title>") == 7          # every live process with memory
    assert "data:image/x-icon;base64," in svg
    assert "Flagged by Insights" in svg and "#cf222e" in svg
    assert "Brave Browser" in svg


def test_svg_escapes_names_from_the_image():
    payload = procmem_payload()
    payload["rows"][3][12] = "<script>alert(1)</script>"
    svg = treemap_svg(programs_from_payload(payload))
    assert "<script>" not in svg and "&lt;script&gt;" in svg


def test_svg_of_nothing_is_still_valid():
    assert treemap_svg([]).endswith("</svg>")


def test_colours_are_distinct_for_the_top_programs():
    colours = [memory_map.colour_for(i) for i in range(12)]
    assert len(set(colours)) == 12
    assert memory_map.colour_for(40) == memory_map.TAIL_COLOR


# ── The tab ───────────────────────────────────────────────────────────────────

def test_view_shows_empty_state_then_the_map(qapp):
    from ui.memory_view import MemoryUsageView
    view = MemoryUsageView()
    view.resize(1200, 700)
    asked = []
    view.collect_requested.connect(asked.append)
    assert view.stack.currentIndex() == 0
    view.collect_btn.click()
    assert asked == [[MEMORY_PLUGIN]]

    view.set_programs(programs_from_payload(procmem_payload()), {"666": ["Suspicious path"]})
    view.show()
    qapp.processEvents()
    assert view.stack.currentIndex() == 1
    assert view.tree.topLevelItemCount() == 4
    assert view.tree.topLevelItem(0).text(0) == "Brave Browser"
    assert "2.7 GB" in view.summary_lbl.text()
    assert view.canvas._tiles, "nothing laid out"
    view.grab()                                    # paints without raising


def test_view_hover_tooltip_and_zoom(qapp):
    from ui.memory_view import MemoryUsageView
    view = MemoryUsageView()
    view.resize(1200, 700)
    view.set_programs(programs_from_payload(procmem_payload()), {"666": ["Suspicious path"]})
    view.show()
    qapp.processEvents()
    canvas = view.canvas
    tile = canvas._tiles[0]
    proc, box = tile.processes[0]
    found = canvas.hit(box.x + box.w / 2, box.y + box.h / 2)
    assert found[0] is tile and found[1] is proc
    tip = canvas.tooltip_html(tile, proc)
    assert "Brave Browser" in tip and "PID 100" in tip and "Program total" in tip

    impostor = next(t for t in canvas._tiles if t.program.key.endswith(r"temp\svchost.exe"))
    assert "Flagged by Insights" in canvas.tooltip_html(impostor, impostor.processes[0][0])

    view.zoom_to(tile.program.key)
    assert len(canvas._tiles) == 1 and view.back_btn.isVisibleTo(view)
    assert "Brave Browser" in view.crumb_lbl.text()
    view.zoom_to("")
    assert len(canvas._tiles) == 4


def test_view_tooltip_escapes_image_strings(qapp):
    from ui.memory_view import MemoryUsageView
    payload = procmem_payload()
    payload["rows"][3][12] = "<img src=x onerror=1>"
    view = MemoryUsageView()
    view.resize(900, 600)
    view.set_programs(programs_from_payload(payload))
    tile = next(t for t in view.canvas._tiles if t.program.name == "Code.exe")
    assert "<img" not in view.canvas.tooltip_html(tile, tile.processes[0][0])


def test_view_metric_switch_reorders(qapp):
    from ui.memory_view import MemoryUsageView
    view = MemoryUsageView()
    view.resize(900, 600)
    view.set_programs(programs_from_payload(procmem_payload()))
    index = view.metric_box.findData("Virtual")
    view.metric_box.setCurrentIndex(index)
    assert view.metric == "Virtual"
    assert "virtual size" in view.help_lbl.text().lower()


def test_search_dims_non_matching_programs(qapp):
    from ui.memory_view import MemoryUsageView
    view = MemoryUsageView()
    view.resize(900, 600)
    view.set_programs(programs_from_payload(procmem_payload()))
    view.search.setText("666")
    assert view.canvas.matches(next(p for p in view.canvas.programs
                                    if p.key.endswith(r"temp\svchost.exe")))
    assert not view.canvas.matches(view.canvas.programs[0])
    view.grab()


def test_squarify_survives_values_too_small_to_scale():
    from core.treemap import Rect, squarify
    for values in ([6e161, 1.0], [1.0, 6e161]):        # the small one underflows to area 0
        assert len(squarify(values, Rect(0, 0, 1, 1))) == 2


def test_squarify_survives_a_vanishingly_small_rectangle():
    from core.treemap import Rect, squarify
    assert len(squarify([1.0, 1.0], Rect(0, 0, 1e-200, 1e-200))) == 2
