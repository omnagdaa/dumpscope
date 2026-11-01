"""
What the memory map draws: the processes in an image grouped by program,
with how much memory each one held.

The figures come from the bundled ``dumpscope.procmem.ProcMem`` plugin
(core/vol_plugins), which reads the counters Windows keeps in each process's
EPROCESS. Grouping is by executable path, not by name, so a second
svchost.exe running from a user folder shows up as its own program rather
than hiding among the real ones.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field

MEMORY_PLUGIN = "dumpscope.procmem.ProcMem"

# (column, label, explanation). The first is the default.
METRICS: tuple[tuple[str, str, str], ...] = (
    ("PrivateWorkingSet", "Private memory",
     "Physical memory (RAM) used by the process alone. This is the figure "
     "Task Manager shows in its Memory column."),
    ("WorkingSet", "Working set",
     "All RAM mapped into the process, including pages it shares with others "
     "(DLLs, mapped files). Shared pages count once per process, so the total "
     "can exceed the machine's RAM."),
    ("Commit", "Committed memory",
     "Private memory the process has reserved backing for, whether it is in "
     "RAM or in the page file."),
    ("Virtual", "Virtual size",
     "Address space the process has reserved. Not RAM: 64-bit browsers "
     "reserve terabytes they never use."),
)
METRIC_LABELS = {key: label for key, label, _ in METRICS}
DEFAULT_METRIC = METRICS[0][0]


@dataclass
class ProcessMemory:
    pid: str
    ppid: str
    name: str
    path: str
    values: dict[str, int]
    threads: str = ""
    created: str = ""
    exited: str = ""

    def value(self, metric: str) -> int:
        return self.values.get(metric, 0)


@dataclass
class Program:
    key: str                    # lower-cased executable path, or name
    name: str                   # executable file name
    description: str            # from the version resource, may be empty
    path: str
    icon: bytes | None
    processes: list[ProcessMemory] = field(default_factory=list)

    @property
    def title(self) -> str:
        """What to call it on screen: "Google Chrome", or "chrome.exe"."""
        return self.description or self.name

    def total(self, metric: str) -> int:
        return sum(p.value(metric) for p in self.processes)


def _int(value) -> int | None:
    text = "" if value is None else str(value).strip()
    return int(text) if text.isdecimal() else None


def _clean(value) -> str:
    text = "" if value is None else str(value).strip()
    return "" if text in ("N/A", "-", "UNREADABLE") else text


def _file_name(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def programs_from_payload(payload: dict, include_exited: bool = False) -> list[Program]:
    """Group a ProcMem payload's rows into programs."""
    columns = [str(c) for c in payload.get("columns") or []]
    at = {name: i for i, name in enumerate(columns)}

    def cell(row, name):
        i = at.get(name)
        return row[i] if i is not None and i < len(row) else None

    programs: dict[str, Program] = {}
    for row in payload.get("rows") or []:
        if not isinstance(row, (list, tuple)):
            continue
        pid = _clean(cell(row, "PID"))
        name = _clean(cell(row, "Name"))
        if not pid.isdecimal() or not name:
            continue
        exited = _clean(cell(row, "ExitTime"))
        if exited and not include_exited:
            continue
        path = _clean(cell(row, "Path"))
        values = {}
        for metric, *_ in METRICS:
            number = _int(cell(row, metric))
            if number is not None:
                values[metric] = number
        key = (path or name).lower()
        program = programs.get(key)
        if program is None:
            # EPROCESS keeps only 15 characters of the name; the path has all of it.
            file_name = _file_name(path) if path else name
            program = Program(key, file_name, "", path, None)
            programs[key] = program
        description = _clean(cell(row, "Description"))
        if description and not program.description:
            program.description = description
        icon = _clean(cell(row, "Icon"))
        if icon and program.icon is None:
            try:
                program.icon = base64.b64decode(icon, validate=True)
            except (binascii.Error, ValueError):
                pass
        program.processes.append(ProcessMemory(
            pid, _clean(cell(row, "PPID")), name, path, values,
            _clean(cell(row, "Threads")), _clean(cell(row, "CreateTime")), exited,
        ))
    return list(programs.values())


def latest_payload(payloads: list[dict]) -> dict | None:
    """The newest stored ProcMem payload; payloads arrive newest first."""
    for payload in payloads or []:
        if isinstance(payload, dict) and payload.get("plugin") == MEMORY_PLUGIN:
            return payload
    return None


def ranked(programs: list[Program], metric: str) -> list[Program]:
    """Programs with something to show for `metric`, largest first."""
    sized = [p for p in programs if p.total(metric) > 0]
    sized.sort(key=lambda p: (-p.total(metric), p.title.lower()))
    for program in sized:
        program.processes.sort(key=lambda proc: -proc.value(metric))
    return sized


def format_bytes(count: int | float) -> str:
    value = float(count or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit in ("B", "KB") else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def summary(programs: list[Program], metric: str) -> dict:
    shown = ranked(programs, metric)
    total = sum(p.total(metric) for p in shown)
    return {
        "total": total,
        "programs": len(shown),
        "processes": sum(len(p.processes) for p in shown),
        "top": [(p.title, p.total(metric), len(p.processes)) for p in shown[:10]],
    }


# ── Colour ────────────────────────────────────────────────────────────────────

# The largest programs get distinct hues in rank order, so the eye finds the
# big ones first; the long tail shares a quiet grey-blue.
PROGRAM_COLORS = ("#4f8fd9", "#d9725f", "#5fae8f", "#d99a4f", "#9a7fd0", "#c9ae5a",
                  "#4fa9b5", "#cf7fa6", "#7fae63", "#b97fc7", "#5f9fd0", "#c98f6a")
TAIL_COLOR = "#6b7684"


def colour_for(rank: int) -> str:
    return PROGRAM_COLORS[rank] if 0 <= rank < len(PROGRAM_COLORS) else TAIL_COLOR


# ── Report figure ─────────────────────────────────────────────────────────────

def _esc(text) -> str:
    import html
    return html.escape("" if text is None else str(text), quote=True)


def treemap_svg(programs: list[Program], metric: str = DEFAULT_METRIC,
                width: int = 960, height: int = 520,
                flagged_pids: set[str] | None = None) -> str:
    """
    The memory map as inline SVG for the HTML report.

    Every box carries a <title>, which browsers show on hover, so the printed
    report has the picture and the opened one has the details. Icons are
    embedded as data: URIs, which the report's Content-Security-Policy allows
    for images only.
    """
    from core.treemap import Rect, squarify

    flagged_pids = flagged_pids or set()
    shown = ranked(programs, metric)
    total = sum(p.total(metric) for p in shown) or 1
    area = Rect(0, 0, width, height)
    program_rects = squarify([p.total(metric) for p in shown], area)
    parts = [f'<svg class="chart memmap" viewBox="0 0 {width} {height}" '
             f'xmlns="http://www.w3.org/2000/svg" role="img" '
             f'aria-label="Memory used by each program">',
             f'<rect width="{width}" height="{height}" fill="#f6f8fa"/>']
    labels = []
    for rank, (program, rect) in enumerate(zip(shown, program_rects, strict=True)):
        if rect.w < 1 or rect.h < 1:
            continue
        colour = colour_for(rank)
        inner = rect.inset(1.5)
        process_rects = squarify([p.value(metric) for p in program.processes], inner)
        for proc, box in zip(program.processes, process_rects):
            if box.w < 0.5 or box.h < 0.5:
                continue
            tip = (f"{program.title} ({program.name})\n{proc.name}, PID {proc.pid}\n"
                   f"{METRIC_LABELS[metric]}: {format_bytes(proc.value(metric))}")
            if proc.pid in flagged_pids:
                tip += "\nFlagged by Insights"
            parts.append(
                f'<rect x="{box.x:.1f}" y="{box.y:.1f}" width="{box.w:.1f}" '
                f'height="{box.h:.1f}" fill="{colour}" fill-opacity="0.85" '
                f'stroke="#ffffff" stroke-width="0.6"><title>{_esc(tip)}</title></rect>')
            if proc.pid in flagged_pids and box.w > 8 and box.h > 8:
                x2, y = box.x + box.w, box.y
                parts.append(f'<path d="M{x2 - 9:.1f},{y:.1f} L{x2:.1f},{y:.1f} '
                             f'L{x2:.1f},{y + 9:.1f} Z" fill="#cf222e"/>')
        parts.append(f'<rect x="{rect.x:.1f}" y="{rect.y:.1f}" width="{rect.w:.1f}" '
                     f'height="{rect.h:.1f}" fill="none" stroke="#ffffff" stroke-width="2"/>')
        side = min(rect.w, rect.h)
        if side < 30:
            continue
        icon = max(16, min(56, side * 0.38))
        cx, cy = rect.x + rect.w / 2, rect.y + rect.h / 2
        has_text = rect.w >= 80 and rect.h >= icon + 40
        top = cy - (icon + (30 if has_text else 0)) / 2
        if program.icon:
            import base64
            data = base64.b64encode(program.icon).decode("ascii")
            labels.append(f'<image x="{cx - icon / 2:.1f}" y="{top:.1f}" width="{icon:.0f}" '
                          f'height="{icon:.0f}" href="data:image/x-icon;base64,{data}"/>')
        else:
            letter = _esc((program.title or "?")[0].upper())
            labels.append(f'<circle cx="{cx:.1f}" cy="{top + icon / 2:.1f}" r="{icon / 2:.1f}" '
                          f'fill="#ffffff" fill-opacity="0.85"/>'
                          f'<text x="{cx:.1f}" y="{top + icon / 2 + icon * 0.18:.1f}" '
                          f'font-size="{icon * 0.5:.0f}" font-weight="700" text-anchor="middle" '
                          f'fill="{colour}">{letter}</text>')
        if has_text:
            share = program.total(metric) / total * 100
            name = program.title if len(program.title) <= max(6, int(rect.w / 7.5)) \
                else program.title[:max(5, int(rect.w / 7.5) - 1)] + "…"
            labels.append(f'<text x="{cx:.1f}" y="{top + icon + 15:.1f}" font-size="12" '
                          f'font-weight="700" text-anchor="middle" fill="#ffffff">'
                          f'{_esc(name)}</text>'
                          f'<text x="{cx:.1f}" y="{top + icon + 29:.1f}" font-size="11" '
                          f'text-anchor="middle" fill="#ffffff" fill-opacity="0.9">'
                          f'{format_bytes(program.total(metric))} · {share:.0f}%</text>')
    parts.extend(labels)
    parts.append("</svg>")
    return "".join(parts)
