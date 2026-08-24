"""
The icon set.

Plugin tiles used emoji. Emoji are the wrong tool for a forensics application:
they render in whatever colour font the platform ships, so they ignore the
palette entirely, they are inconsistent in weight and baseline across machines,
and a wall of them reads as decoration rather than as an instrument panel.

These are stroked vector glyphs on a 24x24 grid, drawn in the colour they are
asked for, cached per (name, size, colour). They are deliberately plain: one
weight, round caps, no fills.

The catalog in core.plugins still carries an emoji per plugin, so `for_emoji`
maps those to glyph names. That keeps the plugin metadata as it is and means an
unmapped emoji degrades to a neutral glyph rather than to a missing icon.
"""

from __future__ import annotations

from PyQt6.QtCore import QByteArray, QSize, Qt
from PyQt6.QtGui import QColor, QIcon, QPainter, QPixmap
from PyQt6.QtSvg import QSvgRenderer

# Every glyph is the inner markup of a 24x24 SVG. `stroke="currentColor"` is
# substituted at render time; nothing here carries a literal colour.
_GLYPHS: dict[str, str] = {
    "box": '<path d="M21 8v8a2 2 0 0 1-1 1.73l-7 4a2 2 0 0 1-2 0l-7-4A2 2 0 0 1 3 16V8a2 2 0 0 1 1-1.73l7-4a2 2 0 0 1 2 0l7 4A2 2 0 0 1 21 8z"/><path d="M3.3 7 12 12l8.7-5"/><path d="M12 22V12"/>',
    "list": '<path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"/>',
    "tree": '<circle cx="18" cy="6" r="2.5"/><circle cx="6" cy="18" r="2.5"/><path d="M6 15.5V4h9.5"/><path d="M18 8.5v3a4 4 0 0 1-4 4H8.5"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="M21 21l-5-5"/>',
    "terminal": '<path d="M5 17l6-5-6-5"/><path d="M13 18h6"/>',
    "link": '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7L11.8 5.2"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
    "badge": '<rect x="2.5" y="4.5" width="19" height="15" rx="2"/><circle cx="16" cy="10.5" r="2"/><path d="M13.2 15.5a3 3 0 0 1 5.6 0M6 9.5h4M6 13.5h2.5"/>',
    "lock": '<rect x="4" y="10.5" width="16" height="10" rx="2"/><path d="M7.5 10.5V7a4.5 4.5 0 0 1 9 0v3.5"/>',
    "unlock": '<rect x="4" y="10.5" width="16" height="10" rx="2"/><path d="M7.5 10.5V7a4.5 4.5 0 0 1 8.9-1"/>',
    "key": '<circle cx="7.5" cy="16" r="4.5"/><path d="M10.8 12.8 21 3"/><path d="M17.5 6.5 20 9"/>',
    "braces": '<path d="M8 3a2 2 0 0 0-2 2v4a2 2 0 0 1-2 2 2 2 0 0 1 2 2v4a2 2 0 0 0 2 2"/><path d="M16 3a2 2 0 0 1 2 2v4a2 2 0 0 0 2 2 2 2 0 0 0-2 2v4a2 2 0 0 1-2 2"/>',
    "network": '<rect x="2.5" y="15.5" width="6" height="6" rx="1"/><rect x="15.5" y="15.5" width="6" height="6" rx="1"/><rect x="9" y="2.5" width="6" height="6" rx="1"/><path d="M5.5 15.5v-3h13v3M12 8.5v4"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a13 13 0 0 1 0 18 13 13 0 0 1 0-18z"/>',
    "signal": '<path d="M4.5 12a7.5 7.5 0 0 1 15 0"/><path d="M1.5 12a10.5 10.5 0 0 1 21 0"/><path d="M8 12a4 4 0 0 1 8 0"/><circle cx="12" cy="19" r="1.5"/>',
    "plug": '<path d="M12 21.5V17"/><path d="M9 7.5V2.5M15 7.5V2.5"/><path d="M6.5 7.5h11V12a5.5 5.5 0 0 1-11 0z"/>',
    "shield": '<path d="M12 21.5s7.5-3.8 7.5-9.5V5.2L12 2.5 4.5 5.2v6.8c0 5.7 7.5 9.5 7.5 9.5z"/>',
    "chip": '<rect x="5" y="5" width="14" height="14" rx="2"/><rect x="9.5" y="9.5" width="5" height="5" rx="1"/><path d="M9 2.5V5M15 2.5V5M9 19v2.5M15 19v2.5M2.5 9H5M2.5 15H5M19 9h2.5M19 15h2.5"/>',
    "disk": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="2.5"/>',
    "map": '<path d="M2 6.5v15l6.5-3.5 7 3.5 6.5-3.5v-15L15.5 6.5l-7-3.5z"/><path d="M8.5 3v15M15.5 6.5v15"/>',
    "layers": '<path d="M12 2.5 2.5 7 12 11.5 21.5 7z"/><path d="M2.5 16.5 12 21l9.5-4.5"/><path d="M2.5 11.75 12 16.25l9.5-4.5"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 6.5V12l3.5 2"/>',
    "user": '<path d="M20 21v-1.5a4.5 4.5 0 0 0-4.5-4.5h-7A4.5 4.5 0 0 0 4 19.5V21"/><circle cx="12" cy="7.5" r="4"/>',
    "file": '<path d="M14 2.5H6.5a2 2 0 0 0-2 2v15a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V8z"/><path d="M14 2.5V8h5.5"/>',
    "bug": '<path d="M12 20.5c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6z"/><path d="M9.5 7.5V6.5a2.5 2.5 0 0 1 5 0v1"/><path d="M6 13H2.5M21.5 13H18M6.5 8.5 4 6.5M17.5 8.5 20 6.5M6.5 17.5 4 19.5M17.5 17.5 20 19.5"/>',
    "gear": '<circle cx="12" cy="12" r="3"/><path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.2 5.2l2.1 2.1M16.7 16.7l2.1 2.1M18.8 5.2l-2.1 2.1M7.3 16.7l-2.1 2.1"/>',
    "tag": '<path d="M20.6 13.4 13.4 20.6a2 2 0 0 1-2.8 0L2.5 12.5V2.5h10l8.1 8.1a2 2 0 0 1 0 2.8z"/><circle cx="7" cy="7" r="1.2"/>',
    "calendar": '<rect x="3.5" y="4.5" width="17" height="16" rx="2"/><path d="M16 2.5v4M8 2.5v4M3.5 10h17"/>',
    "sun": '<circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M19.1 4.9l-1.8 1.8M6.7 17.3l-1.8 1.8"/>',
    "moon": '<path d="M20.5 14.5A8.5 8.5 0 0 1 9.5 3.5a8.5 8.5 0 1 0 11 11z"/>',
    "command": '<path d="M8.5 3.5A2.5 2.5 0 1 1 6 6v12a2.5 2.5 0 1 1 2.5-2.5h7A2.5 2.5 0 1 1 18 18V6a2.5 2.5 0 1 1-2.5 2.5z"/>',
    "cross": '<path d="M6 6l12 12M18 6L6 18"/>',
    "chevron": '<path d="M9 6l6 6-6 6"/>',
    "target": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.3"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 16.5v-5M12 7.8h.01"/>',
    "eye": '<path d="M2 12s3.8-7 10-7 10 7 10 7-3.8 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="2.8"/>',
    "shuffle": '<path d="M16.5 3.5H21v4.5"/><path d="M3 21 21 3.5"/><path d="M21 16v5h-4.5"/><path d="M15 15l6 6"/><path d="M3 3.5l5 5"/>',
    "brick": '<rect x="3" y="4.5" width="18" height="15" rx="1.5"/><path d="M3 9.5h18M3 14.5h18M8.5 4.5v5M15.5 4.5v5M12 9.5v5M7 14.5v5M17 14.5v5"/>',
    "keyboard": '<rect x="2.5" y="6" width="19" height="12" rx="2"/><path d="M6 9.5h.01M9.5 9.5h.01M13 9.5h.01M16.5 9.5h.01M6 14.5h11.5"/>',
    "copy": '<rect x="9" y="9" width="12.5" height="12.5" rx="2"/><path d="M5.5 15H4.5a2 2 0 0 1-2-2V4.5a2 2 0 0 1 2-2H13a2 2 0 0 1 2 2v1"/>',
    "download": '<path d="M21 15.5v3.5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3.5"/><path d="M7.5 10 12 14.5 16.5 10"/><path d="M12 14.5V3"/>',
    "phone": '<path d="M21.5 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 1.6 4.2 2 2 0 0 1 3.6 2h3a2 2 0 0 1 2 1.7c.1 1 .3 1.9.7 2.8a2 2 0 0 1-.5 2.1L7.6 9.9a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.1-.4c.9.3 1.8.6 2.8.7a2 2 0 0 1 1.7 2z"/>',
    "monitor": '<rect x="2.5" y="3.5" width="19" height="13" rx="2"/><path d="M8.5 21h7M12 16.5V21"/>',
    "news": '<path d="M6 4.5a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2V19a2.5 2.5 0 0 1-2.5 2.5h-15A2.5 2.5 0 0 1 2 19v-8a2 2 0 0 1 2-2h2"/><path d="M10 6.5h8v4h-8zM10 14h8M10 17.5h5"/>',
    "wrench": '<path d="M20.9 4.6 17.2 8.3a1.5 1.5 0 0 1-2.1 0l-1.4-1.4a1.5 1.5 0 0 1 0-2.1l3.7-3.7a6 6 0 0 0-7.9 7.9l-6.9 6.9a2.1 2.1 0 0 0 3 3l6.9-6.9a6 6 0 0 0 8.4-7.4z"/>',
    "pin": '<path d="M12 17v4.5"/><path d="M9 10.8a2 2 0 0 1-1.1 1.8l-1.8.9A2 2 0 0 0 5 15.2V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.8a2 2 0 0 0-1.1-1.7l-1.8-.9A2 2 0 0 1 15 10.8V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z"/>',
    "book": '<path d="M4.5 19.5v-15A2.5 2.5 0 0 1 7 2h12.5v20H7a2.5 2.5 0 0 1 0-5h12.5"/>',
    "activity": '<path d="M22 12h-4.5l-3 8.5-6-17-3 8.5H2"/>',
    "database": '<ellipse cx="12" cy="5.5" rx="8.5" ry="3"/><path d="M3.5 5.5v13c0 1.7 3.8 3 8.5 3s8.5-1.3 8.5-3v-13"/><path d="M3.5 12c0 1.7 3.8 3 8.5 3s8.5-1.3 8.5-3"/>',
    "flask": '<path d="M9.5 2.5v6.2L4 18.4A2 2 0 0 0 5.8 21.5h12.4a2 2 0 0 0 1.8-3.1L14.5 8.7V2.5"/><path d="M8 2.5h8M7.4 14.5h9.2"/>',
    "window": '<rect x="2.5" y="3.5" width="19" height="17" rx="2"/><path d="M2.5 8.5h19M6 6h.01M9 6h.01"/>',
    "penguin": '<ellipse cx="12" cy="14" rx="6" ry="7.5"/><path d="M12 2.5a4 4 0 0 1 4 4v2a4 4 0 0 1-8 0v-2a4 4 0 0 1 4-4z"/><path d="M10.5 6.5h.01M13.5 6.5h.01"/>',
    "apple": '<path d="M15.5 8c-1.2 0-2.2.7-3.5.7S9.7 8 8.5 8C6 8 3.5 10.2 3.5 14c0 3.6 2.6 7.5 4.7 7.5 1.2 0 1.9-.8 3.8-.8s2.5.8 3.8.8c2.1 0 4.7-3.9 4.7-7.5 0-3.8-2.5-6-5-6z"/><path d="M12 5.5c.3-1.7 1.7-3 3.2-3"/>',
}

_NEUTRAL = "target"

# The catalog's emoji, mapped onto the glyphs above. Anything unmapped falls
# back to _NEUTRAL rather than disappearing.
_FROM_EMOJI: dict[str, str] = {
    "🗂": "box", "🌲": "tree", "🔎": "search", "💬": "terminal", "📦": "box",
    "🔗": "link", "🪪": "badge", "🔐": "lock", "🌱": "braces",
    "📡": "signal", "🌐": "globe", "🔌": "plug", "🛰": "signal", "🧱": "brick",
    "🧩": "layers", "💽": "disk", "💾": "database", "📚": "book", "🔍": "search",
    "🔒": "lock", "🗺": "map", "🚶": "activity",
    "🔑": "key", "📋": "list", "📜": "file", "👤": "user", "⏰": "clock",
    "🧾": "file",
    "ℹ": "info", "🧰": "wrench", "⏱": "clock", "⚙": "gear", "🏷": "tag",
    "📅": "calendar", "📌": "pin", "📞": "phone", "📤": "download",
    "📰": "news", "🕰": "clock", "🖥": "monitor", "🚗": "gear", "🛠": "wrench",
    "🛡": "shield",
    "🦠": "bug", "⌨": "keyboard", "🎭": "copy", "🎯": "target", "👻": "eye",
    "🔀": "shuffle", "🕳": "target", "🗝": "key",
    "🧬": "layers", "🧵": "activity", "🪝": "link", "🪢": "link",
    "🪤": "target", "🫥": "eye", "🫧": "database", "🧮": "chip",
    "🧿": "shield", "🩹": "wrench", "🔓": "unlock", "🎫": "badge",
    # OS badges.
    "🪟": "window", "🐧": "penguin", "🍎": "apple", "🔬": "flask",
}

_TEMPLATE = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
    'fill="none" stroke="{color}" stroke-width="{width}" '
    'stroke-linecap="round" stroke-linejoin="round">{body}</svg>'
)

_cache: dict[tuple, QPixmap] = {}


def glyph_names() -> list[str]:
    return sorted(_GLYPHS)


def for_emoji(emoji: str) -> str:
    """The glyph name that stands in for a catalog emoji."""
    return _FROM_EMOJI.get((emoji or "").strip(), _NEUTRAL)


def pixmap(name: str, size: int = 18, color: str = "#8b949e",
           width: float = 1.7, ratio: float = 1.0) -> QPixmap:
    """
    Render a glyph. Cached, because the ribbon asks for fifty of them every
    time the palette or the density changes.
    """
    key = (name, size, color, width, round(ratio, 2))
    hit = _cache.get(key)
    if hit is not None:
        return hit

    body = _GLYPHS.get(name) or _GLYPHS[_NEUTRAL]
    markup = _TEMPLATE.format(color=color, width=width, body=body)

    pixels = max(1, int(size * ratio))
    canvas = QPixmap(pixels, pixels)
    canvas.setDevicePixelRatio(ratio)
    canvas.fill(Qt.GlobalColor.transparent)

    painter = QPainter(canvas)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    QSvgRenderer(QByteArray(markup.encode())).render(painter)
    painter.end()

    _cache[key] = canvas
    return canvas


def icon(name: str, size: int = 18, color: str = "#8b949e", width: float = 1.7,
         ratio: float = 1.0) -> QIcon:
    return QIcon(pixmap(name, size=size, color=color, width=width, ratio=ratio))


def clear_cache():
    """Drop the rendered glyphs; called when the palette changes."""
    _cache.clear()
