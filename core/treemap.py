"""
Squarified treemap layout (Bruls, Huizing and van Wijk, 2000).

Splits a rectangle into one tile per value, each tile's area proportional to
its value, while keeping tiles as close to square as possible: a long thin
sliver is hard to see, hard to hover and has no room for a label. The same
layout WinDirStat and WizTree use for disks.

The algorithm takes values largest first and lays them in rows along the
shorter side of the space left. A value joins the current row while that
makes the row's worst aspect ratio better; when it would make it worse, the
row is fixed and a new one starts in the remaining space.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rect:
    x: float
    y: float
    w: float
    h: float

    def contains(self, px: float, py: float) -> bool:
        return self.x <= px < self.x + self.w and self.y <= py < self.y + self.h

    def inset(self, d: float) -> Rect:
        w, h = max(0.0, self.w - 2 * d), max(0.0, self.h - 2 * d)
        return Rect(self.x + min(d, self.w / 2), self.y + min(d, self.h / 2), w, h)


def _worst(row: list[float], side: float) -> float:
    """The worst aspect ratio of `row` laid along a side of length `side`."""
    total = sum(row)
    if total <= 0 or side <= 0:
        return float("inf")
    biggest, smallest = max(row), min(row)
    side2, total2 = side * side, total * total
    if side2 * smallest <= 0 or total2 <= 0:   # underflowed: a value far below the rest
        return float("inf")
    return max(side2 * biggest / total2, total2 / (side2 * smallest))


def squarify(values: list[float], rect: Rect) -> list[Rect]:
    """
    One Rect per value, in the order given. Values must be sorted largest
    first; zero or negative values get an empty Rect.
    """
    out: list[Rect] = [Rect(rect.x, rect.y, 0.0, 0.0)] * len(values)
    total = sum(v for v in values if v > 0)
    if total <= 0 or rect.w <= 0 or rect.h <= 0:
        return out
    # Work in areas, so a tile's area is exactly its share of the rectangle.
    scale = rect.w * rect.h / total
    items = [(i, v * scale) for i, v in enumerate(values) if v > 0]

    x, y, w, h = rect.x, rect.y, rect.w, rect.h
    row: list[tuple[int, float]] = []

    def place(row_items: list[tuple[int, float]]):
        nonlocal x, y, w, h
        area = sum(a for _, a in row_items)
        if w >= h:                       # lay the row as a column on the left
            width = area / h if h else 0.0
            offset = y
            for index, a in row_items:
                height = a / width if width else 0.0
                out[index] = Rect(x, offset, width, height)
                offset += height
            x, w = x + width, max(0.0, w - width)
        else:                            # lay the row along the top
            height = area / w if w else 0.0
            offset = x
            for index, a in row_items:
                width = a / height if height else 0.0
                out[index] = Rect(offset, y, width, height)
                offset += width
            y, h = y + height, max(0.0, h - height)

    for item in items:
        side = min(w, h)
        candidate = row + [item]
        if not row or _worst([a for _, a in candidate], side) <= _worst([a for _, a in row], side):
            row = candidate
        else:
            place(row)
            row = [item]
    if row:
        place(row)
    return out
