"""
Per-process memory use and program icons, for DumpScope's memory map.

The figures are read from each process's EPROCESS, the same counters Task
Manager reports, so the plugin is as quick as pslist:

* PrivateWorkingSet: RAM used by the process alone (Task Manager's "Memory").
* WorkingSet: all RAM mapped into the process, shared pages (DLLs, mapped
  files) included, so the sum over processes exceeds physical memory.
* Commit: private memory the process has committed, in RAM or in the page
  file.
* Virtual: address space reserved. Browsers reserve terabytes; it is not RAM.

Description is the program's FileDescription from its version resource
("Google Chrome" for chrome.exe). Icon is the program's icon as a base64 .ico, taken from the resource section
of its executable as mapped in the process. It is emitted once per executable
path; it is empty when those pages were not in memory when the image was
taken.
"""

import base64
import datetime
import logging
import struct

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import conversion
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

PAGE = 0x1000
# Larger counters come from a torn or freed EPROCESS, not from a process.
SANE_LIMIT = 1 << 42
RT_ICON = 3
RT_GROUP_ICON = 14
RT_VERSION = 16
# The resource section is read in one go; a larger one is not worth the time.
MAX_RESOURCES = 16 * 1024 * 1024
MAX_ICON = 512 * 1024
WANTED_SIZE = 64


def _version_string(block: bytes, key: str) -> str | None:
    """
    One value from a VS_VERSIONINFO block's StringFileInfo.

    Each String entry is wLength, wValueLength (in characters), wType, the
    key in UTF-16 with its terminator, padding to a 4-byte boundary, then the
    value.
    """
    needle = (key + "\0").encode("utf-16-le")
    at = block.find(needle)
    if at < 6 or at % 2:
        return None
    start = at - 6
    length, value_chars = struct.unpack_from("<HH", block, start)
    value_at = at + len(needle)
    value_at += (-value_at) % 4
    if not value_chars or value_at >= start + length:
        return None
    raw = block[value_at:value_at + value_chars * 2]
    text = raw.decode("utf-16-le", errors="replace").split("\0", 1)[0].strip()
    return text[:120] or None



class ProcMem(interfaces.plugins.PluginInterface):
    """Memory use and icon for every process (DumpScope memory map)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel",
                architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)),
            requirements.BooleanRequirement(
                name="no-icons", description="Skip icon extraction",
                default=False, optional=True),
        ]

    # ── Memory counters ──────────────────────────────────────────────────────

    @staticmethod
    def _working_set(proc):
        """(working set, private working set, peak working set) in bytes."""
        vm = proc.Vm
        instance = vm.Instance if vm.has_member("Instance") else vm
        ws = int(instance.WorkingSetSize) * PAGE if instance.has_member("WorkingSetSize") else None
        private = None
        if instance.has_member("WorkingSetPrivateSize"):
            private = int(instance.WorkingSetPrivateSize) * PAGE
        elif instance.has_member("WorkingSetLeafPrivateSize"):
            private = int(instance.WorkingSetLeafPrivateSize) * PAGE
        peak = None
        if instance.has_member("PeakWorkingSetSize"):
            peak = int(instance.PeakWorkingSetSize) * PAGE
        return ws, private, peak

    @staticmethod
    def _image_path(context, kernel, proc):
        try:
            name = proc.ImageFilePointer.FileName.get_string()
            if name:
                return name
        except (exceptions.InvalidAddressException, AttributeError):
            pass
        try:
            layer = proc.add_process_layer()
            peb = context.object(kernel.symbol_table_name + constants.BANG + "_PEB",
                                 layer_name=layer, offset=proc.Peb)
            return peb.ProcessParameters.ImagePathName.get_string()
        except (exceptions.InvalidAddressException, AttributeError):
            return None

    # ── Icon extraction ──────────────────────────────────────────────────────

    @staticmethod
    def _read(layer, offset, length):
        data = layer.read(offset, length, pad=True)
        return data if data.strip(b"\0") else None

    @staticmethod
    def _section_of(head, nt, rva):
        """(VirtualAddress, PointerToRawData) of the section holding `rva`."""
        count = struct.unpack_from("<H", head, nt + 6)[0]
        optional_size = struct.unpack_from("<H", head, nt + 20)[0]
        table = nt + 24 + optional_size
        for i in range(min(count, 96)):
            at = table + i * 40
            if at + 40 > len(head):
                break
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", head, at + 8)
            if vaddr <= rva < vaddr + max(vsize, raw_size):
                return vaddr, raw_ptr
        return None

    @staticmethod
    def _control_area_pages(kernel_layer, area, start, end):
        """
        (physical offset, file offset) of each page of `area` that is in RAM
        and lies in the file range [start, end).

        The same walk as vol3's CONTROL_AREA.get_available_pages, but limited
        to the subsections covering the range, with each run of PTEs read in
        one go: going through vol3's object model one PTE at a time took most
        of a minute for a few large executables. x64 PTE layout only.
        """
        sector = 0x200 if area.u.Flags.Image == 1 else 0x1000
        subsection = area.get_subsection()
        for _ in range(4096):
            if not subsection:
                return
            try:
                if subsection.ControlArea != area.vol.offset:
                    return
                first = subsection.StartingSector * sector
                count = int(subsection.PtesInSubsection)
                lo = max(start, first)
                hi = min(end, first + count * PAGE)
                if lo < hi:
                    a, b = (lo - first) // PAGE, (hi - first + PAGE - 1) // PAGE
                    raw = kernel_layer.read(subsection.SubsectionBase + a * 8,
                                            (b - a) * 8, pad=True)
                    for i, (pte,) in enumerate(struct.iter_unpack("<Q", raw)):
                        frame = (pte >> 12) & ((1 << 36) - 1)
                        if pte & 1:                                   # valid
                            yield frame << 12, first + (a + i) * PAGE
                        elif pte & (1 << 11) and not pte & (1 << 10):  # transition
                            yield (frame & ((1 << 33) - 1)) << 12, first + (a + i) * PAGE
                subsection = subsection.NextSubsection
            except exceptions.InvalidAddressException:
                return

    @classmethod
    def _cached_file_pages(cls, context, kernel_layer_name, file_obj, start, end):
        """
        (file offset, bytes) for the pages of `file_obj` in [start, end) that
        are still in memory in the system's file caches, the way
        windows.dumpfiles finds them.

        A program's own processes rarely touch its icon; Explorer reads it by
        mapping the executable as a data file, so the pages usually survive
        only in the file's data section, image section or cache map.
        """
        kernel_layer = context.layers[kernel_layer_name]
        physical = context.layers[kernel_layer.config["memory_layer"]]
        is_64bit = kernel_layer.metadata.get("architecture") == "Intel64"
        pointers = file_obj.SectionObjectPointer
        for member in ("DataSectionObject", "ImageSectionObject"):
            try:
                area = getattr(pointers, member).dereference().cast("_CONTROL_AREA")
                if not area.is_valid():
                    continue
                pages = (cls._control_area_pages(kernel_layer, area, start, end)
                         if is_64bit else
                         ((m, f) for m, f, _size in area.get_available_pages()))
                for mem_offset, file_offset in pages:
                    if file_offset + PAGE > start and file_offset < end:
                        yield file_offset, physical.read(mem_offset, PAGE, pad=True)
            except (exceptions.InvalidAddressException, AttributeError):
                continue
        try:
            cache_map = pointers.SharedCacheMap.dereference().cast("_SHARED_CACHE_MAP")
            if cache_map.is_valid():
                for mem_offset, file_offset, size in cache_map.get_available_pages():
                    if file_offset + size > start and file_offset < end:
                        yield file_offset, kernel_layer.read(mem_offset, size, pad=True)
        except (exceptions.InvalidAddressException, AttributeError):
            pass

    @classmethod
    def _fill_from_file_cache(cls, context, kernel_layer_name, proc, head, nt,
                              res_rva, res, present):
        """
        Fill the pages of `res` that were not mapped in the process, adding
        each page recovered to `present`.
        """
        missing = [i for i in range(0, len(res), PAGE) if i not in present]
        if not missing:
            return res
        section = cls._section_of(head, nt, res_rva)
        if section is None:
            return res
        vaddr, raw_ptr = section
        # File offset of res[0].
        start = raw_ptr + (res_rva - vaddr)
        end = start + len(res)
        buffer = bytearray(res)
        wanted = set(missing)
        try:
            file_obj = proc.ImageFilePointer.dereference()
        except exceptions.InvalidAddressException:
            return res
        for file_offset, data in cls._cached_file_pages(context, kernel_layer_name, file_obj,
                                                        start, end):
            if wanted <= present:
                break
            lo, hi = max(start, file_offset), min(end, file_offset + len(data))
            if lo >= hi or not data.strip(b"\0"):
                continue
            for page in range((lo - start) // PAGE * PAGE, hi - start, PAGE):
                if page not in wanted:
                    continue
                a, b = max(page, lo - start), min(page + PAGE, hi - start)
                buffer[a:b] = data[a + start - file_offset:b + start - file_offset]
                if a == page and b == min(page + PAGE, len(res)):
                    present.add(page)
        return bytes(buffer)

    @classmethod
    def _program_info(cls, context, kernel_layer_name, proc, use_file_cache=True):
        """(icon as .ico bytes, file description); either may be None."""
        layer_name = proc.add_process_layer()
        if not layer_name:
            return None, None
        layer = context.layers[layer_name]
        base = int(proc.SectionBaseAddress)
        head = cls._read(layer, base, PAGE)
        if not head or head[:2] != b"MZ":
            return None, None
        nt = struct.unpack_from("<I", head, 0x3C)[0]
        if nt + 24 + 128 > len(head) or head[nt:nt + 4] != b"PE\0\0":
            return None, None
        optional = nt + 24
        magic = struct.unpack_from("<H", head, optional)[0]
        directories = optional + (112 if magic == 0x20B else 96)
        res_rva, res_size = struct.unpack_from("<II", head, directories + 2 * 8)
        if not res_rva or not res_size:
            return None, None
        length = min(res_size, MAX_RESOURCES)
        res = layer.read(base + res_rva, length, pad=True)
        # Pages really read, as opposed to zero padding: a transparent icon is
        # zeros too, so the bytes alone cannot tell a gap from a picture.
        present = {i for i in range(0, length, PAGE)
                   if layer.is_valid(base + res_rva + i, min(PAGE, length - i))}
        if use_file_cache:
            res = cls._fill_from_file_cache(context, kernel_layer_name, proc, head, nt,
                                            res_rva, res, present)
        if not res.strip(b"\0"):
            return None, None

        def entries(offset):
            if offset + 16 > len(res):
                return []
            named, ids = struct.unpack_from("<HH", res, offset + 12)
            out = []
            for i in range(min(named + ids, 4096)):
                at = offset + 16 + i * 8
                if at + 8 > len(res):
                    break
                name, target = struct.unpack_from("<II", res, at)
                out.append((None if name & 0x80000000 else name, target))
            return out

        def first_leaf(target):
            """Follow subdirectories down to the first data entry."""
            for _ in range(3):
                if not target & 0x80000000:
                    break
                children = entries(target & 0x7FFFFFFF)
                if not children:
                    return None
                target = children[0][1]
            if target & 0x80000000 or target + 8 > len(res):
                return None
            rva, size = struct.unpack_from("<II", res, target)
            return rva, size

        def data(rva, size):
            if size <= 0 or size > MAX_ICON:
                return None
            start = rva - res_rva
            if start >= 0 and start + size <= len(res):
                pages = range(start // PAGE * PAGE, start + size, PAGE)
                if any(page not in present for page in pages):
                    return None
                return res[start:start + size]
            if not layer.is_valid(base + rva, size):
                return None
            return layer.read(base + rva, size)

        types = dict((name, target) for name, target in entries(0) if name is not None)

        def icon():
            if RT_GROUP_ICON not in types or RT_ICON not in types:
                return None
            groups = entries(types[RT_GROUP_ICON] & 0x7FFFFFFF)
            icons = {name: target for name, target in entries(types[RT_ICON] & 0x7FFFFFFF)
                     if name is not None}
            leaf = first_leaf(groups[0][1]) if groups else None
            group = data(*leaf) if leaf else None
            if not group or len(group) < 6:
                return None
            _reserved, kind, count = struct.unpack_from("<HHH", group, 0)
            if kind != 1:
                return None
            candidates = []
            for i in range(min(count, 64)):
                at = 6 + i * 14
                if at + 14 > len(group):
                    break
                width, height, colours, _r, planes, bits, _size, icon_id = struct.unpack_from(
                    "<BBBBHHIH", group, at)
                pixels = width or 256
                candidates.append((abs(pixels - WANTED_SIZE), -bits, pixels, i,
                                   (width, height, colours, planes, bits, icon_id)))
            for *_rank, (width, height, colours, planes, bits, icon_id) in sorted(candidates):
                if icon_id not in icons:
                    continue
                leaf = first_leaf(icons[icon_id])
                image = data(*leaf) if leaf else None
                if not image:
                    continue
                # PNG, or a DIB whose BITMAPINFOHEADER is 40 bytes long.
                if image[:8] == b"\x89PNG\r\n\x1a\n":
                    if b"IEND" not in image[-16:]:
                        continue
                elif image[:4] != b"\x28\0\0\0":
                    continue
                header = struct.pack("<HHH", 0, 1, 1) + struct.pack(
                    "<BBBBHHII", width, height, colours, 0, planes, bits, len(image), 22)
                return header + image
            return None

        def description():
            if RT_VERSION not in types:
                return None
            children = entries(types[RT_VERSION] & 0x7FFFFFFF)
            leaf = first_leaf(children[0][1]) if children else None
            block = data(*leaf) if leaf else None
            return _version_string(block, "FileDescription") or \
                _version_string(block, "ProductName") if block else None

        return icon(), description()


    # ── Output ───────────────────────────────────────────────────────────────

    def _generator(self, procs):
        kernel = self.context.modules[self.config["kernel"]]
        want_icons = not self.config.get("no-icons", False)
        icon_done = set()
        # Every chrome.exe shares one file cache, so trying all forty of them
        # costs time and finds nothing more than the first few.
        icon_tries: dict[str, int] = {}
        desc_done = set()
        for proc in procs:
            try:
                pid = int(proc.UniqueProcessId)
                ppid = int(proc.InheritedFromUniqueProcessId)
                name = utility.array_to_string(proc.ImageFileName)
            except exceptions.InvalidAddressException:
                continue
            try:
                ws, private, peak = self._working_set(proc)
            except (exceptions.InvalidAddressException, AttributeError):
                ws = private = peak = None
            ws, private, peak = (v if v is not None and 0 <= v < SANE_LIMIT else None
                                 for v in (ws, private, peak))
            try:
                commit = int(proc.CommitCharge) * PAGE
                if not 0 <= commit < SANE_LIMIT:
                    commit = None
            except (exceptions.InvalidAddressException, AttributeError):
                commit = None
            try:
                virtual = int(proc.VirtualSize)
            except (exceptions.InvalidAddressException, AttributeError):
                virtual = None
            try:
                threads = int(proc.ActiveThreads)
            except (exceptions.InvalidAddressException, AttributeError):
                threads = None
            try:
                created = conversion.wintime_to_datetime(proc.CreateTime.QuadPart)
            except (exceptions.InvalidAddressException, AttributeError):
                created = None
            try:
                exited = conversion.wintime_to_datetime(proc.ExitTime.QuadPart)
            except (exceptions.InvalidAddressException, AttributeError):
                exited = None
            if not isinstance(created, datetime.datetime):
                created = None
            if not isinstance(exited, datetime.datetime):
                exited = None
            path = self._image_path(self.context, kernel, proc)
            icon = described = ""
            key = (path or name).lower()
            if want_icons and key not in icon_done and pid > 4 and icon_tries.get(key, 0) < 3:
                icon_tries[key] = icon_tries.get(key, 0) + 1
                # The file cache is the same for every process of a program.
                first_try = icon_tries[key] == 1
                try:
                    raw, text = self._program_info(self.context, kernel.layer_name, proc,
                                                   use_file_cache=first_try)
                except (exceptions.InvalidAddressException, struct.error) as exc:
                    vollog.debug("No icon for PID %s: %s", pid, exc)
                    raw = text = None
                if raw:
                    icon = base64.b64encode(raw).decode("ascii")
                    icon_done.add(key)
                if text and key not in desc_done:
                    described = text
                    desc_done.add(key)

            def value(v):
                return renderers.UnreadableValue() if v is None else v

            yield (0, (pid, ppid, name, value(path), value(private), value(ws), value(peak),
                       value(commit), value(virtual), value(threads),
                       value(created), value(exited), described, icon))

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("PPID", int), ("Name", str), ("Path", str),
             ("PrivateWorkingSet", int), ("WorkingSet", int), ("PeakWorkingSet", int),
             ("Commit", int), ("Virtual", int), ("Threads", int),
             ("CreateTime", datetime.datetime), ("ExitTime", datetime.datetime),
             ("Description", str), ("Icon", str)],
            self._generator(pslist.PsList.list_processes(
                context=self.context, kernel_module_name=self.config["kernel"])),
        )
