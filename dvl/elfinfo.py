"""
ELF/DWARF ground-truth extraction.

We do not trust the upstream SAST tool's function boundaries or ARM/Thumb
mode. Both are re-derived here from the ELF symbol table, mapping symbols
and DWARF, which is the information the upstream tools had to guess at.
"""
from __future__ import annotations

import bisect
import os
from dataclasses import dataclass, field
from typing import Optional

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.dwarf.locationlists import LocationParser, LocationExpr

DW_OP_addr = 0x03
DW_OP_fbreg = 0x91
DW_OP_call_frame_cfa = 0x9C


@dataclass
class FunctionInfo:
    name: str
    address: int          # real address, Thumb bit (bit0) already stripped
    size: int
    mode: str              # "thumb" | "arm"

    @property
    def end(self) -> int:
        return self.address + self.size

    def contains(self, addr: int) -> bool:
        return self.address <= addr < self.end


@dataclass
class VariableInfo:
    """A DWARF local/global variable, resolved enough to build a bounds oracle."""
    name: str
    byte_size: Optional[int]
    is_global: bool
    # Globals: absolute address. Locals: offset from the owning function's
    # frame base, which is only kept when that frame base is the CFA (the
    # SP value at function entry), so the emulator can resolve it exactly.
    address: Optional[int] = None
    fbreg_offset: Optional[int] = None


@dataclass
class ElfGroundTruth:
    path: str
    entry: int
    is_thumb_entry: bool
    functions: list = field(default_factory=list)          # list[FunctionInfo], sorted by address
    mapping_points: list = field(default_factory=list)      # list[(addr, mode)], sorted
    segments: list = field(default_factory=list)            # list[(vaddr, data)] PT_LOAD, for memory image
    sections: dict = field(default_factory=dict)            # name -> (addr, size) for SHF_ALLOC sections
    symbols_by_addr: dict = field(default_factory=dict)     # addr -> name (functions + objects)
    symbols_by_name: dict = field(default_factory=dict)     # name -> addr (functions + objects)
    variables_by_function: dict = field(default_factory=dict)  # function entry addr -> list[VariableInfo]
    global_variables: dict = field(default_factory=dict)    # addr -> VariableInfo
    line_rows: list = field(default_factory=list)           # list[(addr, file_basename, line)], sorted
    has_dwarf: bool = False

    def __post_init__(self):
        self._func_starts = [f.address for f in self.functions]

    def mode_at(self, addr: int) -> str:
        """ARM vs Thumb at an address, from the toolchain's own mapping
        symbols ($a / $t / $d), independent of any upstream disassembly."""
        idx = bisect.bisect_right(self.mapping_points, (addr, "\xff")) - 1
        if idx < 0:
            return "thumb" if self.is_thumb_entry else "arm"
        return self.mapping_points[idx][1]

    def function_at(self, addr: int) -> Optional[FunctionInfo]:
        idx = bisect.bisect_right(self._func_starts, addr) - 1
        # Aliases share a start address (and may have size 0), so try each.
        while idx >= 0:
            f = self.functions[idx]
            if f.contains(addr):
                return f
            if idx == 0 or self._func_starts[idx - 1] != f.address:
                return None
            idx -= 1
        return None

    def function_by_name(self, name: str) -> Optional[FunctionInfo]:
        for f in self.functions:
            if f.name == name:
                return f
        return None

    def variables_for(self, func: FunctionInfo) -> list:
        return self.variables_by_function.get(func.address, [])

    def read_bytes(self, addr: int, size: int) -> Optional[bytes]:
        for vaddr, data in self.segments:
            if vaddr <= addr < vaddr + len(data):
                off = addr - vaddr
                return data[off:min(off + size, len(data))]
        return None

    def address_for_line(self, filename: str, line: int) -> Optional[int]:
        """Lowest code address the line table attributes to filename:line
        (matched on basename)."""
        base = os.path.basename(filename)
        addrs = [a for a, f, l in self.line_rows if f == base and l == line]
        return min(addrs) if addrs else None

    def line_for_address(self, addr: int) -> Optional[str]:
        idx = bisect.bisect_right(self.line_rows, (addr, "\xff", 1 << 30)) - 1
        if idx < 0:
            return None
        _, f, l = self.line_rows[idx]
        return f"{f}:{l}"


def _decode_sleb128(data) -> int:
    result = 0
    shift = 0
    for b in data:
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                result -= (1 << shift)
            break
    return result


def _parse_expr(expr, address_size: int) -> tuple:
    """Returns (kind, value) where kind is 'addr' | 'fbreg' | None."""
    if not expr:
        return (None, None)
    op = expr[0]
    if op == DW_OP_addr:
        return ("addr", int.from_bytes(bytes(expr[1:1 + address_size]), "little"))
    if op == DW_OP_fbreg:
        return ("fbreg", _decode_sleb128(expr[1:]))
    return (None, None)


def _parse_variable_location(die, loc_parser: LocationParser, address_size: int = 4) -> tuple:
    """Returns (kind, value) where kind is 'addr' | 'fbreg' | None.

    A location list (the norm at -O1 and above) is only accepted when every
    entry agrees on the same frame-base offset; anything else, such as a
    variable that lives in a register for part of its lifetime, is left
    unresolved rather than guessed at."""
    attr = die.attributes.get("DW_AT_location")
    if attr is None:
        return (None, None)
    try:
        loc = loc_parser.parse_from_attribute(attr, die.cu["version"], die)
    except Exception:
        return (None, None)
    if isinstance(loc, LocationExpr):
        return _parse_expr(loc.loc_expr, address_size)
    kinds = {_parse_expr(e.loc_expr, address_size) for e in loc if hasattr(e, "loc_expr")}
    if len(kinds) == 1:
        return kinds.pop()
    return (None, None)


def _follow(die, attr_name: str):
    """Attribute lookup that follows abstract_origin / specification, so
    inlined and out-of-line instances get the name and type of their
    abstract declaration."""
    seen = 0
    while die is not None and seen < 8:
        if attr_name in die.attributes:
            return die, die.attributes[attr_name]
        nxt = None
        for link in ("DW_AT_abstract_origin", "DW_AT_specification"):
            if link in die.attributes:
                nxt = die.get_DIE_from_attribute(link)
                break
        die = nxt
        seen += 1
    return None, None


def _die_name(die) -> Optional[str]:
    _, attr = _follow(die, "DW_AT_name")
    if attr is None:
        return None
    val = attr.value
    return val.decode("utf-8", "replace") if isinstance(val, bytes) else str(val)


def _type_byte_size(die) -> Optional[int]:
    try:
        owner, attr = _follow(die, "DW_AT_type")
        if attr is None:
            return None
        return _resolve_type_size(owner.get_DIE_from_attribute("DW_AT_type"))
    except Exception:
        return None


def _resolve_type_size(type_die, depth=0) -> Optional[int]:
    if type_die is None or depth > 10:
        return None
    if "DW_AT_byte_size" in type_die.attributes:
        return type_die.attributes["DW_AT_byte_size"].value
    tag = type_die.tag
    if tag == "DW_TAG_array_type":
        elem_size = None
        if "DW_AT_type" in type_die.attributes:
            elem_die = type_die.get_DIE_from_attribute("DW_AT_type")
            elem_size = _resolve_type_size(elem_die, depth + 1)
        count = None
        for child in type_die.iter_children():
            if child.tag == "DW_TAG_subrange_type":
                if "DW_AT_count" in child.attributes:
                    count = child.attributes["DW_AT_count"].value
                elif "DW_AT_upper_bound" in child.attributes:
                    count = child.attributes["DW_AT_upper_bound"].value + 1
        if elem_size is not None and count is not None:
            return elem_size * count
        return elem_size
    if tag in ("DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_typedef"):
        if "DW_AT_type" in type_die.attributes:
            inner = type_die.get_DIE_from_attribute("DW_AT_type")
            return _resolve_type_size(inner, depth + 1)
    if tag == "DW_TAG_pointer_type":
        return 4
    return None


def load(path: str) -> ElfGroundTruth:
    with open(path, "rb") as f:
        elf = ELFFile(f)
        return _load(path, elf)


def _load(path: str, elf: ELFFile) -> ElfGroundTruth:
    entry = elf.header["e_entry"]
    is_thumb_entry = bool(entry & 1)
    entry &= ~1

    functions = []
    mapping_points = []
    symbols_by_addr = {}
    symbols_by_name = {}

    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for sym in section.iter_symbols():
            name = sym.name
            val = sym["st_value"]
            stt = sym["st_info"]["type"]

            if name in ("$a", "$t", "$d") or name.startswith(("$a.", "$t.", "$d.")):
                mode = {"$a": "arm", "$t": "thumb", "$d": "data"}[name[:2]]
                mapping_points.append((val, mode))
            elif stt == "STT_FUNC" and name:
                size = sym["st_size"] or 0
                addr = val & ~1
                mode = "thumb" if (val & 1) else "arm"
                functions.append(FunctionInfo(name=name, address=addr, size=size, mode=mode))
                symbols_by_addr.setdefault(addr, name)
                symbols_by_name[name] = addr
            elif stt in ("STT_OBJECT", "STT_NOTYPE") and name and not name.startswith("$"):
                symbols_by_addr.setdefault(val, name)
                symbols_by_name[name] = val

    mapping_points.sort(key=lambda t: t[0])
    functions.sort(key=lambda fi: fi.address)

    segments = []
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_LOAD":
            segments.append((seg["p_vaddr"], seg.data()))

    sections = {}
    for sec in elf.iter_sections():
        if sec.name and sec["sh_flags"] & 0x2:  # SHF_ALLOC
            sections[sec.name] = (sec["sh_addr"], sec["sh_size"])

    gt = ElfGroundTruth(
        path=path,
        entry=entry,
        is_thumb_entry=is_thumb_entry,
        functions=functions,
        mapping_points=mapping_points,
        segments=segments,
        sections=sections,
        symbols_by_addr=symbols_by_addr,
        symbols_by_name=symbols_by_name,
    )

    if elf.has_dwarf_info():
        dwinfo = elf.get_dwarf_info()
        gt.has_dwarf = True
        loc_parser = LocationParser(dwinfo.location_lists())
        for cu in dwinfo.iter_CUs():
            _walk_dwarf(cu.get_top_DIE(), gt, loc_parser, current_function=None)
            _collect_lines(dwinfo, cu, gt)
        gt.line_rows.sort()

    return gt


def _collect_lines(dwinfo, cu, gt: ElfGroundTruth):
    lineprog = dwinfo.line_program_for_CU(cu)
    if lineprog is None:
        return
    file_entries = lineprog["file_entry"]
    base = 0 if lineprog["version"] >= 5 else 1
    for entry in lineprog.get_entries():
        st = entry.state
        if st is None or st.end_sequence or not st.is_stmt:
            continue
        idx = st.file - base
        if not 0 <= idx < len(file_entries):
            continue
        name = file_entries[idx].name
        name = name.decode("utf-8", "replace") if isinstance(name, bytes) else name
        gt.line_rows.append((st.address & ~1, os.path.basename(name), st.line))


def _frame_base_is_cfa(die, loc_parser: LocationParser) -> bool:
    attr = die.attributes.get("DW_AT_frame_base")
    if attr is None:
        return False
    try:
        loc = loc_parser.parse_from_attribute(attr, die.cu["version"], die)
    except Exception:
        return False
    return isinstance(loc, LocationExpr) and list(loc.loc_expr) == [DW_OP_call_frame_cfa]


def _walk_dwarf(die, gt: ElfGroundTruth, loc_parser: LocationParser,
                current_function: Optional[int], fbreg_ok: bool = False):
    """current_function is the entry address of the concrete function whose
    frame the DIE's locals live in. Declarations and abstract instances have
    no low_pc and therefore no frame; their children are skipped. Inlined
    subroutines keep the enclosing function, since their locals are
    addressed from its frame base."""
    if die.tag == "DW_TAG_subprogram":
        low_pc = die.attributes.get("DW_AT_low_pc")
        if low_pc is None:
            current_function, fbreg_ok = None, False
        else:
            current_function = low_pc.value & ~1
            fbreg_ok = _frame_base_is_cfa(die, loc_parser)
            gt.variables_by_function.setdefault(current_function, [])

    if die.tag in ("DW_TAG_variable", "DW_TAG_formal_parameter"):
        name = _die_name(die)
        if name is not None:
            kind, value = _parse_variable_location(die, loc_parser)
            if kind == "addr":
                gt.global_variables[value] = VariableInfo(
                    name=name, byte_size=_type_byte_size(die), is_global=True, address=value)
            elif kind == "fbreg" and current_function is not None and fbreg_ok:
                gt.variables_by_function[current_function].append(VariableInfo(
                    name=name, byte_size=_type_byte_size(die), is_global=False, fbreg_offset=value))

    for child in die.iter_children():
        _walk_dwarf(child, gt, loc_parser, current_function, fbreg_ok)
