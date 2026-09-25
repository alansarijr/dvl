"""
ELF/DWARF ground-truth extraction.

Per the prompt's "Known Hard Problems": we do NOT trust the upstream
SAST tool's function-boundary or ARM/Thumb mode determination blindly.
This module independently re-derives both directly from the ELF/DWARF,
which is the actual source of truth cwe_checker/r2 themselves had to
guess at.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Optional

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


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
    # For globals: absolute address. For locals: frame-relative offset
    # (DW_OP_fbreg SLEB128 operand); resolve against the runtime frame
    # base register value (r7 for GCC ARM -O0 / -mthumb) to get the
    # concrete address at emulation time.
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
    symbols_by_addr: dict = field(default_factory=dict)     # addr -> name (functions + objects)
    variables_by_function: dict = field(default_factory=dict)  # func_name -> list[VariableInfo]
    global_variables: dict = field(default_factory=dict)    # var_name -> VariableInfo

    def mode_at(self, addr: int) -> str:
        """Resolve ARM vs Thumb at an arbitrary address via mapping symbols
        ($a / $t / $d), the ground truth the ELF toolchain itself emitted --
        independent of whatever cwe_checker/upstream disassembly guessed."""
        idx = bisect.bisect_right(self.mapping_points, (addr, "\xff")) - 1
        if idx < 0:
            return "thumb" if self.is_thumb_entry else "arm"
        return self.mapping_points[idx][1]

    def function_at(self, addr: int) -> Optional[FunctionInfo]:
        for f in self.functions:
            if f.contains(addr):
                return f
        return None

    def function_by_name(self, name: str) -> Optional[FunctionInfo]:
        for f in self.functions:
            if f.name == name:
                return f
        return None


def _parse_variable_location(die, address_size=4) -> tuple:
    """Returns (kind, value) where kind is 'addr' | 'fbreg' | None."""
    loc = die.attributes.get("DW_AT_location")
    if loc is None:
        return (None, None)
    expr = loc.value
    if not expr:
        return (None, None)
    op = expr[0]
    if op == 0x03:  # DW_OP_addr
        addr = int.from_bytes(bytes(expr[1:1 + address_size]), "little")
        return ("addr", addr)
    if op == 0x91:  # DW_OP_fbreg
        # SLEB128 decode of expr[1:]
        result = 0
        shift = 0
        i = 1
        while i < len(expr):
            b = expr[i]
            result |= (b & 0x7F) << shift
            shift += 7
            i += 1
            if not (b & 0x80):
                if b & 0x40:
                    result -= (1 << shift)
                break
        return ("fbreg", result)
    return (None, None)


def _type_byte_size(die, cu) -> Optional[int]:
    try:
        type_ref = die.attributes.get("DW_AT_type")
        if type_ref is None:
            return None
        type_die = die.get_DIE_from_attribute("DW_AT_type")
        return _resolve_type_size(type_die)
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
    f = open(path, "rb")
    elf = ELFFile(f)

    entry = elf.header["e_entry"]
    is_thumb_entry = bool(entry & 1)
    entry &= ~1

    functions = []
    mapping_points = []
    symbols_by_addr = {}

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
                symbols_by_addr[addr] = name
            elif stt == "STT_OBJECT" and name:
                symbols_by_addr[val] = name

    mapping_points.sort(key=lambda t: t[0])
    functions.sort(key=lambda fi: fi.address)

    segments = []
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_LOAD":
            data = seg.data()
            segments.append((seg["p_vaddr"], data))

    gt = ElfGroundTruth(
        path=path,
        entry=entry,
        is_thumb_entry=is_thumb_entry,
        functions=functions,
        mapping_points=mapping_points,
        segments=segments,
        symbols_by_addr=symbols_by_addr,
    )

    # DWARF: locals (fbreg) grouped by enclosing function, globals (addr) flat.
    if elf.has_dwarf_info():
        dwinfo = elf.get_dwarf_info()
        for cu in dwinfo.iter_CUs():
            root = cu.get_top_DIE()
            _walk_dwarf(root, cu, gt, current_function=None)

    f.close()
    return gt


def _walk_dwarf(die, cu, gt: ElfGroundTruth, current_function: Optional[str]):
    if die.tag == "DW_TAG_subprogram":
        name_attr = die.attributes.get("DW_AT_name")
        if name_attr is not None:
            current_function = name_attr.value.decode("utf-8", "replace")
            gt.variables_by_function.setdefault(current_function, [])

    if die.tag in ("DW_TAG_variable", "DW_TAG_formal_parameter"):
        name_attr = die.attributes.get("DW_AT_name")
        if name_attr is not None:
            name = name_attr.value.decode("utf-8", "replace")
            kind, value = _parse_variable_location(die)
            size = _type_byte_size(die, cu)
            if kind == "addr":
                vi = VariableInfo(name=name, byte_size=size, is_global=True, address=value)
                gt.global_variables[name] = vi
            elif kind == "fbreg":
                vi = VariableInfo(name=name, byte_size=size, is_global=False, fbreg_offset=value)
                if current_function is not None:
                    gt.variables_by_function.setdefault(current_function, []).append(vi)

    for child in die.iter_children():
        _walk_dwarf(child, cu, gt, current_function)
