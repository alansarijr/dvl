"""
Target profiles: the memory map, vector table and peripheral models the
emulator needs for a given firmware image.

A profile is a TOML file (see targets/). Every field is optional; whatever
it leaves out is derived from the ELF:

  - vector table: .isr_vector section, known symbols, or the
    initial-SP/reset-handler shape at the lowest loaded address
  - initial SP: vector table slot 0
  - flash / RAM: the loaded segments, split along the architectural
    Cortex-M map (code below 0x20000000, SRAM 0x20000000-0x3FFFFFFF), with
    RAM extended up to the initial SP
  - peripherals: the whole architectural peripheral region and the
    private peripheral bus, served by the generic poll-breaker

An SVD file (`svd = "device.svd"`) contributes each peripheral's address
range and, for the UART named by `svd_uart` (or the first one found), the
status/data register offsets and RXNE/TXE bits.
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, replace
from typing import Optional

from .elfinfo import ElfGroundTruth

PAGE = 0x1000
CODE_TOP = 0x20000000          # Cortex-M: code region is 0x00000000-0x1FFFFFFF
SRAM_TOP = 0x40000000          # SRAM region is 0x20000000-0x3FFFFFFF
DEFAULT_PERIPHERALS = [("peripheral", 0x40000000, 0x20000000), ("ppb", 0xE0000000, 0x00100000)]

DEFAULT_INSTRUCTION_BUDGET = 4_000_000
DEFAULT_MAX_PLAUSIBLE_OVERRUN = 4096
# cwe_checker's default CWE-789 stack threshold.
DEFAULT_CWE789_STACK_THRESHOLD = 7500


@dataclass(frozen=True)
class Region:
    name: str
    kind: str          # "flash" | "ram"
    base: int
    size: int

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, addr: int) -> bool:
        return self.base <= addr < self.end


@dataclass(frozen=True)
class UartModel:
    name: str
    base: int
    status: int        # offset of the status register (RXNE / TXE bits)
    data: int          # offset of the receive data register
    rxne: int          # status mask: receive data available
    txe: int           # status mask: transmitter ready
    tx_data: Optional[int] = None   # offset of the transmit data register, if separate

    @property
    def status_addr(self) -> int:
        return self.base + self.status

    @property
    def data_addr(self) -> int:
        return self.base + self.data

    @property
    def tx_data_addr(self) -> int:
        return self.base + (self.data if self.tx_data is None else self.tx_data)


@dataclass
class TargetProfile:
    name: str = "auto"
    regions: list = field(default_factory=list)            # list[Region]
    vector_table: Optional[tuple] = None                    # (address, slot count incl. initial SP)
    initial_sp: Optional[int] = None
    peripherals: list = field(default_factory=list)         # list[(name, base, size)], mapped as MMIO
    uarts: list = field(default_factory=list)               # list[UartModel]; the first is the input channel
    sim_exit: Optional[int] = None                          # test-harness "exit" register
    sim_print: Optional[int] = None
    instruction_budget: int = DEFAULT_INSTRUCTION_BUDGET
    max_plausible_overrun: int = DEFAULT_MAX_PLAUSIBLE_OVERRUN
    cwe789_stack_threshold: int = DEFAULT_CWE789_STACK_THRESHOLD
    source: str = "derived from the ELF"
    resolved: bool = False

    def region_of(self, addr: int) -> Optional[Region]:
        for r in self.regions:
            if r.contains(addr):
                return r
        return None

    @property
    def ram(self) -> Optional[Region]:
        return next((r for r in self.regions if r.kind == "ram"), None)

    @property
    def uart(self) -> Optional[UartModel]:
        return self.uarts[0] if self.uarts else None

    @property
    def stack_top(self) -> Optional[int]:
        if self.initial_sp is not None:
            return self.initial_sp
        return self.ram.end if self.ram else None

    def emulation_blocker(self, gt: ElfGroundTruth) -> Optional[str]:
        """None if this image can be emulated as a Cortex-M target, else why not."""
        if self.vector_table is None:
            return "no Cortex-M vector table was found (section, symbol, or reset-handler shape)"
        reset = gt.read_bytes(self.vector_table[0] + 4, 4)
        if not reset or not int.from_bytes(reset, "little") & 1 or gt.mode_at(gt.entry) == "arm":
            return "the reset vector is not a Thumb address, so this is not a Cortex-M image"
        if self.initial_sp is None or self.ram is None or not (self.ram.base < self.initial_sp <= self.ram.end):
            return "the initial SP does not fall inside a RAM region"
        flash = self.region_of(gt.entry)
        if flash is None:
            return f"the reset handler 0x{gt.entry:x} is not inside a mapped region"
        return None


def _align_down(x: int) -> int:
    return x & ~(PAGE - 1)


def _align_up(x: int) -> int:
    return (x + PAGE - 1) & ~(PAGE - 1)


def _derive_regions(gt: ElfGroundTruth, initial_sp: Optional[int]) -> list:
    spans = [(a, a + len(d)) for a, d in list(gt.segments) + list(gt.load_images) if len(d)]
    spans += [(a, a + s) for a, s, _ in gt.sections.values() if s]
    code = [(lo, hi) for lo, hi in spans if lo < CODE_TOP]
    sram = [(lo, hi) for lo, hi in spans if CODE_TOP <= lo < SRAM_TOP]
    if initial_sp is not None and CODE_TOP < initial_sp <= SRAM_TOP:
        # The stack grows down from the initial SP toward whatever RAM the
        # image does not use, so map from the SRAM region's start.
        sram.append((CODE_TOP, initial_sp))
    regions = []
    if code:
        lo = _align_down(min(l for l, _ in code))
        regions.append(Region("flash", "flash", lo, _align_up(max(h for _, h in code)) - lo))
    if sram:
        lo = _align_down(min(l for l, _ in sram))
        regions.append(Region("ram", "ram", lo, _align_up(max(h for _, h in sram)) - lo))
    return regions


def _int(v) -> int:
    return int(v, 0) if isinstance(v, str) else int(v)


def load(path: str) -> TargetProfile:
    """Parse a TOML profile. Fields it omits are filled in by resolve()."""
    with open(path, "rb") as f:
        data = tomllib.load(f)
    base_dir = os.path.dirname(os.path.abspath(path))
    prof = TargetProfile(name=data.get("name", os.path.splitext(os.path.basename(path))[0]),
                         source=path)

    for m in data.get("memory", []):
        prof.regions.append(Region(m.get("name", m["kind"]), m["kind"], _int(m["base"]), _int(m["size"])))
    vt = data.get("vector_table")
    if vt:
        prof.vector_table = (_int(vt["address"]), _int(vt["count"])) if "count" in vt else (_int(vt["address"]), None)
    if "initial_sp" in data:
        prof.initial_sp = _int(data["initial_sp"])
    for p in data.get("peripheral", []):
        prof.peripherals.append((p.get("name", "peripheral"), _int(p["base"]), _int(p["size"])))
    for u in data.get("uart", []):
        prof.uarts.append(UartModel(
            name=u.get("name", "uart"), base=_int(u["base"]), status=_int(u["status"]),
            data=_int(u["data"]), rxne=_int(u["rxne"]), txe=_int(u["txe"]),
            tx_data=_int(u["tx_data"]) if "tx_data" in u else None))
    sim = data.get("sim", {})
    prof.sim_exit = _int(sim["exit"]) if "exit" in sim else None
    prof.sim_print = _int(sim["print"]) if "print" in sim else None
    limits = data.get("limits", {})
    prof.instruction_budget = _int(limits.get("instruction_budget", prof.instruction_budget))
    prof.max_plausible_overrun = _int(limits.get("max_plausible_overrun", prof.max_plausible_overrun))
    prof.cwe789_stack_threshold = _int(data.get("cwe789", {}).get("stack_threshold", prof.cwe789_stack_threshold))

    if "svd" in data:
        from . import svd
        dev = svd.load(os.path.join(base_dir, data["svd"]))
        prof.peripherals.extend(dev.ranges())
        uart = dev.uart(data.get("svd_uart"))
        if uart is not None and not prof.uarts:
            prof.uarts.append(uart)
    return prof


def resolve(gt: ElfGroundTruth, profile: Optional[TargetProfile] = None) -> TargetProfile:
    """Fill in everything the profile leaves out from the ELF, and make the
    vector table visible to the static call graph."""
    from .callgraph import find_vector_table

    prof = replace(profile) if profile is not None else TargetProfile()
    prof.regions = list(prof.regions)
    prof.peripherals = list(prof.peripherals)

    if prof.vector_table is not None and prof.vector_table[1] is None:
        gt.cache["vector_table_override"] = (prof.vector_table[0], None)
        prof.vector_table = find_vector_table(gt)
    elif prof.vector_table is not None:
        gt.cache["vector_table_override"] = prof.vector_table
    else:
        prof.vector_table = find_vector_table(gt)

    if prof.initial_sp is None and prof.vector_table is not None:
        word = gt.read_bytes(prof.vector_table[0], 4)
        if word and len(word) == 4:
            prof.initial_sp = int.from_bytes(word, "little")

    if not prof.regions:
        prof.regions = _derive_regions(gt, prof.initial_sp)
    if not prof.peripherals:
        prof.peripherals = list(DEFAULT_PERIPHERALS)
    elif not any(b <= 0xE000E000 < b + s for _, b, s in prof.peripherals):
        prof.peripherals.append(DEFAULT_PERIPHERALS[1])
    prof.resolved = True
    return prof
