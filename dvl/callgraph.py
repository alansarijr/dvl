"""
Static call graph and reachability facts for a firmware image.

Built once per binary (cached on ElfGroundTruth.cache) with capstone,
disassembling each code region in the mode its mapping symbol says
($t / $a), never the upstream tool's mode.

What counts as an entry point:
  - the ELF entry / reset handler
  - every vector-table slot
  - every function whose address is taken: stored in a data word
    (literal pools, .data/.rodata tables, callback registrations) or built
    in code with movw/movt or adr. An indirect call can only land on such
    a function, so treating them all as roots keeps "unreachable" sound
    without resolving which pointer is called where.

Indirect branches are recorded so callers can lower their confidence: a
target computed arithmetically at runtime would escape the address-taken
scan.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import capstone as cs
from capstone import arm_const as A

from .elfinfo import ElfGroundTruth, FunctionInfo

_VECTOR_SECTIONS = (".isr_vector", ".vectors", ".vector_table", ".intvec")
_VECTOR_SYMBOLS = ("__isr_vector", "g_pfnVectors", "__Vectors", "__vector_table",
                   "_vectors", "vector_table", "_vector_table")
_MAX_VECTORS = 256


def _disassembler(mode: str) -> cs.Cs:
    md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB if mode == "thumb" else cs.CS_MODE_ARM)
    md.detail = True
    return md


_MD = {"thumb": _disassembler("thumb"), "arm": _disassembler("arm")}


def decode_one(gt: ElfGroundTruth, addr: int):
    mode = gt.mode_at(addr)
    if mode not in _MD:
        return None
    data = gt.read_bytes(addr, 4)
    if not data:
        return None
    for insn in _MD[mode].disasm(data, addr, count=1):
        return insn
    return None


# -- instruction classification ---------------------------------------------

DIRECT, RETURN, INDIRECT_CALL, INDIRECT_JUMP, JUMP_TABLE = (
    "direct", "return", "indirect_call", "indirect_jump", "jump_table")


def _writes_pc(insn) -> bool:
    try:
        return A.ARM_REG_PC in insn.regs_access()[1]
    except cs.CsError:
        return False


def classify_branch(insn) -> Optional[str]:
    """None for instructions that don't transfer control."""
    iid = insn.id
    if iid in (A.ARM_INS_TBB, A.ARM_INS_TBH):
        return JUMP_TABLE
    if iid in (A.ARM_INS_B, A.ARM_INS_BL, A.ARM_INS_CBZ, A.ARM_INS_CBNZ) or (
            iid == A.ARM_INS_BLX and insn.operands and insn.operands[0].type == A.ARM_OP_IMM):
        return DIRECT
    if iid == A.ARM_INS_BLX:
        return INDIRECT_CALL
    if iid == A.ARM_INS_BX:
        return RETURN if insn.operands[0].reg == A.ARM_REG_LR else INDIRECT_JUMP
    if iid == A.ARM_INS_POP:
        return RETURN if _writes_pc(insn) else None
    if not _writes_pc(insn):
        return None
    if iid == A.ARM_INS_MOV and len(insn.operands) == 2 and insn.operands[1].type == A.ARM_OP_REG \
            and insn.operands[1].reg == A.ARM_REG_LR:
        return RETURN
    if iid in (A.ARM_INS_LDR, A.ARM_INS_LDM):
        for op in insn.operands:
            if op.type == A.ARM_OP_MEM and op.mem.base == A.ARM_REG_SP:
                return RETURN
        if iid == A.ARM_INS_LDM and insn.operands[0].type == A.ARM_OP_REG \
                and insn.operands[0].reg == A.ARM_REG_SP:
            return RETURN
    return INDIRECT_JUMP


def is_call(insn) -> bool:
    return insn.id in (A.ARM_INS_BL, A.ARM_INS_BLX)


def branch_target(insn) -> Optional[int]:
    for op in insn.operands:
        if op.type == A.ARM_OP_IMM:
            return op.imm & ~1
    return None


def _it_length(insn) -> int:
    """Number of instructions an IT/ITT/ITE/... makes conditional."""
    return len(insn.mnemonic) - 1 if insn.id == A.ARM_INS_IT else 0


# -- code regions ---------------------------------------------------------------

def code_regions(gt: ElfGroundTruth, lo: int, hi: int):
    """Yield (start, end, mode) sub-ranges of [lo, hi), split at mapping
    symbols, with mode 'thumb' | 'arm' | 'data'."""
    cuts = sorted({lo, hi} | {a for a, _ in gt.mapping_points if lo < a < hi})
    for a, b in zip(cuts, cuts[1:]):
        yield a, b, gt.mode_at(a)


# -- vector table -----------------------------------------------------------------

def find_vector_table(gt: ElfGroundTruth) -> Optional[tuple]:
    """(address, slot_count) of the Cortex-M vector table, slot 0 being the
    initial SP. Found by section name, then symbol name, then by the
    architectural shape at the lowest loaded address (initial SP followed
    by the reset handler == ELF entry). A target profile can pin the
    address (and optionally the count) via gt.cache["vector_table_override"]."""
    override = gt.cache.get("vector_table_override")
    if override is not None and override[1] is not None:
        return override
    for name in (() if override is not None else _VECTOR_SECTIONS):
        if name in gt.sections:
            addr, size, _ = gt.sections[name]
            if size >= 8:
                return addr, min(size // 4, _MAX_VECTORS)
    start = override[0] if override is not None else next(
        (gt.symbols_by_name[n] for n in _VECTOR_SYMBOLS if n in gt.symbols_by_name), None)
    if start is None and gt.segments:
        base = min(v for v, _ in gt.segments)
        head = gt.read_bytes(base, 8)
        if head and len(head) == 8 and (int.from_bytes(head[4:8], "little") & ~1) == gt.entry:
            start = base
    if start is None:
        return None
    entries = {f.address for f in gt.functions}
    count = 1
    while count < _MAX_VECTORS:
        word = gt.read_bytes(start + 4 * count, 4)
        if not word or len(word) < 4:
            break
        w = int.from_bytes(word, "little")
        if w != 0 and (w & ~1) not in entries:
            break
        count += 1
    return (start, count) if count > 1 else None


def vector_table_roots(gt: ElfGroundTruth, table: Optional[tuple]) -> list:
    """(label, handler_addr) for every non-null handler slot (slot 0, the
    initial SP, is skipped)."""
    if table is None:
        return []
    addr, count = table
    data = gt.read_bytes(addr, count * 4) or b""
    roots = []
    for i in range(1, min(count, len(data) // 4)):
        word = int.from_bytes(data[i * 4:i * 4 + 4], "little")
        if word == 0:
            continue
        target = word & ~1
        names = [f.name for f in gt.functions if f.address == target]
        label = names[0] if len(names) <= 1 else f"{names[0]} (+{len(names) - 1} aliases)"
        roots.append((f"vector[{i}]:{label or hex(target)}", target))
    return roots


# -- call graph -----------------------------------------------------------------------

@dataclass
class CallGraph:
    edges: dict = field(default_factory=dict)          # caller_addr -> set(callee_addr)
    roots: list = field(default_factory=list)          # list[(label, addr)]
    reset_roots: list = field(default_factory=list)    # roots excluding vector-table handlers
    address_taken: dict = field(default_factory=dict)  # func_addr -> first address that references it
    indirect_sites: dict = field(default_factory=dict) # func_addr -> list[insn_addr] of indirect calls/jumps
    vector_table: Optional[tuple] = None

    def reachable_from(self, root_addrs) -> set:
        seen = set()
        stack = list(root_addrs)
        while stack:
            a = stack.pop()
            if a in seen:
                continue
            seen.add(a)
            stack.extend(c for c in self.edges.get(a, ()) if c not in seen)
        return seen

    def reachable_from_roots(self) -> set:
        return self.reachable_from(a for _, a in self.roots)

    def reachable_from_reset(self) -> set:
        return self.reachable_from(a for _, a in self.reset_roots)


def _scan_function(gt: ElfGroundTruth, func: FunctionInfo, entries: dict, cg: CallGraph):
    size = func.size if func.size > 0 else 4096  # zero-size symbols: over-approximate
    callees = set()
    indirect = []
    movw = {}
    for lo, hi, mode in code_regions(gt, func.address, func.address + size):
        if mode not in _MD:
            continue
        data = gt.read_bytes(lo, hi - lo)
        if not data:
            continue
        for insn in _MD[mode].disasm(data, lo):
            kind = classify_branch(insn)
            if kind == DIRECT:
                tgt = branch_target(insn)
                if tgt in entries:
                    callees.add(tgt)
            elif kind in (INDIRECT_CALL, INDIRECT_JUMP):
                indirect.append(insn.address)

            iid = insn.id
            if iid == A.ARM_INS_MOVW and len(insn.operands) == 2:
                movw[insn.operands[0].reg] = insn.operands[1].imm & 0xFFFF
            elif iid == A.ARM_INS_MOVT and len(insn.operands) == 2 and insn.operands[0].reg in movw:
                value = ((insn.operands[1].imm & 0xFFFF) << 16) | movw.pop(insn.operands[0].reg)
                _note_pointer(value, insn.address, entries, cg)
            elif iid == A.ARM_INS_ADR and len(insn.operands) == 2:
                pc = (insn.address + 4) & ~3 if mode == "thumb" else insn.address + 8
                _note_pointer(pc + insn.operands[1].imm, insn.address, entries, cg)
    cg.edges[func.address] = callees
    if indirect:
        cg.indirect_sites[func.address] = indirect


def _note_pointer(value: int, where: int, entries: dict, cg: CallGraph):
    """A word that equals a function's callable address (Thumb bit set for
    Thumb functions) marks that function as address-taken."""
    target = value & ~1
    mode = entries.get(target)
    if mode is None:
        return
    if (mode == "thumb") != bool(value & 1):
        return
    cg.address_taken.setdefault(target, where)


def _scan_data_words(gt: ElfGroundTruth, entries: dict, cg: CallGraph, skip: tuple):
    """Look for function pointers in every data byte of the image: whole
    non-executable sections, and the $d (literal pool / rodata) regions
    inside executable ones. The vector table is skipped; its slots are
    roots of their own and must stay distinguishable from pointers that
    main-line code can call."""
    skip_lo, skip_hi = skip
    ranges = []
    if gt.sections:
        for addr, size, executable in gt.sections.values():
            if not executable:
                ranges.append((addr, addr + size))
            else:
                ranges.extend((lo, hi) for lo, hi, mode in code_regions(gt, addr, addr + size)
                              if mode == "data")
    else:
        ranges = [(v, v + len(d)) for v, d in gt.segments]

    for lo, hi in ranges:
        data = gt.read_bytes(lo, hi - lo)
        if not data:
            continue
        start = (lo + 3) & ~3
        for off in range(start - lo, len(data) - 3, 4):
            addr = lo + off
            if skip_lo <= addr < skip_hi:
                continue
            _note_pointer(int.from_bytes(data[off:off + 4], "little"), addr, entries, cg)


def build_callgraph(gt: ElfGroundTruth) -> CallGraph:
    cached = gt.cache.get("callgraph")
    if cached is not None:
        return cached

    cg = CallGraph()
    entries = {}
    for f in gt.functions:
        entries.setdefault(f.address, f.mode)
    for func in gt.functions:
        if func.address not in cg.edges:
            _scan_function(gt, func, entries, cg)

    cg.vector_table = find_vector_table(gt)
    skip = (cg.vector_table[0], cg.vector_table[0] + 4 * cg.vector_table[1]) if cg.vector_table else (0, 0)
    _scan_data_words(gt, entries, cg, skip)

    entry_func = gt.function_at(gt.entry)
    entry_root = (entry_func.name, entry_func.address) if entry_func else ("_entry", gt.entry)
    taken = []
    for addr, where in sorted(cg.address_taken.items()):
        f = gt.function_at(addr)
        taken.append((f"address-taken@0x{where:x}:{f.name if f else hex(addr)}", addr))
    cg.reset_roots = [entry_root] + taken
    cg.roots = cg.reset_roots + vector_table_roots(gt, cg.vector_table)

    gt.cache["callgraph"] = cg
    return cg


def idle_addresses(gt: ElfGroundTruth) -> frozenset:
    """Addresses of wfi/wfe and branch-to-self instructions: the points where
    firmware waits for an interrupt and nothing further happens without one."""
    cached = gt.cache.get("idle")
    if cached is not None:
        return cached
    idle = set()
    for func in gt.functions:
        if func.size <= 0:
            continue
        for lo, hi, mode in code_regions(gt, func.address, func.end):
            if mode not in _MD:
                continue
            for insn in _MD[mode].disasm(gt.read_bytes(lo, hi - lo) or b"", lo):
                if insn.id in (A.ARM_INS_WFI, A.ARM_INS_WFE):
                    idle.add(insn.address)
                elif insn.id == A.ARM_INS_B and insn.cc in (A.ARM_CC_AL, A.ARM_CC_INVALID) \
                        and branch_target(insn) == insn.address:
                    idle.add(insn.address)
    result = frozenset(idle)
    gt.cache["idle"] = result
    return result


# -- intra-procedural reachability ---------------------------------------------------

@dataclass
class LocalReachability:
    reached: list          # list[(insn_addr, size)] of instructions reachable from the entry
    gave_up: bool          # hit a jump table / indirect jump: the reached set is incomplete
    reason: str = ""

    def covers(self, addr: int) -> bool:
        return any(a <= addr < a + n for a, n in self.reached)


def local_reachability(gt: ElfGroundTruth, func: FunctionInfo) -> LocalReachability:
    """Recursive-descent walk from the function's entry over fall-through
    and direct branch edges, to find code inside a live function that no
    path reaches (e.g. a branch the compiler kept but nothing takes)."""
    key = ("local", func.address)
    if key in gt.cache:
        return gt.cache[key]

    end = func.end if func.size > 0 else func.address
    reached = {}
    work = [(func.address, 0)]   # (addr, remaining instructions inside an IT block)
    gave_up, reason = func.size <= 0, "function has no size" if func.size <= 0 else ""
    while work and not gave_up:
        addr, it_left = work.pop()
        if addr in reached or not (func.address <= addr < end):
            continue
        insn = decode_one(gt, addr)
        if insn is None:
            continue
        reached[addr] = insn.size
        nxt = addr + insn.size
        conditional = it_left > 0 or insn.cc not in (A.ARM_CC_AL, A.ARM_CC_INVALID)
        next_it = _it_length(insn) or max(it_left - 1, 0)

        kind = classify_branch(insn)
        if kind in (INDIRECT_JUMP, JUMP_TABLE):
            gave_up, reason = True, f"{insn.mnemonic} {insn.op_str} at 0x{addr:x}"
            break
        if kind == DIRECT and not is_call(insn):
            tgt = branch_target(insn)
            if tgt is not None:
                work.append((tgt, 0))
            if conditional or insn.id in (A.ARM_INS_CBZ, A.ARM_INS_CBNZ):
                work.append((nxt, next_it))
            continue
        if kind == RETURN and not conditional:
            continue
        work.append((nxt, next_it))

    result = LocalReachability(reached=sorted(reached.items()), gave_up=gave_up, reason=reason)
    gt.cache[key] = result
    return result
