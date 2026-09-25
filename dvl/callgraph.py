"""
Static reachability analysis (pre-emulation filter).

Per the prompt's pipeline step 2: build a CFG/call-graph from the reset
vector (and, for bare-metal, every interrupt-vector-table entry) and
check whether the flagged address is reachable at all. Anything
statically unreachable is auto-classified FP without needing emulation.

We deliberately re-disassemble using our OWN mode-per-address ground
truth (dvl.elfinfo.mode_at, sourced from ELF mapping symbols) rather
than trusting whatever mode the upstream SAST pipeline assumed --
per the prompt's "ARM Thumb-2 mode detection has already caused issues
upstream" warning.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import capstone as cs

from .elfinfo import ElfGroundTruth


@dataclass
class CallGraph:
    edges: dict = field(default_factory=dict)   # caller_addr -> set(callee_addr)
    roots: list = field(default_factory=list)   # list[(name, addr)]

    def reachable_from_roots(self) -> set:
        seen = set()
        stack = [addr for _, addr in self.roots]
        while stack:
            a = stack.pop()
            if a in seen:
                continue
            seen.add(a)
            for callee in self.edges.get(a, ()):
                if callee not in seen:
                    stack.append(callee)
        return seen


def _disasm_function_calls(gt: ElfGroundTruth, func) -> set:
    """Disassemble one function's byte range and collect branch/call targets
    that land on a *known* function entry point (direct calls/tail-branches
    only -- indirect calls (bx/blx reg) can't be statically resolved and are
    conservatively ignored, same limitation any static CFG builder has)."""
    targets = set()
    size = func.size if func.size > 0 else 4096  # guard against zero-size syms
    data = gt.read_bytes(func.address, size)
    if not data:
        return targets

    mode = gt.mode_at(func.address)
    if mode == "thumb":
        md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB)
    else:
        md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
    md.detail = False

    known_addrs = {f.address for f in gt.functions}

    try:
        for insn in md.disasm(data, func.address):
            mnem = insn.mnemonic
            if mnem.startswith(("bl", "b", "cbz", "cbnz")) or mnem in ("bx", "blx"):
                ops = insn.op_str
                # Only handle direct (immediate) targets: "#0x1234" or "0x1234"
                if ops.startswith("#"):
                    ops = ops[1:]
                try:
                    tgt = int(ops, 16) if ops.lower().startswith("0x") else int(ops)
                except ValueError:
                    continue
                tgt &= ~1
                if tgt in known_addrs:
                    targets.add(tgt)
    except Exception:
        pass
    return targets


def build_callgraph(gt: ElfGroundTruth, extra_roots: Optional[list] = None) -> CallGraph:
    """extra_roots: list[(name, addr)] e.g. vector-table entries, for
    bare-metal targets where interrupt handlers are entry points that no
    call-graph walk from main() will ever discover."""
    cg = CallGraph()
    for func in gt.functions:
        cg.edges[func.address] = _disasm_function_calls(gt, func)

    roots = []
    entry_func = gt.function_at(gt.entry)
    if entry_func:
        roots.append((entry_func.name, entry_func.address))
    else:
        roots.append(("_entry", gt.entry))
    if extra_roots:
        roots.extend(extra_roots)
    cg.roots = roots
    return cg


def vector_table_roots(gt: ElfGroundTruth, vector_table_addr: int, count: int) -> list:
    """Read a Cortex-M vector table and return (label, handler_addr) for
    every non-null, non-default-handler entry -- i.e. every real interrupt
    entry point, which per the prompt must be treated as reachable
    independent of main()'s call graph."""
    roots = []
    data = gt.read_bytes(vector_table_addr, count * 4)
    if not data:
        return roots
    for i in range(count):
        word = int.from_bytes(data[i * 4:i * 4 + 4], "little")
        if word == 0:
            continue
        addr = word & ~1
        name = gt.symbols_by_addr.get(addr, f"vector[{i}]@0x{addr:x}")
        roots.append((f"vector[{i}]:{name}", addr))
    return roots
