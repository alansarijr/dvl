"""
CWE-121/787/125 trigger-verification oracle.

Checks the emulator's access trace against the buffers DWARF says exist,
at the addresses they actually had during the run, rather than the bound
the SAST tool guessed.

Only accesses made while the flagged function's frame is live count: by
the function itself or by a callee such as mem_copy. Accesses after it
returns, or by unrelated code, cannot be evidence about this finding.

A live access is out of bounds when either:

  1. it lands outside every live object (the gaps between variables,
     saved registers, padding, beyond the frame) and the nearest object
     below it belongs to the flagged function, one of its callers, or the
     globals. That object is the one being overflowed; or
  2. it lands inside a *different* object than the previous access from
     the same instruction, starting right where that one ended: a linear
     copy running from one buffer into its neighbour.

Register save/restore instructions (push/pop and SP-writeback stm/ldm)
are never variable accesses and are ignored; the epilogue's `pop {..., pc}`
reads the saved registers just above the locals.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from capstone import arm_const as A

from .callgraph import decode_one
from .elfinfo import ElfGroundTruth, FunctionInfo
from .emulator_cortexm import MemAccess
from .schema import Verdict

READ_CWES = {"CWE-125"}
WRITE_CWES = {"CWE-121", "CWE-787"}

@dataclass(frozen=True)
class MemObject:
    key: tuple          # (activation or 0 for globals, variable name)
    name: str
    owner: str          # function name, or "global"
    lo: int
    hi: int

    def contains(self, lo: int, hi: int) -> bool:
        return self.lo <= lo and hi <= self.hi


@dataclass
class BoundsOracleResult:
    verdict: Optional[Verdict]      # TP when a violation was observed, else None
    detail: str
    violation: Optional[MemAccess] = None
    window: Optional[tuple] = None  # (lo, hi) of the overflowed object
    objects_known: int = 0          # DWARF objects the flagged function can see
    accesses_checked: int = 0       # accesses made while the flagged function was live


def is_register_spill(gt: ElfGroundTruth, pc: int) -> bool:
    cache = gt.cache.setdefault("spill", {})
    if pc in cache:
        return cache[pc]
    insn = decode_one(gt, pc)
    spill = False
    if insn is not None:
        if insn.id in (A.ARM_INS_PUSH, A.ARM_INS_POP):
            spill = True
        elif insn.id in (A.ARM_INS_STMDB, A.ARM_INS_LDM, A.ARM_INS_STM) and insn.writeback \
                and insn.operands and insn.operands[0].reg == A.ARM_REG_SP:
            spill = True
    cache[pc] = spill
    return spill


def _frame_objects(gt: ElfGroundTruth, frame, cache: dict) -> list:
    objs = cache.get(frame.activation)
    if objs is None:
        f = gt.function_at(frame.func)
        owner = f.name if f else hex(frame.func)
        objs = [MemObject(key=(frame.activation, v.name), name=v.name, owner=owner,
                          lo=frame.cfa + v.fbreg_offset, hi=frame.cfa + v.fbreg_offset + (v.byte_size or 1))
                for v in gt.variables_by_function.get(frame.func, [])]
        cache[frame.activation] = objs
    return objs


def _describe(kind: str, acc: MemAccess, obj: MemObject, how: str, gt: ElfGroundTruth) -> str:
    lo, hi = acc.address, acc.address + acc.size
    pc_func = gt.function_at(acc.pc)
    where = f"PC=0x{acc.pc:x}" + (f" in {pc_func.name}" if pc_func else "")
    return (f"Out-of-bounds {kind} at {where}: accessed [0x{lo:x}, 0x{hi:x}) but "
            f"'{obj.name}' ({obj.owner}) is only [0x{obj.lo:x}, 0x{obj.hi:x}) "
            f"({obj.hi - obj.lo} bytes); {how}.")


def check(gt: ElfGroundTruth, cwe_id: str, func: FunctionInfo, run_result) -> BoundsOracleResult:
    """max_overrun (from the target profile) bounds how far past an
    object's end an access can land and still be attributed to it rather
    than to unrelated memory higher up."""
    profile = run_result.profile
    max_overrun = profile.max_plausible_overrun
    _region = profile.region_of
    want_write = cwe_id in WRITE_CWES
    kind = "write" if want_write else "read"
    globals_ = [MemObject(key=(0, v.name), name=v.name, owner="global",
                          lo=v.address, hi=v.address + (v.byte_size or 1))
                for v in gt.global_variables.values()]
    frame_cache: dict = {}
    last_by_pc: dict = {}   # pc -> (object, access end, activation)
    checked = 0

    for acc in run_result.accesses:
        if acc.is_write != want_write:
            continue
        own = acc.frame_of(func.address)
        if own is None:
            continue
        region = "unmapped" if acc.unmapped else _region(acc.address)
        if region is None or is_register_spill(gt, acc.pc):
            continue
        checked += 1

        # Overflow sources: the flagged function's frame, its callers'
        # (a pointer passed down), and globals. Deeper callees' locals are
        # legitimate targets but not something this finding is about.
        sources = list(globals_)
        everything = list(globals_)
        own_depth = acc.frames.index(own)
        for depth, fr in enumerate(acc.frames):
            objs = _frame_objects(gt, fr, frame_cache)
            everything.extend(objs)
            if depth <= own_depth:
                sources.extend(objs)

        lo, hi = acc.address, acc.address + acc.size
        innermost = acc.frames[-1].activation
        inside = next((o for o in everything if o.contains(lo, hi)), None)
        prev = last_by_pc.get(acc.pc)

        if inside is not None:
            if prev is not None:
                p_obj, p_end, p_act = prev
                sequential = p_end <= lo <= p_end + max(acc.size, 8)
                same_run = p_act == innermost or p_obj.owner == "global"
                if (p_obj.key != inside.key and p_obj in sources and sequential and same_run
                        and lo >= p_obj.hi and lo - p_obj.hi < max_overrun):
                    return BoundsOracleResult(
                        verdict=Verdict.TP, violation=acc, window=(p_obj.lo, p_obj.hi),
                        objects_known=len(sources), accesses_checked=checked,
                        detail=_describe(kind, acc, p_obj,
                                         f"the same instruction ran contiguously from '{p_obj.name}' "
                                         f"into '{inside.name}', {hi - p_obj.hi} bytes past its end", gt))
            last_by_pc[acc.pc] = (inside, hi, innermost)
            continue

        # An unmapped access ran off the end of a region, so any object
        # below it may be the source; otherwise stay within the region.
        below = [o for o in sources if o.lo <= lo and (acc.unmapped or _region(o.lo) == region)]
        if below:
            base = max(below, key=lambda o: o.lo)
            if hi > base.hi and lo - base.hi < max_overrun:
                fault = "; the access hit unmapped memory and faulted" if acc.unmapped else ""
                return BoundsOracleResult(
                    verdict=Verdict.TP, violation=acc, window=(base.lo, base.hi),
                    objects_known=len(sources), accesses_checked=checked,
                    detail=_describe(kind, acc, base,
                                     f"overrun = {hi - base.hi} bytes past the end{fault}", gt))
        last_by_pc.pop(acc.pc, None)

    n_objects = len(globals_) + len(gt.variables_for(func))
    return BoundsOracleResult(
        verdict=None, objects_known=n_objects, accesses_checked=checked,
        detail=(f"No out-of-bounds {kind} observed: {checked} {kind}(s) made while "
                f"'{func.name}' was live all landed inside a live object ({n_objects} "
                f"DWARF-described objects in scope)."))
