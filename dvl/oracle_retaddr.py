"""
CWE-121/787 oracle that needs no debug info: return-address integrity.

Every function that calls others saves LR in its prologue (push {..., lr}).
The harness records where each activation saved it. A stack buffer
overflow that runs upward past a frame's locals overwrites that slot on its
way, so a write to a live saved-LR slot by anything other than a register
save/restore instruction is a stack smash, whatever the buffer was called
and whether or not DWARF exists.

A second, later symptom is also accepted: the run faulting on an
instruction fetch from an address built out of input bytes, i.e. a return
through a smashed LR.

This oracle can confirm but not clear a finding: a small overflow can
stop short of the saved registers, so "LR intact" is not proof of safety.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .elfinfo import ElfGroundTruth, FunctionInfo
from .emulator_cortexm import MemAccess
from .oracle_bounds import is_register_spill
from .schema import Verdict


@dataclass
class RetAddrResult:
    verdict: Optional[Verdict]      # TP when the saved return address was smashed, else None
    detail: str
    violation: Optional[MemAccess] = None
    frames_tracked: int = 0         # activations of the flagged function (or its callers) with a known LR slot


def check(gt: ElfGroundTruth, func: FunctionInfo, run_result, input_bytes: bytes = b"") -> RetAddrResult:
    slots = run_result.saved_lr_slots
    tracked = set()
    for acc in run_result.accesses:
        if not acc.is_write:
            continue
        own = acc.frame_of(func.address)
        if own is None:
            continue
        lo, hi = acc.address, acc.address + acc.size
        for fr in acc.frames[:acc.frames.index(own) + 1]:
            slot = slots.get(fr.activation)
            if slot is None:
                continue
            tracked.add(fr.activation)
            if lo < slot + 4 and slot < hi and not is_register_spill(gt, acc.pc):
                owner = gt.function_at(fr.func)
                pc_func = gt.function_at(acc.pc)
                return RetAddrResult(
                    verdict=Verdict.TP, violation=acc, frames_tracked=len(tracked),
                    detail=(f"Stack smash at PC=0x{acc.pc:x}"
                            f"{' in ' + pc_func.name if pc_func else ''}: wrote [0x{lo:x}, 0x{hi:x}) "
                            f"over the return address that "
                            f"'{owner.name if owner else hex(fr.func)}' saved at 0x{slot:x} "
                            f"(value 0x{acc.value or 0:x}, was 0x{fr.lr:x}) while its frame was live."))

    target = run_result.fault_target
    if target is not None and input_bytes and run_result.stopped_reason == "fault":
        word = (target | 1).to_bytes(4, "little")
        if all(b in input_bytes for b in word[1:]) and (word[0] | 1) in {b | 1 for b in input_bytes}:
            return RetAddrResult(
                verdict=Verdict.TP, frames_tracked=len(tracked),
                detail=(f"Control-flow hijack: execution faulted fetching from 0x{target:x}, an "
                        f"address made of input bytes, after '{func.name}' ran "
                        f"({run_result.fault_detail})."))

    return RetAddrResult(
        verdict=None, frames_tracked=len(tracked),
        detail=(f"No write to a saved return address while '{func.name}' was live "
                f"({len(tracked)} frame(s) with a known LR slot)."))
