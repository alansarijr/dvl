"""
CWE-789 ("Memory Allocation with Excessive Size Value") oracle, static.

cwe_checker raises CWE-789 for a stack allocation whose size exceeds a
threshold (7500 bytes by default), so the question for a flagged
`sub sp, sp, #N` is simply whether N exceeds that threshold:

  - N above the threshold: TP (medium). The allocation the finding
    describes is really there; whether it exhausts the stack depends on
    how much stack the target has, which is noted when known.
  - N at or below it: FP (high). The upstream tool mis-sized or
    mis-decoded the instruction.
  - a register-sized allocation: Inconclusive (needs taint analysis).
  - not a stack allocation at all: Inconclusive. The flagged address is
    probably wrong (e.g. decoded in the wrong ARM/Thumb mode upstream),
    which says nothing about whether a real allocation nearby is too big.

The instruction is re-disassembled here in the mode the ELF's mapping
symbols give, not the mode the upstream tool assumed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import capstone as cs

from .elfinfo import ElfGroundTruth
from .schema import Verdict


@dataclass
class AllocSizeResult:
    verdict: Verdict
    detail: str
    confidence: str = "high"



def _disasm_one(gt: ElfGroundTruth, addr: int):
    data = gt.read_bytes(addr, 8)
    if not data:
        return None
    mode = gt.mode_at(addr)
    md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB if mode == "thumb" else cs.CS_MODE_ARM)
    md.detail = False
    try:
        for insn in md.disasm(data, addr):
            return insn
    except Exception:
        return None
    return None


def check(gt: ElfGroundTruth, address: int, stack_threshold: int,
          stack_size: Optional[int] = None) -> AllocSizeResult:
    mode = gt.mode_at(address)
    insn = _disasm_one(gt, address)
    if insn is None:
        return AllocSizeResult(
            verdict=Verdict.INCONCLUSIVE, confidence="low",
            detail=(f"Could not disassemble an instruction at 0x{address:x} in mode '{mode}' "
                    f"(from the ELF's mapping symbols)."))

    text = f"{insn.mnemonic} {insn.op_str}"
    ops = [o.strip() for o in insn.op_str.lower().split(",")]
    is_alloc = insn.mnemonic.lower().startswith("sub") and ops[:1] == ["sp"]
    if not is_alloc:
        return AllocSizeResult(
            verdict=Verdict.INCONCLUSIVE, confidence="low",
            detail=(f"Re-disassembled in mode '{mode}' (from the ELF's mapping symbols), 0x{address:x} "
                    f"is '{text}', not a stack allocation. The upstream address or ARM/Thumb mode is "
                    f"likely wrong, which neither confirms nor refutes an excessive allocation nearby."))

    imm = None
    if "#" in insn.op_str:
        try:
            imm = int(insn.op_str.split("#", 1)[1].split(",")[0].strip(), 0)
        except ValueError:
            imm = None
    if imm is None:
        return AllocSizeResult(
            verdict=Verdict.INCONCLUSIVE, confidence="low",
            detail=(f"'{text}' at 0x{address:x} sizes the stack allocation from a register; "
                    f"confirming or refuting needs dataflow/taint analysis back to its origin."))

    stack_note = (f" The target has at most {stack_size} bytes of RAM for its stack." if stack_size else "")
    if imm > stack_threshold:
        return AllocSizeResult(
            verdict=Verdict.TP, confidence="medium",
            detail=(f"'{text}' at 0x{address:x} allocates {imm} bytes of stack in one step, above "
                    f"the {stack_threshold}-byte threshold.{stack_note}"))
    return AllocSizeResult(
        verdict=Verdict.FP, confidence="high",
        detail=(f"'{text}' at 0x{address:x} allocates a constant {imm} bytes of stack, at or below "
                f"the {stack_threshold}-byte threshold (mode '{mode}', from the ELF's mapping "
                f"symbols).{stack_note}"))
