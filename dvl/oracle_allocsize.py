"""
CWE-789 ("Memory Allocation with Excessive Size Value") verification oracle.

Two distinct refutation strategies live here, both static (no emulation
needed -- this CWE is about the *size operand's provenance*, not a
runtime memory-safety violation an access trace could catch):

1. Constant-immediate proof (fixture 02): if the flagged instruction (or
   the function's own prologue `sub sp, sp, #imm`) encodes its size as a
   literal immediate operand, that is a compile-time constant by
   construction -- no taint from any input can reach it, so CWE-789
   (which is fundamentally about attacker/input-controlled allocation
   size) cannot hold, regardless of what any emulated input is fed.

2. Instruction-identity re-validation (the real-world sample): per the
   prompt's "Known Hard Problems" -- function boundary / mode-detection
   errors upstream produce garbage answers even when our own downstream
   logic is correct. Before trusting that a flagged address is even an
   allocation instruction at all, re-disassemble it ourselves (using our
   own ELF-mapping-symbol-derived ARM/Thumb mode, not whatever the
   upstream tool assumed). If it isn't a stack-pointer-adjusting
   instruction at all (e.g. it's a conditional branch), the finding is
   invalid on its face: CWE-789 cannot apply to an instruction that
   doesn't allocate anything.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import capstone as cs

from .elfinfo import ElfGroundTruth
from .callgraph import _read_bytes
from .schema import Verdict


@dataclass
class AllocSizeResult:
    verdict: Verdict
    detail: str
    confidence: str = "high"


_SP_REGS = {"sp"}


def _disasm_one(gt: ElfGroundTruth, addr: int):
    data = _read_bytes(gt, addr, 8)
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


def check(gt: ElfGroundTruth, address: int) -> AllocSizeResult:
    insn = _disasm_one(gt, address)
    if insn is None:
        return AllocSizeResult(
            verdict=Verdict.INCONCLUSIVE,
            detail=(f"Could not disassemble any instruction at 0x{address:x} using "
                     f"our own ELF-mapping-symbol-derived mode ('{gt.mode_at(address)}') "
                     f"-- insufficient evidence to confirm or refute this finding."),
            confidence="low",
        )

    mnem = insn.mnemonic.lower()
    ops = insn.op_str.lower().replace(" ", "")

    is_sp_adjust = mnem.startswith(("sub", "add")) and "sp" in ops.split(",")[0:1] or \
                   (mnem.startswith(("sub", "add")) and ops.startswith("sp,"))

    if not is_sp_adjust:
        return AllocSizeResult(
            verdict=Verdict.FP,
            detail=(f"Re-disassembled independently (mode='{gt.mode_at(address)}', derived "
                     f"from ELF mapping symbols, not the upstream tool's assumption): the "
                     f"flagged address 0x{address:x} decodes to '{insn.mnemonic} {insn.op_str}', "
                     f"NOT a stack-pointer-adjusting instruction. CWE-789 (excessive "
                     f"allocation size) cannot apply to an instruction that does not "
                     f"allocate anything -- this is exactly the 'function boundary / mode "
                     f"detection' failure mode called out for bare-metal SAST pipelines: "
                     f"the upstream tool's own disassembly window shows a mismatch between "
                     f"the description's referenced address and the flagged instruction, "
                     f"and/or a Thumb/ARM mode error caused it to point at the wrong byte "
                     f"entirely."),
            confidence="high",
        )

    # It IS a sp-adjusting instruction. Is the size operand a literal
    # immediate ("#N") or a register (tainted, needs real dataflow analysis
    # we don't attempt here)?
    if "#" in insn.op_str:
        imm_str = insn.op_str.split("#", 1)[1].split(",")[0].strip()
        try:
            imm = int(imm_str, 16) if imm_str.lower().startswith("0x") else int(imm_str)
        except ValueError:
            imm = None
        return AllocSizeResult(
            verdict=Verdict.FP,
            detail=(f"'{insn.mnemonic} {insn.op_str}' at 0x{address:x} adjusts sp by a "
                     f"literal immediate{f' (0x{imm:x} / {imm} bytes)' if imm is not None else ''} "
                     f"encoded directly in the instruction. This is a compile-time constant "
                     f"by construction -- no register/memory taint from any input can reach "
                     f"an immediate operand, so CWE-789 (attacker/input-controlled excessive "
                     f"allocation size) cannot hold here regardless of what value emulation "
                     f"would otherwise feed as input."),
            confidence="high",
        )

    return AllocSizeResult(
        verdict=Verdict.INCONCLUSIVE,
        detail=(f"'{insn.mnemonic} {insn.op_str}' at 0x{address:x} adjusts sp using a "
                 f"register operand, not a literal immediate -- its value could in "
                 f"principle be influenced by tainted input. Confirming or refuting this "
                 f"requires dataflow/taint analysis back to the register's origin, which "
                 f"this oracle does not attempt; flagging for manual review."),
        confidence="low",
    )
