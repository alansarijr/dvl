"""
Static reachability oracle: the pre-emulation triage filter.

A finding is refuted (FP) only when its code cannot run:
  - its function has no path from any root in dvl.callgraph (reset
    handler, every vector-table slot, every address-taken function), or
  - its function is live, but no path inside the function reaches the
    flagged instruction.

Confidence is "high" when the binary has no indirect branches in code the
roots reach, and "medium" otherwise, because a target computed at runtime
could escape the address-taken scan.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .callgraph import CallGraph, build_callgraph, local_reachability
from .elfinfo import ElfGroundTruth
from .schema import Verdict


@dataclass
class ReachabilityResult:
    verdict: Optional[Verdict]   # Verdict.FP if unreachable; None if reachable (must proceed)
    detail: str
    confidence: str = "high"
    callgraph: Optional[CallGraph] = None
    facts: dict = field(default_factory=dict)


def _facts(cg: CallGraph, reachable: set) -> dict:
    live_indirect = {f: sites for f, sites in cg.indirect_sites.items() if f in reachable}
    return {
        "roots": [f"{label}@0x{addr:x}" for label, addr in cg.roots],
        "vector_table": (f"0x{cg.vector_table[0]:x} x{cg.vector_table[1]}" if cg.vector_table else None),
        "address_taken_functions": len(cg.address_taken),
        "indirect_branch_sites": sorted(f"0x{s:x}" for sites in live_indirect.values() for s in sites),
    }


def check(gt: ElfGroundTruth, address: int) -> ReachabilityResult:
    cg = build_callgraph(gt)
    reachable = cg.reachable_from_roots()
    facts = _facts(cg, reachable)
    confidence = "medium" if facts["indirect_branch_sites"] else "high"
    indirect_note = (
        f" {len(facts['indirect_branch_sites'])} indirect branch site(s) exist in reachable code; "
        f"their targets are assumed to be among the address-taken functions."
        if facts["indirect_branch_sites"] else " No indirect branches exist in reachable code.")

    func = gt.function_at(address)
    if func is None:
        return ReachabilityResult(
            verdict=None, callgraph=cg, facts=facts,
            detail=(f"Address 0x{address:x} does not fall inside any known function's "
                    f"boundary; reachability cannot be decided statically."))

    if func.address not in reachable:
        return ReachabilityResult(
            verdict=Verdict.FP, confidence=confidence, callgraph=cg, facts=facts,
            detail=(f"Function '{func.name}' (0x{func.address:x}) has no call-graph path from "
                    f"any of the {len(cg.roots)} entry points (reset handler, "
                    f"{len(cg.roots) - len(cg.reset_roots)} vector-table slots, "
                    f"{facts['address_taken_functions']} address-taken functions).{indirect_note}"))

    local = local_reachability(gt, func)
    if gt.mode_at(address) == "data":
        return ReachabilityResult(
            verdict=None, callgraph=cg, facts=facts,
            detail=(f"Function '{func.name}' is reachable, but 0x{address:x} lies in a data "
                    f"region ($d) inside it, not in code; the flagged address itself is suspect."))
    if not local.gave_up and not local.covers(address):
        return ReachabilityResult(
            verdict=Verdict.FP, confidence=confidence, callgraph=cg, facts=facts,
            detail=(f"Function '{func.name}' (0x{func.address:x}) is reachable, but no control-flow "
                    f"path from its entry reaches 0x{address:x}: the flagged instruction is dead "
                    f"code inside a live function.{indirect_note}"))

    note = f" (intra-function walk incomplete: {local.reason})" if local.gave_up else ""
    return ReachabilityResult(
        verdict=None, callgraph=cg, facts=facts,
        detail=(f"Function '{func.name}' (0x{func.address:x}) is reachable from the static "
                f"entry points{note}."))


def is_irq_only(gt: ElfGroundTruth, address: int) -> bool:
    """True if the flagged function is reachable only through a vector-table
    slot (interrupt/exception delivery), so a run from the reset handler
    can never reach it and emulation must be seeded at the handler."""
    func = gt.function_at(address)
    if func is None:
        return False
    cg = build_callgraph(gt)
    return func.address in cg.reachable_from_roots() and func.address not in cg.reachable_from_reset()
