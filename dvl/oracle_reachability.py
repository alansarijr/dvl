"""
Static reachability oracle (prompt pipeline step 2 -- the pre-emulation
fast-triage filter).

"use angr to build a CFG from the reset vector and check whether the
flagged address is reachable at all from any entry point (interrupt
handlers included). Anything statically unreachable gets auto-classified
FP without needing emulation -- saves cycles."

We use our own capstone-based call-graph builder (dvl.callgraph) rather
than angr (not installed in this environment; capstone-only static CFG
recovery is a reasonable substitute for direct-call-edge reachability,
which is all these fixtures require -- indirect calls are conservatively
treated as "can't statically resolve", never as "definitely unreachable").

Roots always include:
  - the reset vector / ELF entry point
  - EVERY vector-table slot (NMI, HardFault, ..., IRQ0..IRQ7) --
    per the prompt's explicit callout, and fixture 05's whole point:
    a handler with no incoming call edge from main() can still be very
    reachable via hardware interrupt delivery.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .elfinfo import ElfGroundTruth
from .callgraph import build_callgraph, vector_table_roots, CallGraph
from .schema import Verdict


@dataclass
class ReachabilityResult:
    verdict: Optional[Verdict]   # Verdict.FP if unreachable; None if reachable (must proceed)
    detail: str
    callgraph: Optional[CallGraph] = None


def check(gt: ElfGroundTruth, address: int,
          vector_table_addr: int = 4, vector_count: int = 23) -> ReachabilityResult:
    """
    vector_table_addr/vector_count default to skipping isr_vector[0]
    (the initial SP value, not a code address) and covering
    Reset_Handler + every exception/IRQ slot (isr_vector[1..23]) --
    matching fixtures/baremetal/common/startup.s's 24-word table.
    """
    cg = build_callgraph(gt, extra_roots=vector_table_roots(gt, vector_table_addr, vector_count))
    reachable = cg.reachable_from_roots()

    func = gt.function_at(address)
    if func is None:
        return ReachabilityResult(
            verdict=None,
            detail=(f"Address 0x{address:x} does not fall inside any known function's "
                     f"boundary -- cannot resolve a reachability verdict statically; "
                     f"proceeding to emulation for a direct answer."),
            callgraph=cg,
        )

    if func.address in reachable:
        return ReachabilityResult(
            verdict=None,
            detail=(f"Function '{func.name}' (0x{func.address:x}) IS reachable from the "
                     f"reset vector / vector-table roots via the static call graph."),
            callgraph=cg,
        )

    root_names = ", ".join(name for name, _ in cg.roots)
    return ReachabilityResult(
        verdict=Verdict.FP,
        detail=(f"Function '{func.name}' (0x{func.address:x}) has NO call-graph path from "
                 f"any of the {len(cg.roots)} static entry points considered "
                 f"({root_names}). Statically unreachable -- classified FP without "
                 f"needing emulation, per the pipeline's fast-triage design."),
        callgraph=cg,
    )


def is_irq_only(gt: ElfGroundTruth, address: int,
                 vector_table_addr: int = 4, vector_count: int = 23) -> bool:
    """True if the flagged address is reachable ONLY via a vector-table
    root (interrupt/exception delivery) and has NO path from the reset
    vector's own call graph -- i.e. a handler that main()'s code never
    calls directly, fixture 05's whole scenario. Used by pipeline.py to
    pick a driving strategy: a plain reset-vector run will never reach
    an IRQ-only handler, no matter how long it's allowed to execute, so
    it must instead be seeded directly at the handler's own entry point."""
    func = gt.function_at(address)
    if func is None:
        return False

    main_only_cg = build_callgraph(gt)
    if func.address in main_only_cg.reachable_from_roots():
        return False

    full_cg = build_callgraph(gt, extra_roots=vector_table_roots(gt, vector_table_addr, vector_count))
    return func.address in full_cg.reachable_from_roots()

