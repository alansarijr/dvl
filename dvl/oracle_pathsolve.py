"""
Symbolic path-driving fallback (prompt pipeline step 4, "solve for
register/memory state at the finding's entry point").

`pipeline.py`'s generic concrete driver (a fixed-pattern UART payload)
covers every *currently known* fixture shape, but by construction it can
never reach a finding gated behind a *specific* input value (e.g.
`if (cmd[0] == 0xA5) ...`) -- no amount of padding satisfies an equality
check the driver doesn't know about. This module is invoked ONLY as a
second-chance fallback when that concrete driver's result comes back
Inconclusive: it uses angr to symbolically solve for a concrete UART byte
sequence that reaches the flagged address, then hands that solved input
back to the caller so it can be replayed through the same
`emulator_cortexm.CortexM3Harness` + `oracle_bounds` used everywhere else
in this pipeline. angr never performs the trigger-verification step
itself -- it only synthesizes an input. This keeps the actual
memory-safety verdict resting on the same proven concrete Unicorn trace
as every other finding.

Deliberately scoped to reset-vector-rooted (non-IRQ) findings only. The
IRQ-only driving strategy (repeated ISR re-entry, one queued byte per
simulated interrupt) doesn't map onto a single continuous symbolic run in
any straightforward way, and none of the hard problems this MVP targets
need it -- see pipeline.py's is_irq_only() branch, which never calls
into this module.

Anti-explosion design (the same failure mode the Unicorn harness's
poll-breaker exists to avoid, per the prompt's "Known Hard Problems" on
MMIO stubbing): the UART status register (SR) is modeled CONCRETELY,
using the identical read-count-threshold poll-break rule as
dvl.mmio.MmioModel -- so control-flow forking stays bounded exactly like
the concrete harness. Only the UART data register (DR) -- the actual
attacker-controlled bytes -- is left symbolic, which is the only place
a magic-value gate could actually live.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from .elfinfo import ElfGroundTruth
from .mmio import (
    PERIPH_BASE, UART0_SR, UART0_DR, UART_SR_TXE, UART_SR_RXNE,
    GENERIC_POLL_BREAK_THRESHOLD,
)

LR_SENTINEL = 0xFFFFFFFE

_FAULT_HANDLER_NAMES = (
    "HardFault_Handler", "NMI_Handler", "MemManage_Handler",
    "BusFault_Handler", "UsageFault_Handler", "Default_Handler",
)


@dataclass
class PathSolveResult:
    uart_bytes: bytes
    detail: str
    steps_used: int = 0


def _fault_avoid_addrs(gt: ElfGroundTruth) -> set:
    addrs = set()
    for name in _FAULT_HANDLER_NAMES:
        f = gt.function_by_name(name)
        if f is not None:
            addrs.add(f.address)
    return addrs


def solve_driving_input(gt: ElfGroundTruth, root_addr: int, target_addr: int,
                         extra_avoid_addrs: Optional[set] = None,
                         prefix_bytes: int = 4,
                         suffix_bytes: int = 32,
                         step_budget: int = 400,
                         time_budget_s: float = 20.0) -> Optional[PathSolveResult]:
    """Symbolically solve for the first `prefix_bytes` UART bytes that
    drive execution from root_addr to target_addr AT LEAST ONCE, then
    append a generic `suffix_bytes`-long 'A'-filled, newline-terminated
    tail -- identical in spirit to pipeline.py's own GENERIC_RESET_PAYLOAD
    -- and return the concatenation.

    Deliberately NOT solving for the whole run: reaching target_addr once
    only proves the code path is reachable (e.g. got past a magic-value
    gate), not that a loop-driven overflow actually happened -- the first
    pass through a vulnerable copy loop is typically still in-bounds.
    Proving the overflow itself is left to the caller replaying the
    returned bytes through the real Unicorn harness + oracle_bounds,
    exactly as it does for the generic driver. Only the small solved
    prefix is left symbolic during the angr run; every later UART read
    resolves to a concrete filler byte so control flow can't keep
    forking once the gate has been satisfied -- that bound is what keeps
    this from hitting the same explosion risk as a fully symbolic MMIO
    model.

    Returns None if angr is unavailable, the exploration budget is
    exhausted, or no satisfying path exists -- all three fail closed to
    "no solved input", never an exception the caller has to handle
    specially."""
    try:
        import angr
        import claripy
    except ImportError:
        return None

    try:
        project = angr.Project(gt.path, main_opts={"backend": "elf"},
                                auto_load_libs=False)
    except Exception:
        return None

    sr_read_counts: dict = {}
    uart_syms: list = []
    uart0_sr_abs = PERIPH_BASE + UART0_SR
    uart0_dr_abs = PERIPH_BASE + UART0_DR

    def mem_read_hook(state):
        addr = state.inspect.mem_read_address
        if addr is None or addr.symbolic:
            return
        addr_c = state.solver.eval(addr)
        width = state.inspect.mem_read_length * 8

        if addr_c == uart0_sr_abs:
            pc = state.solver.eval(state.regs.pc)
            cnt = sr_read_counts.get(pc, 0) + 1
            sr_read_counts[pc] = cnt
            rxne = UART_SR_RXNE if cnt >= GENERIC_POLL_BREAK_THRESHOLD else 0
            state.inspect.mem_read_expr = claripy.BVV(UART_SR_TXE | rxne, width)
        elif addr_c == uart0_dr_abs:
            if len(uart_syms) >= prefix_bytes:
                # Beyond the solved prefix: deterministic filler, so
                # nothing downstream keeps branching on data values.
                state.inspect.mem_read_expr = claripy.BVV(ord("A"), width)
                return
            sym = claripy.BVS(f"uart_rx_{len(uart_syms)}", 8)
            uart_syms.append(sym)
            state.inspect.mem_read_expr = (
                claripy.ZeroExt(width - 8, sym) if width > 8 else sym
            )

    try:
        state = project.factory.blank_state(addr=root_addr | 1)
        state.regs.sp = 0x20000000 + 0x00010000 - 0x400
        state.regs.lr = LR_SENTINEL
        state.inspect.b("mem_read", when=angr.BP_AFTER, action=mem_read_hook)

        avoid = {a | 1 for a in (_fault_avoid_addrs(gt) | (extra_avoid_addrs or set()))}
        find_addr = target_addr | 1

        simgr = project.factory.simgr(state)
        simgr.use_technique(
            angr.exploration_techniques.Explorer(find={find_addr}, avoid=avoid, num_find=1)
        )

        deadline = time.monotonic() + time_budget_s
        steps = 0
        while not simgr.found and simgr.active and steps < step_budget:
            if time.monotonic() > deadline:
                break
            simgr.step()
            steps += 1

        if not simgr.found:
            return None

        found = simgr.found[0]
        solved_prefix = bytes(found.solver.eval(sym) for sym in uart_syms)
    except Exception:
        return None

    uart_bytes = solved_prefix + (b"A" * suffix_bytes) + b"\n"

    return PathSolveResult(
        uart_bytes=uart_bytes,
        detail=(f"angr symbolically solved a {len(solved_prefix)}-byte UART prefix "
                f"({solved_prefix!r}) driving execution from 0x{root_addr:x} to "
                f"0x{target_addr:x} at least once (reached in {steps} block-steps; "
                f"UART status register kept concrete via the same poll-break rule "
                f"as the Unicorn harness). A generic {suffix_bytes}-byte 'A'-filled, "
                f"newline-terminated tail was appended after the solved prefix "
                f"(same pattern as the generic driver) so the replayed run can "
                f"actually drive a loop-based overflow past the first, in-bounds "
                f"pass through the flagged instruction."),
        steps_used=steps,
    )
