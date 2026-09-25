"""
Symbolic path-driving fallback.

The generic concrete driver (a fixed UART payload) can never reach code
behind a check for a specific value, e.g. `if (cmd[0] == 0xA5)`. When the
flagged instruction never executed, this module uses angr to solve for a
UART byte prefix and r0-r3 arguments that reach it from the flagged
function's entry. The caller replays the result in the Unicorn harness
and runs the usual oracles on that trace; angr only produces the input.

Not used for IRQ-only findings: repeated interrupt delivery does not map
onto one continuous symbolic run.

Keeping the search small: the UART status register is concrete and only
the first few data-register bytes are symbolic. The UART model matches
what the replay will see: RXNE is set while bytes remain in
`prefix + filler + '\n'`, the filler is 'A', and nothing arrives after
that. UART state lives in state.globals so each branch counts its own
reads. Registers other than r0-r3, and memory, are zero-filled like the
harness's fresh RAM.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

from .elfinfo import ElfGroundTruth
from .emulator_cortexm import SEED_STACK_HEADROOM
from .target import TargetProfile

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
    args: tuple = (0, 0, 0, 0)     # solved r0-r3 at the function's entry


def _fault_avoid_addrs(gt: ElfGroundTruth) -> set:
    addrs = set()
    for name in _FAULT_HANDLER_NAMES:
        f = gt.function_by_name(name)
        if f is not None:
            addrs.add(f.address)
    return addrs


def solve_driving_input(gt: ElfGroundTruth, profile: TargetProfile, root_addr: int, target_addr: int,
                         extra_avoid_addrs: Optional[set] = None,
                         prefix_bytes: int = 4,
                         suffix_bytes: int = 32,
                         step_budget: int = 400,
                         time_budget_s: float = 20.0) -> Optional[PathSolveResult]:
    """Symbolically solve for the first `prefix_bytes` UART bytes (and the
    r0-r3 arguments) that drive execution from root_addr to target_addr at
    least once, and return them followed by a 'A'-filled, newline-terminated
    tail of `suffix_bytes`.

    Only reaching the target is solved for; the first pass through a copy
    loop is usually still in bounds, so proving the overflow is left to the
    caller replaying these bytes through the Unicorn harness.

    Returns None if angr is unavailable, the budget runs out, or no path
    exists."""
    try:
        import angr
        import claripy
    except ImportError:
        return None
    for noisy in ("angr", "cle", "pyvex", "claripy"):
        logging.getLogger(noisy).setLevel(logging.ERROR)

    try:
        project = gt.cache.get("angr_project")
        if project is None:
            project = angr.Project(gt.path, main_opts={"backend": "elf"}, auto_load_libs=False)
            gt.cache["angr_project"] = project
    except Exception:
        return None

    uart = profile.uart
    sr_addr = uart.status_addr if uart else None
    dr_addr = uart.data_addr if uart else None
    stream_len = prefix_bytes + suffix_bytes + 1   # prefix + filler + '\n'

    def mem_read_hook(state):
        attrs = state.inspect.attrs
        addr = attrs.mem_read_address
        if addr is None or addr.symbolic:
            return
        addr_c = state.solver.eval(addr)
        width = attrs.mem_read_length * 8
        n = state.globals.get("uart_n", 0)

        if addr_c == sr_addr:
            rxne = uart.rxne if n < stream_len else 0
            attrs.mem_read_expr = claripy.BVV(uart.txe | rxne, width)
        elif addr_c == dr_addr:
            if n >= stream_len:
                attrs.mem_read_expr = claripy.BVV(0, width)
                return
            state.globals["uart_n"] = n + 1
            if n < prefix_bytes:
                sym = claripy.BVS(f"uart_rx_{n}", 8)
                state.globals["uart_syms"] = state.globals.get("uart_syms", ()) + (sym,)
                value = sym
            else:
                value = claripy.BVV(ord("A") if n < stream_len - 1 else ord("\n"), 8)
            attrs.mem_read_expr = claripy.ZeroExt(width - 8, value) if width > 8 else value

    try:
        state = project.factory.blank_state(
            addr=root_addr | 1,
            add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                         angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        args = tuple(claripy.BVS(f"arg{i}", 32) for i in range(4))
        state.regs.r0, state.regs.r1, state.regs.r2, state.regs.r3 = args
        state.regs.sp = profile.stack_top - SEED_STACK_HEADROOM   # as the Unicorn replay seeds it
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
        syms = found.globals.get("uart_syms", ())
        solved_prefix = bytes(found.solver.eval(sym) for sym in syms)
        solved_args = tuple(found.solver.eval(a) for a in args)
    except Exception:
        return None

    # Pad the prefix to its full width so the replayed stream lines up with
    # the one angr reasoned about.
    solved_prefix = solved_prefix + b"A" * (prefix_bytes - len(solved_prefix))
    uart_bytes = solved_prefix + (b"A" * suffix_bytes) + b"\n"

    return PathSolveResult(
        uart_bytes=uart_bytes,
        args=solved_args,
        detail=(f"angr solved a {len(syms)}-byte UART prefix ({solved_prefix[:len(syms)]!r}) "
                f"and arguments r0-r3=({', '.join(hex(a) for a in solved_args)}) that drive "
                f"execution from 0x{root_addr:x} to 0x{target_addr:x} (reached in {steps} "
                f"block-steps). A {suffix_bytes}-byte 'A' tail and a newline follow, so the "
                f"replayed run can go past the first, in-bounds pass through the flagged "
                f"instruction."),
        steps_used=steps,
    )
