"""
Unicorn-based Cortex-M3 bare-metal emulation harness.

Runs firmware from the reset handler (or seeded at a function or
interrupt handler), feeds UART input through dvl.mmio, and records every
memory access together with the call stack that was live when it
happened. The CWE oracles work from that trace.

The shadow call stack is what lets an oracle ask "was this function's
frame still live when that byte was written?". A frame is pushed when
execution reaches a function entry (its CFA is the SP at that moment,
which is exactly DWARF's DW_OP_call_frame_cfa) and popped once execution
reaches its return address with SP back at or above the CFA.
"""
from __future__ import annotations

import itertools
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UcError
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
)
from unicorn.unicorn_const import (
    UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UC_MEM_WRITE,
    UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UC_MEM_WRITE_UNMAPPED,
)

from . import target
from .callgraph import RETURN, classify_branch, decode_one, idle_addresses
from .elfinfo import ElfGroundTruth
from .mmio import MmioModel, install as mmio_install

SEED_STACK_HEADROOM = 0x400  # below the stack top, for runs seeded at a function

LR_SENTINEL = 0xFFFFFFFE     # unmapped; landing here on return = "function returned"
EXCEPTION_FRAME_BYTES = 32   # r0-r3, r12, lr, pc, xpsr stacked by hardware on exception entry
SAVED_LR_SEARCH_BYTES = 64   # push {r4-r11, lr} is the widest prologue save
MAX_HIJACK_RECOVERIES = 16
GUARD_BYTES = 0x10000        # mapped above RAM so an overflow off its end is recorded, not fatal
_CALLEE_SAVED = (UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                 UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11)
_SNAPSHOT_REGS = (("r0", UC_ARM_REG_R0), ("r1", UC_ARM_REG_R1), ("r2", UC_ARM_REG_R2),
                  ("r3", UC_ARM_REG_R3)) + tuple((f"r{i + 4}", r) for i, r in enumerate(_CALLEE_SAVED)) + (
                  ("sp", UC_ARM_REG_SP), ("lr", UC_ARM_REG_LR))


@dataclass(frozen=True)
class Frame:
    func: int          # function entry address
    activation: int    # unique per call
    cfa: int           # SP at entry == DWARF CFA
    ret: int           # return address (LR at entry, Thumb bit cleared)
    lr: int = 0        # raw LR at entry, as the prologue will push it
    callee_saved: tuple = ()   # r4-r11 at entry, restored if a smashed return is recovered


@dataclass
class MemAccess:
    pc: int
    address: int
    size: int
    is_write: bool
    value: Optional[int] = None
    frames: tuple = ()      # live Frame stack at access time, outermost first
    unmapped: bool = False  # the access hit no mapped memory (the run faulted on it)

    def frame_of(self, func_addr: int) -> Optional[Frame]:
        """Innermost live activation of func_addr, if any."""
        for f in reversed(self.frames):
            if f.func == func_addr:
                return f
        return None


@dataclass
class RunResult:
    stopped_reason: str          # "sim_exit" | "returned" | "idle" | "input_exhausted" | "fault" | "budget_exceeded"
    fault_detail: Optional[str] = None
    fault_pc: Optional[int] = None
    instructions_executed: int = 0   # this run only
    mmio: Optional[MmioModel] = None
    accesses: list = field(default_factory=list)          # list[MemAccess], cumulative across runs
    watch_hits: dict = field(default_factory=dict)        # watched addr -> times executed
    saved_lr_slots: dict = field(default_factory=dict)    # activation -> address its prologue pushed LR to
    profile: Optional[target.TargetProfile] = None
    fault_target: Optional[int] = None                    # PC value execution faulted trying to fetch
    recoveries: list = field(default_factory=list)        # smashed returns the harness repaired to keep going
    exit_code: Optional[int] = None

    @property
    def input_consumed(self) -> int:
        return self.mmio.rx_pos if self.mmio else 0

    @property
    def deterministic(self) -> bool:
        """The run read no input and ran to a natural end, so it is the
        program's only possible behavior: code it never executed cannot
        execute under any input this harness can supply."""
        return (self.stopped_reason in ("sim_exit", "returned", "idle")
                and self.input_consumed == 0 and not self.recoveries
                and not (self.mmio and self.mmio.poll_break_log))


class CortexM3Harness:
    """One instance per verification attempt. run_from() may be called
    repeatedly on the same instance (reset, then one call per simulated
    interrupt); RAM and the access log persist across calls."""

    def __init__(self, gt: ElfGroundTruth, profile: Optional[target.TargetProfile] = None,
                 snapshot_at: Optional[int] = None):
        """snapshot_at: index into the access log; when that access happens,
        the registers are captured into self.snapshot (used to replay a run
        up to its violating access)."""
        self.gt = gt
        self.profile = profile if profile is not None and profile.resolved else target.resolve(gt, profile)
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.mmio = MmioModel.for_profile(self.profile)
        self._guard: tuple = (0, 0)
        self._setup_memory()
        mmio_install(self.uc, self.mmio, self.profile)
        self._instr_count = 0
        self._max_instructions = self.profile.instruction_budget
        self._accesses: list = []
        self._monitor_ranges: list = []     # list[(lo,hi)] restrict access-trace collection (perf)
        self._stop_reason = None
        self._fault_detail = None
        self._func_entries = {f.address for f in gt.functions}
        self._idle = idle_addresses(gt)
        self._stop_at_idle = False
        self._watch: set = set()
        self._watch_hits: Counter = Counter()
        self._pc = 0
        self._stack: list = []
        self._live: tuple = ()
        self._rets: Counter = Counter()
        self._activations = itertools.count(1)
        self._lr_slots: dict = {}
        self._snapshot_at = snapshot_at
        self.snapshot: Optional[dict] = None
        self._recoveries: list = []
        # Registered once per instance: registering per run_from() call would
        # stack duplicate callbacks and multiply-count every access.
        self.uc.hook_add(UC_HOOK_CODE, self._code_hook)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._mem_hook)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._mem_hook)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self._unmapped_hook)

    def _setup_memory(self):
        for r in self.profile.regions:
            lo = r.base & ~(target.PAGE - 1)
            hi = (r.end + target.PAGE - 1) & ~(target.PAGE - 1)
            self.uc.mem_map(lo, hi - lo)
        # Past the end of RAM, real hardware bus-faults. Mapping a guard
        # there lets the run continue past a stack overflow that runs off
        # the top (accesses to it are marked unmapped for the oracles), so
        # one crash does not hide every later finding.
        ram = self.profile.ram
        if ram is not None:
            g_lo = (ram.end + target.PAGE - 1) & ~(target.PAGE - 1)
            g_hi = g_lo + GUARD_BYTES
            if not any(r.base < g_hi and g_lo < r.end for r in self.profile.regions):
                try:
                    self.uc.mem_map(g_lo, GUARD_BYTES)
                    self._guard = (g_lo, g_hi)
                except UcError:
                    pass
        # load_images puts initialized data at its flash (LMA) address too,
        # where the reset handler's .data copy loop reads it from.
        for addr, data in list(self.gt.load_images) + list(self.gt.segments):
            for r in self.profile.regions:
                lo, hi = max(addr, r.base), min(addr + len(data), r.end)
                if lo < hi:
                    self.uc.mem_write(lo, bytes(data[lo - addr:hi - addr]))

    def set_input_queue(self, data: bytes):
        self.mmio.load_input(data)

    def set_instruction_budget(self, n: int):
        self._max_instructions = n

    def watch(self, *addrs: int):
        """Count executions of these instruction addresses (RunResult.watch_hits)."""
        self._watch.update(addrs)

    def add_monitor_range(self, lo: int, hi: int):
        self._monitor_ranges.append((lo, hi))

    # -- shadow call stack -------------------------------------------------

    def _set_stack(self, frames: list):
        self._stack = frames
        self._live = tuple(frames)
        self._rets = Counter(f.ret for f in frames)

    def _pop_returned(self, sp: int):
        changed = False
        while self._stack and self._stack[-1].cfa <= sp:
            f = self._stack.pop()
            self._rets[f.ret] -= 1
            changed = True
        if changed:
            self._live = tuple(self._stack)

    def _code_hook(self, uc, address, size, user_data):
        self._instr_count += 1
        if self._instr_count > self._max_instructions:
            self._stop_reason = "budget_exceeded"
            uc.emu_stop()
            return
        self._pc = address
        if address in self._watch:
            self._watch_hits[address] += 1
        if self._rets[address]:
            self._pop_returned(uc.reg_read(UC_ARM_REG_SP))
        if address in self._func_entries:
            sp = uc.reg_read(UC_ARM_REG_SP)
            # A new frame at or above an existing one means that one is
            # gone (tail call, or a return we did not see).
            self._pop_returned(sp)
            lr = uc.reg_read(UC_ARM_REG_LR)
            frame = Frame(func=address, activation=next(self._activations), cfa=sp,
                          ret=lr & ~1, lr=lr, callee_saved=tuple(uc.reg_read(r) for r in _CALLEE_SAVED))
            self._stack.append(frame)
            self._rets[frame.ret] += 1
            self._live = tuple(self._stack)
        if self._stop_at_idle and address in self._idle:
            self._stop_reason = "idle"
            uc.emu_stop()

    def _mem_hook(self, uc, access, address, size, value, user_data):
        if self._monitor_ranges and not any(lo <= address < hi for lo, hi in self._monitor_ranges):
            return
        is_write = access == UC_MEM_WRITE
        if self._guard[0] <= address < self._guard[1]:
            self._unmapped_hook(uc, UC_MEM_WRITE_UNMAPPED if is_write else 0, address, size, value, None)
            return
        if is_write and self._stack:
            top = self._stack[-1]
            # The prologue's push stores LR just below the CFA: remember
            # where, so later writes to that slot can be recognized.
            if (value == top.lr and top.activation not in self._lr_slots
                    and top.cfa - SAVED_LR_SEARCH_BYTES <= address < top.cfa):
                self._lr_slots[top.activation] = address
        self._accesses.append(MemAccess(
            pc=self._pc, address=address, size=size, is_write=is_write,
            value=value if is_write else None, frames=self._live))
        self._maybe_snapshot(uc)

    def _maybe_snapshot(self, uc):
        if self._snapshot_at is not None and len(self._accesses) == self._snapshot_at + 1:
            self.snapshot = {name: f"0x{uc.reg_read(reg):08x}" for name, reg in _SNAPSHOT_REGS}
            self.snapshot["pc"] = f"0x{self._pc:08x}"

    def _unmapped_hook(self, uc, access, address, size, value, user_data):
        is_write = access == UC_MEM_WRITE_UNMAPPED
        self._accesses.append(MemAccess(
            pc=self._pc, address=address, size=size, is_write=is_write,
            value=value if is_write else None, frames=self._live, unmapped=True))
        self._maybe_snapshot(uc)
        return False   # let Unicorn raise the fault

    # -- running -------------------------------------------------------------

    def run_from(self, entry_addr: int, sp: Optional[int] = None,
                 r0: int = 0, r1: int = 0, r2: int = 0, r3: int = 0,
                 stop_at_idle: bool = False) -> RunResult:
        """Execute Thumb code at entry_addr until it returns to the LR
        sentinel, exits via the SIM register, faults, exhausts the budget,
        or (with stop_at_idle) reaches a wfi/wfe or branch-to-self loop.
        sp defaults to the vector table's initial SP for a run from the
        reset handler, and to just below the stack top otherwise."""
        if sp is None:
            top = self.profile.stack_top
            sp = top if entry_addr == self.gt.entry else top - SEED_STACK_HEADROOM

        self.uc.reg_write(UC_ARM_REG_SP, sp)
        self.uc.reg_write(UC_ARM_REG_LR, LR_SENTINEL)
        self.uc.reg_write(UC_ARM_REG_R0, r0)
        self.uc.reg_write(UC_ARM_REG_R1, r1)
        self.uc.reg_write(UC_ARM_REG_R2, r2)
        self.uc.reg_write(UC_ARM_REG_R3, r3)

        self._stop_reason = None
        self._fault_detail = None
        self._stop_at_idle = stop_at_idle
        self.mmio.sim_exit_requested = False
        self.mmio.starved = False
        self.mmio.sr_read_count_since_last_rx = 0
        self._instr_count = 0
        self._set_stack([])

        fault_pc = fault_target = None
        start = entry_addr | 1   # forces Thumb state for the initial branch
        while True:
            try:
                self.uc.emu_start(start, LR_SENTINEL)
                break
            except UcError as e:
                if self.mmio.sim_exit_requested:
                    break
                target_pc = self.uc.reg_read(UC_ARM_REG_PC)
                if self._recover_from_hijack(target_pc):
                    start = self.uc.reg_read(UC_ARM_REG_PC) | 1
                    continue
                self._stop_reason = "fault"
                self._fault_detail = str(e)
                fault_pc = self._pc
                fault_target = target_pc
                break

        if self._stop_reason is None:
            if self.mmio.sim_exit_requested:
                self._stop_reason = "sim_exit"
            elif self.mmio.starved:
                self._stop_reason = "input_exhausted"
            else:
                self._stop_reason = "returned"
        elif self.mmio.sim_exit_requested and self._stop_reason != "budget_exceeded":
            self._stop_reason = "sim_exit"

        return RunResult(
            stopped_reason=self._stop_reason,
            fault_detail=self._fault_detail,
            fault_pc=fault_pc,
            instructions_executed=self._instr_count,
            mmio=self.mmio,
            accesses=self._accesses,
            watch_hits=dict(self._watch_hits),
            saved_lr_slots=dict(self._lr_slots),
            fault_target=fault_target,
            recoveries=list(self._recoveries),
            profile=self.profile,
            exit_code=self.mmio.sim_exit_code,
        )

    def _recover_from_hijack(self, target_pc: int) -> bool:
        """A return through a smashed saved LR sends execution to garbage and
        ends the run, hiding every later finding. When the faulting
        instruction was the innermost frame's return, finish that return the
        way the intact frame would have (callee-saved registers, SP and PC
        from its entry) and keep going. Evidence of the smash itself is
        already in the access trace."""
        if not self._stack or len(self._recoveries) >= MAX_HIJACK_RECOVERIES:
            return False
        frame = self._stack[-1]
        if (target_pc & ~1) == frame.ret:
            return False
        insn = decode_one(self.gt, self._pc)
        if insn is None or classify_branch(insn) != RETURN:
            return False
        for reg, value in zip(_CALLEE_SAVED, frame.callee_saved):
            self.uc.reg_write(reg, value)
        self.uc.reg_write(UC_ARM_REG_SP, frame.cfa)
        self.uc.reg_write(UC_ARM_REG_PC, frame.ret | 1)
        func = self.gt.function_at(frame.func)
        self._recoveries.append({"function": func.name if func else hex(frame.func),
                                 "return_pc": hex(self._pc), "smashed_target": hex(target_pc),
                                 "resumed_at": hex(frame.ret)})
        self._pop_returned(frame.cfa)
        return True

    def deliver_irq(self, handler_addr: int) -> RunResult:
        """Run an interrupt handler on top of the current (idle) context,
        the way the NVIC would: on the same stack, below an exception
        frame's worth of stacked registers, with RAM exactly as the
        interrupted code left it."""
        sp = self.uc.reg_read(UC_ARM_REG_SP)
        ram = self.profile.ram
        if ram is None or not (ram.base < sp <= ram.end):
            sp = self.profile.stack_top - SEED_STACK_HEADROOM
        sp = (sp - EXCEPTION_FRAME_BYTES) & ~7
        return self.run_from(handler_addr, sp=sp)
