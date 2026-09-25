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
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
)
from unicorn.unicorn_const import (
    UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UC_MEM_WRITE,
)

from .callgraph import idle_addresses
from .elfinfo import ElfGroundTruth
from .mmio import MmioModel, install as mmio_install

FLASH_BASE = 0x00000000
FLASH_SIZE = 0x00040000     # 256K, matches linker.ld
RAM_BASE = 0x20000000
RAM_SIZE = 0x00010000        # 64K, matches linker.ld

LR_SENTINEL = 0xFFFFFFFE     # unmapped; landing here on return = "function returned"
DEFAULT_MAX_INSTRUCTIONS = 2_000_000
EXCEPTION_FRAME_BYTES = 32   # r0-r3, r12, lr, pc, xpsr stacked by hardware on exception entry
SAVED_LR_SEARCH_BYTES = 64   # push {r4-r11, lr} is the widest prologue save


@dataclass(frozen=True)
class Frame:
    func: int          # function entry address
    activation: int    # unique per call
    cfa: int           # SP at entry == DWARF CFA
    ret: int           # return address (LR at entry, Thumb bit cleared)
    lr: int = 0        # raw LR at entry, as the prologue will push it


@dataclass
class MemAccess:
    pc: int
    address: int
    size: int
    is_write: bool
    value: Optional[int] = None
    frames: tuple = ()      # live Frame stack at access time, outermost first

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
    fault_target: Optional[int] = None                    # PC value execution faulted trying to fetch
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
                and self.input_consumed == 0
                and not (self.mmio and self.mmio.poll_break_log))


class CortexM3Harness:
    """One instance per verification attempt. run_from() may be called
    repeatedly on the same instance (reset, then one call per simulated
    interrupt); RAM and the access log persist across calls."""

    def __init__(self, gt: ElfGroundTruth):
        self.gt = gt
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.mmio = MmioModel()
        self._setup_memory()
        mmio_install(self.uc, self.mmio)
        self._instr_count = 0
        self._max_instructions = DEFAULT_MAX_INSTRUCTIONS
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
        # Registered once per instance: registering per run_from() call would
        # stack duplicate callbacks and multiply-count every access.
        self.uc.hook_add(UC_HOOK_CODE, self._code_hook)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._mem_hook)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._mem_hook)

    def _setup_memory(self):
        self.uc.mem_map(FLASH_BASE, FLASH_SIZE)
        self.uc.mem_map(RAM_BASE, RAM_SIZE)
        # load_images puts initialized data at its flash (LMA) address too,
        # where the reset handler's .data copy loop reads it from.
        for addr, data in list(self.gt.load_images) + list(self.gt.segments):
            if FLASH_BASE <= addr < FLASH_BASE + FLASH_SIZE:
                self.uc.mem_write(addr, bytes(data))
            elif RAM_BASE <= addr < RAM_BASE + RAM_SIZE:
                self.uc.mem_write(addr, bytes(data))

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
                          ret=lr & ~1, lr=lr)
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

    # -- running -------------------------------------------------------------

    def run_from(self, entry_addr: int, sp: Optional[int] = None,
                 r0: int = 0, r1: int = 0, r2: int = 0, r3: int = 0,
                 stop_at_idle: bool = False) -> RunResult:
        """Execute Thumb code at entry_addr until it returns to the LR
        sentinel, exits via the SIM register, faults, exhausts the budget,
        or (with stop_at_idle) reaches a wfi/wfe or branch-to-self loop.
        sp defaults to near the top of RAM."""
        if sp is None:
            sp = RAM_BASE + RAM_SIZE - 0x400   # leave headroom below top of RAM

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
        try:
            # entry_addr | 1 forces Thumb state for the initial branch.
            self.uc.emu_start(entry_addr | 1, LR_SENTINEL)
        except UcError as e:
            if not self.mmio.sim_exit_requested:
                self._stop_reason = "fault"
                self._fault_detail = str(e)
                fault_pc = self._pc
                fault_target = self.uc.reg_read(UC_ARM_REG_PC)

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
            exit_code=self.mmio.sim_exit_code,
        )

    def deliver_irq(self, handler_addr: int) -> RunResult:
        """Run an interrupt handler on top of the current (idle) context,
        the way the NVIC would: on the same stack, below an exception
        frame's worth of stacked registers, with RAM exactly as the
        interrupted code left it."""
        sp = self.uc.reg_read(UC_ARM_REG_SP)
        if not (RAM_BASE < sp <= RAM_BASE + RAM_SIZE):
            sp = RAM_BASE + RAM_SIZE - 0x400
        sp = (sp - EXCEPTION_FRAME_BYTES) & ~7
        return self.run_from(handler_addr, sp=sp)
