"""
Unicorn-based Cortex-M3 bare-metal emulation harness.

Implements the prompt's pipeline steps 3-5 for the ARM Cortex-M target
tier:
  3. Harness/emulation setup -- Unicorn, real base address, MMIO stubs.
  4. Path-driving -- for these fixtures, the "attacker input" is either
     baked into the call site (stack-overflow fixtures) or fed through
     the emulated UART RX queue (MMIO-gated / IRQ-only fixtures); no
     angr/symbolic solving is required to reach the finding.
  5. Trigger verification -- delegated to dvl.oracle_bounds /
     dvl.oracle_allocsize, which inspect the access trace this harness
     collects.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UcError
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R7, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
)
from unicorn.unicorn_const import (
    UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ,
    UC_HOOK_MEM_UNMAPPED, UC_ERR_OK,
    UC_MEM_WRITE, UC_MEM_READ,
)


from .elfinfo import ElfGroundTruth
from .mmio import MmioModel, install as mmio_install

FLASH_BASE = 0x00000000
FLASH_SIZE = 0x00040000     # 256K, matches linker.ld
RAM_BASE = 0x20000000
RAM_SIZE = 0x00010000        # 64K, matches linker.ld

LR_SENTINEL = 0xFFFFFFFE     # unmapped; landing here on return = "function returned"
DEFAULT_MAX_INSTRUCTIONS = 2_000_000


@dataclass
class MemAccess:
    pc: int
    address: int
    size: int
    is_write: bool
    value: Optional[int] = None
    frame_bases: dict = field(default_factory=dict)   # snapshot of live frame bases at access time


@dataclass
class RunResult:
    stopped_reason: str          # "sim_exit" | "returned" | "fault" | "budget_exceeded"
    fault_detail: Optional[str] = None
    instructions_executed: int = 0
    mmio: Optional[MmioModel] = None
    accesses: list = field(default_factory=list)          # list[MemAccess], filtered to RAM/monitored range
    entry_sp_snapshots: dict = field(default_factory=dict)    # func entry addr -> SP at entry == DWARF CFA
    exit_code: Optional[int] = None



class CortexM3Harness:
    """One instance per emulation run (fresh Unicorn context each time --
    simpler and safer than trying to reset/rewind engine state)."""

    def __init__(self, gt: ElfGroundTruth):
        self.gt = gt
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.mmio = MmioModel()
        self._setup_memory()
        mmio_install(self.uc, self.mmio)
        self._instr_count = 0
        self._max_instructions = DEFAULT_MAX_INSTRUCTIONS
        self._accesses: list = []
        self._entry_sp: dict = {}           # func entry addr -> SP value at function entry == DWARF CFA
        self._monitor_ranges: list = []     # list[(lo,hi)] restrict access-trace collection (perf)
        self._stop_reason = None
        self._fault_detail = None
        self._func_entries = {f.address for f in gt.functions}
        # Hooks are registered exactly once per harness instance (not per
        # run_from() call) so that run_from() can be invoked repeatedly on
        # the same instance -- e.g. fixture 05 seeds execution at an ISR
        # entry point once per simulated interrupt, and RAM state (globals
        # like a static ring buffer/index) must persist across those calls.
        # Registering hooks again on every call would stack duplicate
        # callbacks and multiply-count every access.
        self.uc.hook_add(UC_HOOK_CODE, self._frame_tracker_hook)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._mem_hook)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._mem_hook)



    def _setup_memory(self):
        self.uc.mem_map(FLASH_BASE, FLASH_SIZE)
        self.uc.mem_map(RAM_BASE, RAM_SIZE)
        for vaddr, data in self.gt.segments:
            if FLASH_BASE <= vaddr < FLASH_BASE + FLASH_SIZE:
                self.uc.mem_write(vaddr, bytes(data))
            elif RAM_BASE <= vaddr < RAM_BASE + RAM_SIZE:
                self.uc.mem_write(vaddr, bytes(data))

    def set_input_queue(self, data: bytes):
        self.mmio.load_input(data)

    def set_instruction_budget(self, n: int):
        self._max_instructions = n

    def _frame_tracker_hook(self, uc, address, size, user_data):
        self._instr_count += 1
        if self._instr_count > self._max_instructions:
            self._stop_reason = "budget_exceeded"
            uc.emu_stop()
            return
        # DWARF's DW_AT_frame_base for GCC ARM -O0 is DW_OP_call_frame_cfa,
        # and the CFA is defined as "the SP value at function entry, before
        # the callee pushes anything" -- i.e. exactly the SP register value
        # the first instant PC reaches a function's entry address. Capture
        # it there so fbreg-relative locals resolve to the *real* concrete
        # address the compiler generated, instead of guessing an offset
        # from r7 (which depends on that function's specific
        # push/sub-sp prologue and isn't a fixed relationship).
        if address in self._func_entries:
            self._entry_sp[address] = uc.reg_read(UC_ARM_REG_SP)

    def _mem_hook(self, uc, access, address, size, value, user_data):
        is_write = (access == UC_MEM_WRITE)

        if self._monitor_ranges:
            in_range = any(lo <= address < hi for lo, hi in self._monitor_ranges)
            if not in_range:
                return
        pc = uc.reg_read(UC_ARM_REG_PC)
        rec = MemAccess(
            pc=pc, address=address, size=size, is_write=is_write,
            value=value if is_write else None,
            frame_bases=dict(self._entry_sp),
        )
        self._accesses.append(rec)


    def add_monitor_range(self, lo: int, hi: int):
        self._monitor_ranges.append((lo, hi))

    def run_from(self, entry_addr: int, sp: Optional[int] = None,
                 r0: int = 0, r1: int = 0, r2: int = 0, r3: int = 0) -> RunResult:
        """Start executing Thumb code at entry_addr. If sp is None, uses
        top of RAM (a fresh, generously-sized stack) -- appropriate both
        for a normal reset-vector run and for directly seeding execution
        at an ISR per the prompt's step 4 ('symbolic execution to solve
        for register state ... and directly seed emulation there'; we
        substitute a concrete, generously-provisioned register/stack
        seed since no angr/symbolic solving is needed for these
        fixtures)."""
        if sp is None:
            sp = RAM_BASE + RAM_SIZE - 0x400   # leave headroom below top of RAM

        self.uc.reg_write(UC_ARM_REG_SP, sp)
        self.uc.reg_write(UC_ARM_REG_LR, LR_SENTINEL)
        self.uc.reg_write(UC_ARM_REG_R0, r0)
        self.uc.reg_write(UC_ARM_REG_R1, r1)
        self.uc.reg_write(UC_ARM_REG_R2, r2)
        self.uc.reg_write(UC_ARM_REG_R3, r3)

        # Reset per-call stop state so run_from() can be invoked repeatedly
        # on the same instance (e.g. once per simulated interrupt in
        # fixture 05) without a previous call's terminal status leaking
        # into this one's result.
        self._stop_reason = None
        self._fault_detail = None

        try:

            # entry_addr | 1 forces Thumb state for the initial branch.
            self.uc.emu_start(entry_addr | 1, LR_SENTINEL)
            if self._stop_reason is None:
                pc = self.uc.reg_read(UC_ARM_REG_PC)
                if pc == LR_SENTINEL:
                    self._stop_reason = "returned"
                elif self.mmio.sim_exit_requested:
                    self._stop_reason = "sim_exit"
                else:
                    self._stop_reason = "returned"
        except UcError as e:
            if self.mmio.sim_exit_requested:
                self._stop_reason = "sim_exit"
            else:
                self._stop_reason = "fault"
                self._fault_detail = str(e)

        if self.mmio.sim_exit_requested and self._stop_reason != "budget_exceeded":
            self._stop_reason = "sim_exit"

        return RunResult(
            stopped_reason=self._stop_reason or "unknown",
            fault_detail=self._fault_detail,
            instructions_executed=self._instr_count,
            mmio=self.mmio,
            accesses=self._accesses,
            entry_sp_snapshots=dict(self._entry_sp),
            exit_code=self.mmio.sim_exit_code,

        )
