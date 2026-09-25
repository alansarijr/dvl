"""
Peripheral/MMIO models for the Cortex-M harness.

Peripheral stubbing is the biggest source of emulation hangs and false
"unreachable" results on bare metal. Two things must hold:

 1. Status-register poll loops must terminate, or every uart_getc()/
    uart_putc() hangs forever.
 2. Data registers must deliver a real byte stream, or a loop that is
    unblocked but always reads the same byte can exit early and never
    drive the iteration count that triggers the bug.

The target profile names a UART (status/data offsets, RXNE/TXE masks) that
serves as the input channel, and optionally the fixtures' SIM exit/print
registers. Every other mapped peripheral address is served by a generic
poll-breaker: after a few repeated reads it alternates all-ones and zero,
so both "wait until set" and "wait until clear" loops make progress.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .target import PAGE, TargetProfile, UartModel

GENERIC_POLL_BREAK_THRESHOLD = 8   # reads of an unmodeled address before it starts toggling
INPUT_STARVED_THRESHOLD = 2000     # UART status polls with an empty RX queue before the run is stopped


@dataclass
class MmioModel:
    """Stateful peripheral model, one instance per harness."""
    uart: Optional[UartModel] = None
    sim_exit: Optional[int] = None
    sim_print: Optional[int] = None
    input_queue: bytearray = field(default_factory=bytearray)
    rx_pos: int = 0
    tx_bytes: bytearray = field(default_factory=bytearray)
    debug_print: bytearray = field(default_factory=bytearray)
    sim_exit_requested: bool = False
    sim_exit_code: Optional[int] = None
    read_counts: dict = field(default_factory=dict)     # generic-fallback poll counters
    sr_read_count_since_last_rx: int = 0
    poll_break_log: list = field(default_factory=list)   # addresses the generic poll-breaker forced
    starved: bool = False    # firmware is spinning on RXNE and the input queue is empty

    @classmethod
    def for_profile(cls, profile: TargetProfile) -> "MmioModel":
        return cls(uart=profile.uart, sim_exit=profile.sim_exit, sim_print=profile.sim_print)

    def load_input(self, data: bytes):
        self.input_queue = bytearray(data)
        self.rx_pos = 0

    def rx_available(self) -> bool:
        return self.rx_pos < len(self.input_queue)

    def read(self, addr: int, size: int) -> int:
        u = self.uart
        if u is not None and addr == u.status_addr:
            if self.rx_available():
                return u.txe | u.rxne
            self.sr_read_count_since_last_rx += 1
            if self.sr_read_count_since_last_rx >= INPUT_STARVED_THRESHOLD:
                self.starved = True
            return u.txe

        if u is not None and addr == u.data_addr:
            if self.rx_available():
                b = self.input_queue[self.rx_pos]
                self.rx_pos += 1
                self.sr_read_count_since_last_rx = 0
                return b
            return 0

        n = self.read_counts.get(addr, 0) + 1
        self.read_counts[addr] = n
        if n <= GENERIC_POLL_BREAK_THRESHOLD:
            return 0
        if n == GENERIC_POLL_BREAK_THRESHOLD + 1:
            self.poll_break_log.append({"address": hex(addr), "action": "toggle_all_bits"})
        return (1 << (size * 8)) - 1 if n % 2 else 0

    def write(self, addr: int, size: int, value: int):
        if self.uart is not None and addr == self.uart.tx_data_addr:
            self.tx_bytes.append(value & 0xFF)
        elif addr == self.sim_exit:
            self.sim_exit_requested = True
            self.sim_exit_code = value
        elif addr == self.sim_print:
            self.debug_print.append(value & 0xFF)
        # other peripheral writes have no modeled side effect


def mmio_windows(profile: TargetProfile) -> list:
    """Page-aligned, merged (base, size) windows covering every peripheral
    range plus the UART and SIM registers, minus anything that overlaps
    flash or RAM."""
    spans = [(b, b + s) for _, b, s in profile.peripherals]
    for addr in (profile.sim_exit, profile.sim_print,
                 profile.uart.status_addr if profile.uart else None,
                 profile.uart.data_addr if profile.uart else None):
        if addr is not None:
            spans.append((addr, addr + 4))
    spans = sorted((lo & ~(PAGE - 1), (hi + PAGE - 1) & ~(PAGE - 1)) for lo, hi in spans)
    merged = []
    for lo, hi in spans:
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return [(lo, hi - lo) for lo, hi in merged
            if not any(r.base < hi and lo < r.end for r in profile.regions)]


def install(uc, model: MmioModel, profile: TargetProfile):
    """Map the peripheral windows into Unicorn with fully virtualized
    reads/writes (no backing RAM)."""
    for base, size in mmio_windows(profile):
        def read_cb(uc_, offset, sz, user_data, base=base):
            value = model.read(base + offset, sz)
            if model.starved:
                # Waiting forever for input that will never come.
                uc_.emu_stop()
            return value

        def write_cb(uc_, offset, sz, value, user_data, base=base):
            addr = base + offset
            model.write(addr, sz, value)
            if addr == model.sim_exit:
                # sim_exit() spins after the write; stop here instead of
                # burning the rest of the instruction budget.
                uc_.emu_stop()

        uc.mmio_map(base, size, read_cb, None, write_cb, None)
