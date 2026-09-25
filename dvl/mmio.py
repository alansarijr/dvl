"""
Peripheral/MMIO stubbing for the Cortex-M3 bare-metal harness.

Per the prompt's "Known Hard Problems": peripheral/MMIO stubbing is the
single biggest source of emulation hangs/false-unreachability for
bare-metal. Two things must both be true for this harness to be useful:

 1. Poll loops on status registers (UART SR.TXE / SR.RXNE) must be
    broken, or every fixture that ever calls uart_putc()/uart_getc()
    hangs forever and gets misreported as "unreachable".
 2. The values fed through data registers (UART DR) must actually vary
    with each read, or a poll-breaker that unblocks the loop but always
    returns the same byte can make the loop exit trivially (e.g. on the
    first read) without ever driving the intended number of iterations,
    silently hiding a bug that only triggers with a longer input.

This module implements a per-project *declarative* peripheral model
(UART0 + SIM test-harness registers, matching fixtures/baremetal/common/
mmio.h) plus a generic fallback poll-breaker for any other MMIO address
the fixtures don't know about -- exactly the two stubbing strategies
called out as open questions in the prompt ("hand-written stubs vs.
existing emulator peripheral models"); we chose hand-written, since a
full QEMU peripheral model is out of scope for firmware with a small,
fixed set of test peripherals.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

PERIPH_BASE = 0x40000000
PERIPH_SIZE = 0x10000

UART0_OFFSET = 0x1000
UART0_SR = UART0_OFFSET + 0x00
UART0_DR = UART0_OFFSET + 0x04

SIM_OFFSET = 0x2000
SIM_EXIT = SIM_OFFSET + 0x00
SIM_PRINT = SIM_OFFSET + 0x04

UART_SR_TXE = 1 << 0
UART_SR_RXNE = 1 << 1

GENERIC_POLL_BREAK_THRESHOLD = 8   # reads of an unmodeled address before we force a bit
INPUT_STARVED_THRESHOLD = 2000     # UART SR polls with an empty RX queue before the run is stopped


@dataclass
class MmioModel:
    """Stateful peripheral model, one instance per emulation run."""
    input_queue: bytearray = field(default_factory=bytearray)
    rx_pos: int = 0
    tx_bytes: bytearray = field(default_factory=bytearray)
    debug_print: bytearray = field(default_factory=bytearray)
    sim_exit_requested: bool = False
    sim_exit_code: Optional[int] = None
    read_counts: dict = field(default_factory=dict)     # generic-fallback poll counters
    sr_read_count_since_last_rx: int = 0
    poll_break_log: list = field(default_factory=list)   # audit trail of poll-breaks applied
    starved: bool = False    # firmware is spinning on RXNE and the input queue is empty

    def load_input(self, data: bytes):
        self.input_queue = bytearray(data)
        self.rx_pos = 0

    def rx_available(self) -> bool:
        return self.rx_pos < len(self.input_queue)

    def read(self, offset: int, size: int) -> int:
        if offset == UART0_SR:
            txe = UART_SR_TXE  # transmit never blocks in this harness
            rxne = UART_SR_RXNE if self.rx_available() else 0
            if not self.rx_available():
                self.sr_read_count_since_last_rx += 1
                if self.sr_read_count_since_last_rx >= INPUT_STARVED_THRESHOLD:
                    self.starved = True
            return txe | rxne

        if offset == UART0_DR:
            if self.rx_available():
                b = self.input_queue[self.rx_pos]
                self.rx_pos += 1
                self.sr_read_count_since_last_rx = 0
                return b
            return 0

        # Generic fallback poll-breaker for any address we don't have a
        # declarative model for: after enough repeated reads, start
        # forcing all-bits-set so a "wait until bit X set" loop can make
        # progress instead of spinning forever.
        self.read_counts[offset] = self.read_counts.get(offset, 0) + 1
        if self.read_counts[offset] > GENERIC_POLL_BREAK_THRESHOLD:
            self.poll_break_log.append(
                {"offset": hex(offset), "reads": self.read_counts[offset],
                 "action": "forced_all_bits_set"}
            )
            return (1 << (size * 8)) - 1
        return 0

    def write(self, offset: int, size: int, value: int):
        if offset == UART0_DR:
            self.tx_bytes.append(value & 0xFF)
            return
        if offset == SIM_EXIT:
            self.sim_exit_requested = True
            self.sim_exit_code = value
            return
        if offset == SIM_PRINT:
            self.debug_print.append(value & 0xFF)
            return
        # unmodeled peripheral write: ignored (no side effect modeled)


def install(uc, model: MmioModel):
    """Wire the MmioModel into a Unicorn instance via mmio_map -- fully
    virtualized reads/writes, no backing RAM needed for the periph
    region."""

    def read_cb(uc_, offset, size, user_data):
        value = model.read(offset, size)
        if model.starved:
            # Waiting forever for input that will never come.
            uc_.emu_stop()
        return value

    def write_cb(uc_, offset, size, value, user_data):
        model.write(offset, size, value)
        if offset == SIM_EXIT:
            # sim_exit() spins after the write; without stopping here every
            # "exited" run burns the rest of the instruction budget.
            uc_.emu_stop()

    uc.mmio_map(PERIPH_BASE, PERIPH_SIZE, read_cb, None, write_cb, None)
