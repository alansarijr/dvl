"""
Minimal CMSIS-SVD reader: peripheral address ranges, and enough of a UART's
register layout to feed it input.

Handles derivedFrom peripherals and the common UART register/field names
(STM32 SR/DR and ISR/RDR/TDR, NXP/others STAT/DATA). Anything more (reset
values, enumerated fields, clusters) is ignored.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

from .target import UartModel

_UART_NAME = re.compile(r"^(US?ART|LPUART|UART)\d*$", re.IGNORECASE)
_STATUS_REGS = ("SR", "ISR", "STAT", "STATUS", "FR", "LSR")
_RX_DATA_REGS = ("DR", "RDR", "DATA", "RBR", "RXDATA")
_TX_DATA_REGS = ("TDR", "TXDATA", "THR")
_RXNE_FIELDS = ("RXNE", "RXNE_RXFNE", "RDRF", "RXRDY")
_TXE_FIELDS = ("TXE", "TXE_TXFNF", "TDRE", "TXRDY", "THRE", "TXEMPTY")


def _num(text: Optional[str], default: int = 0) -> int:
    if text is None:
        return default
    text = text.strip().lower()
    if text.startswith("#"):
        return int(text[1:].replace("x", "0"), 2)
    return int(text, 0)


@dataclass
class Register:
    name: str
    offset: int
    fields: dict = field(default_factory=dict)   # field name -> bit offset


@dataclass
class Peripheral:
    name: str
    base: int
    size: int
    registers: dict = field(default_factory=dict)   # name -> Register


@dataclass
class Device:
    name: str
    peripherals: list = field(default_factory=list)

    def ranges(self) -> list:
        return [(p.name, p.base, p.size) for p in self.peripherals if p.size]

    def uart(self, name: Optional[str] = None) -> Optional[UartModel]:
        for p in self.peripherals:
            if name is not None and p.name.upper() != name.upper():
                continue
            if name is None and not _UART_NAME.match(p.name):
                continue
            model = _uart_model(p)
            if model is not None:
                return model
        return None


def _find(regs: dict, names) -> Optional[Register]:
    for n in names:
        if n in regs:
            return regs[n]
    return None


def _bit(reg: Register, names) -> Optional[int]:
    for n in names:
        if n in reg.fields:
            return 1 << reg.fields[n]
    return None


def _uart_model(p: Peripheral) -> Optional[UartModel]:
    status = _find(p.registers, _STATUS_REGS)
    rx = _find(p.registers, _RX_DATA_REGS)
    if status is None or rx is None:
        return None
    rxne = _bit(status, _RXNE_FIELDS)
    txe = _bit(status, _TXE_FIELDS)
    if rxne is None or txe is None:
        return None
    tx = _find(p.registers, _TX_DATA_REGS)
    return UartModel(name=p.name, base=p.base, status=status.offset, data=rx.offset,
                     rxne=rxne, txe=txe, tx_data=tx.offset if tx is not None else None)


def _parse_registers(elem) -> dict:
    regs = {}
    if elem is None:
        return regs
    for r in elem.iter("register"):
        name = (r.findtext("name") or "").strip().upper()
        reg = Register(name=name, offset=_num(r.findtext("addressOffset")))
        for f in r.iter("field"):
            fname = (f.findtext("name") or "").strip().upper()
            if f.find("bitOffset") is not None:
                reg.fields[fname] = _num(f.findtext("bitOffset"))
            elif f.find("lsb") is not None:
                reg.fields[fname] = _num(f.findtext("lsb"))
            elif f.find("bitRange") is not None:
                m = re.match(r"\[(\d+):(\d+)\]", f.findtext("bitRange").strip())
                if m:
                    reg.fields[fname] = int(m.group(2))
        regs[name] = reg
    return regs


def load(path: str) -> Device:
    root = ET.parse(path).getroot()
    by_name = {}
    ordered = []
    for p in root.iter("peripheral"):
        name = (p.findtext("name") or "").strip()
        base = _num(p.findtext("baseAddress"))
        size = sum(_num(b.findtext("size")) for b in p.findall("addressBlock"))
        regs = _parse_registers(p.find("registers"))
        parent = by_name.get(p.get("derivedFrom", ""))
        if parent is not None:
            size = size or parent.size
            regs = regs or parent.registers
        per = Peripheral(name=name, base=base, size=size, registers=regs)
        by_name[name] = per
        ordered.append(per)
    return Device(name=(root.findtext("name") or "").strip(), peripherals=ordered)
