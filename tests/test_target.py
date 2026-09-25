from pathlib import Path

from dvl import elfinfo, svd, target
from dvl.mmio import GENERIC_POLL_BREAK_THRESHOLD, MmioModel, mmio_windows

ROOT = Path(__file__).resolve().parent.parent
STM32 = ROOT / "fixtures" / "baremetal" / "12_stm32_layout"


def test_profile_derives_memory_map_and_vector_table_from_elf():
    gt = elfinfo.load(str(STM32 / "bad.elf"))
    prof = target.resolve(gt, target.load(str(STM32 / "target.toml")))
    assert prof.vector_table == (0x08000000, 24)
    assert prof.initial_sp == 0x20020000
    flash, ram = prof.region_of(0x08000000), prof.ram
    assert flash.kind == "flash" and flash.base == 0x08000000
    assert ram.base == 0x20000000 and ram.end == 0x20020000
    assert prof.emulation_blocker(gt) is None


def test_svd_uart_model_and_derived_peripheral():
    dev = svd.load(str(STM32 / "device.svd"))
    u1 = dev.uart("USART1")
    assert (u1.status_addr, u1.data_addr, u1.rxne, u1.txe) == (0x40013800, 0x40013804, 1 << 5, 1 << 7)
    u2 = dev.uart("USART2")   # derivedFrom USART1: same registers, own base
    assert u2.status_addr == 0x40004400 and u2.rxne == 1 << 5
    assert ("USART2", 0x40004400, 0x400) in dev.ranges()


def test_non_cortex_m_image_is_not_emulated():
    gt = elfinfo.load(str(ROOT / "Firmware Samples" / "row_413_bad.arm.elf"))
    assert target.resolve(gt).emulation_blocker(gt) is not None


def test_generic_poll_breaker_toggles_so_both_loop_kinds_exit():
    m = MmioModel()
    values = [m.read(0x40005000, 4) for _ in range(GENERIC_POLL_BREAK_THRESHOLD + 4)]
    tail = values[GENERIC_POLL_BREAK_THRESHOLD:]
    assert all(v == 0 for v in values[:GENERIC_POLL_BREAK_THRESHOLD])
    assert 0xFFFFFFFF in tail and 0 in tail


def test_mmio_windows_merge_and_avoid_memory():
    prof = target.TargetProfile(
        regions=[target.Region("ram", "ram", 0x20000000, 0x10000)],
        peripherals=[("a", 0x40013800, 0x400), ("b", 0x40013c00, 0x400), ("clash", 0x20000000, 0x100)])
    assert mmio_windows(prof) == [(0x40013000, 0x1000)]
