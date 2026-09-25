"""End-to-end runs of main.py's code path on the checked-in samples."""
from pathlib import Path

import pytest

from dvl import ingest, pipeline, target

ROOT = Path(__file__).resolve().parent.parent


def _run(binary, report, profile=None):
    findings = ingest.load_report(str(ROOT / report))
    return {r.finding_id: r for r in pipeline.run(str(ROOT / binary), findings, profile)}


def test_row_413_cwe789_findings_are_small_constant_frames():
    records = _run("Firmware Samples/row_413_bad.arm.elf", "Firmware Samples/result.json")
    assert {k: r.verdict.value for k, r in records.items()} == {
        "instr_0x0001c5c0_9": "FP",
        "instr_0x00050640_9": "FP",
    }


@pytest.mark.slow
def test_gateway_firmware_report():
    # Ground truth from the header comment of sample_firmware/gateway_fw.c.
    records = _run("sample_firmware/gateway_fw.elf", "sample_firmware/gateway_fw_report.json",
                   target.load(str(ROOT / "targets" / "dvl-fixtures.toml")))
    assert {k: r.verdict.value for k, r in records.items()} == {
        "finding_uart_cmd_overflow": "TP",
        "finding_header_copy": "FP",
        "finding_calibration_oob_read": "TP",
        "finding_diag_buffer_alloc": "FP",
        "finding_event_log_overflow": "TP",
        "finding_auth_buf_overflow": "TP",
    }
