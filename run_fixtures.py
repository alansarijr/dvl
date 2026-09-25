#!/usr/bin/env python3
"""
End-to-end fixture validator: drives every fixtures/baremetal/NN_*/ case
through the appropriate pipeline stage(s) (reachability / emulation+bounds
oracle / alloc-size oracle) and asserts the observed verdict matches
expected.json.

Each fixture scenario needs a different *driving* strategy (this is the
"path-driving to the finding" pipeline step, prompt section 4) -- there is
no single generic "just run from reset" recipe that covers a straight
overflow, an MMIO-gated poll loop, and an interrupt-only code path alike.
That per-scenario driving logic lives here; the actual verification
(oracle_bounds / oracle_allocsize / oracle_reachability) is scenario-
agnostic and reused unchanged across all of them.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dvl import elfinfo, oracle_bounds, oracle_allocsize, oracle_reachability, pipeline
from dvl.emulator_cortexm import CortexM3Harness, RAM_BASE, RAM_SIZE
from dvl.schema import Verdict, Finding, AddressSpace
from dvl.callgraph import _read_bytes
import capstone as cs

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "baremetal"

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"


def find_sp_adjust_addr(gt, func) -> int:
    """Locate the function's own 'sub sp, sp, #imm' prologue instruction
    address (fixture 02's synthetic 'flagged address', standing in for
    whatever address a real SAST tool would have pointed at)."""
    data = _read_bytes(gt, func.address, min(func.size or 64, 64))
    mode = gt.mode_at(func.address)
    md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB if mode == "thumb" else cs.CS_MODE_ARM)
    md.detail = False
    for insn in md.disasm(data, func.address):
        if insn.mnemonic.lower().startswith("sub") and insn.op_str.lower().replace(" ", "").startswith("sp,"):
            return insn.address
    raise RuntimeError(f"no sub-sp prologue instruction found in {func.name}")


def run_case_01_style(gt, func_name: str, var_name: str, cwe: str) -> tuple:
    """Plain reset-vector run -- input is already baked into main()'s call
    site (fixtures 01 and 06 both fit this shape)."""
    harness = CortexM3Harness(gt)
    result = harness.run_from(gt.entry)
    var = None
    owning = func_name
    for candidate_scope in (func_name, "main"):
        for v in gt.variables_by_function.get(candidate_scope, []):
            if v.name == var_name:
                var = v
                owning = candidate_scope
                break
        if var:
            break
    if var is None:
        var = gt.global_variables.get(var_name)
        owning = func_name
    entry_addrs = {f.address for f in gt.functions}
    res = oracle_bounds.check(cwe, var, owning, result,
                               all_function_vars=gt.variables_by_function.get(owning),
                               function_entry_addrs=entry_addrs)
    return res.verdict, res.detail


def run_case_04_style(gt, func_name: str, var_name: str, cwe: str) -> tuple:
    """MMIO-gated: preload the UART RX queue with > sizeof(cmd) non-newline
    bytes before running from reset, so the poll-breaker-fed loop actually
    drives past the buffer's bound (or doesn't, for the safe twin)."""
    harness = CortexM3Harness(gt)
    payload = bytes([ord('A')] * 16) + b'\n'
    harness.set_input_queue(payload)
    result = harness.run_from(gt.entry)
    var = next(v for v in gt.variables_by_function[func_name] if v.name == var_name)
    entry_addrs = {f.address for f in gt.functions}
    res = oracle_bounds.check(cwe, var, func_name, result,
                               all_function_vars=gt.variables_by_function[func_name],
                               function_entry_addrs=entry_addrs)
    return res.verdict, res.detail


def run_case_05_style(gt, func_name: str, var_name: str, cwe: str) -> tuple:
    """IRQ-only: seed emulation directly at the ISR's entry point,
    repeatedly -- once per simulated interrupt -- rather than trying to
    simulate real NVIC preemption from main()'s wfi loop. Each invocation
    consumes exactly one queued UART byte, matching one real hardware
    interrupt delivering one received byte."""
    handler = gt.function_by_name(func_name)
    harness = CortexM3Harness(gt)
    payload = bytes([ord('A')] * 12)   # no '\n' -> index never resets
    harness.set_input_queue(payload)
    isr_sp = RAM_BASE + RAM_SIZE - 0x400
    result = None
    for _ in range(len(payload)):
        result = harness.run_from(handler.address, sp=isr_sp)
    var = gt.global_variables.get(var_name)
    entry_addrs = {f.address for f in gt.functions}
    res = oracle_bounds.check(cwe, var, func_name, result,
                               all_function_vars=None,
                               function_entry_addrs=entry_addrs)
    return res.verdict, res.detail


def run_case_alloc(gt, func_name: str) -> tuple:
    func = gt.function_by_name(func_name)
    addr = find_sp_adjust_addr(gt, func)
    res = oracle_allocsize.check(gt, addr)
    return res.verdict, res.detail


def run_case_07_style(gt, func_name: str, address: int, cwe: str) -> tuple:
    """Magic-value-gated overflow (fixture 07): unlike every other
    run_case_*_style function here, this does NOT hand-pick a driving
    strategy -- it calls pipeline.adjudicate() directly, the same entry
    point main.py uses for a real finding. The point of this fixture is
    to exercise pipeline.py's own generic driver -> angr path-solve
    fallback chain, not a bespoke scenario driver, since the concrete
    generic payload can never satisfy the gate on its own."""
    finding = Finding(
        finding_id=f"{func_name}_{cwe}",
        address=address,
        space=AddressSpace.CODE,
        cwe_id=cwe,
        function=func_name,
    )
    record = pipeline.adjudicate(gt, finding)
    detail = (f"[tier={record.engine_tier.value} evidence={record.evidence.kind}] "
              f"{record.evidence.detail}")
    return record.verdict, detail


def run_case_reachability(gt, func_name: str) -> tuple:
    func = gt.function_by_name(func_name)
    res = oracle_reachability.check(gt, func.address)
    verdict = res.verdict if res.verdict is not None else Verdict.TP  # "reachable" -> would proceed; treat as TP-candidate for this fixture's purposes
    return verdict, res.detail


def main():
    total = 0
    failed = 0

    fixtures = sorted(FIXTURES_DIR.glob("*/expected.json"))
    for exp_path in fixtures:
        fixture_dir = exp_path.parent
        expected = json.loads(exp_path.read_text())
        print(f"=== {expected['fixture']} ===")

        for case in expected["cases"]:
            total += 1
            binary = fixture_dir / case["binary"]
            gt = elfinfo.load(str(binary))
            func_name = case["function"]
            cwe = case["cwe"]
            expected_verdict = Verdict(case["expected_verdict"])

            fixture_name = expected["fixture"]
            try:
                if fixture_name == "01_stack_overflow" or fixture_name == "06_oob_read":
                    verdict, detail = run_case_01_style(gt, func_name, "buf" if "buf" in [v.name for v in gt.variables_by_function.get(func_name, [])] else "data", cwe)
                elif fixture_name == "02_alloc_const":
                    verdict, detail = run_case_alloc(gt, func_name)
                elif fixture_name == "03_unreachable":
                    verdict, detail = run_case_reachability(gt, func_name)
                elif fixture_name == "04_mmio_gated":
                    varname = "cmd"
                    verdict, detail = run_case_04_style(gt, func_name, varname, cwe)
                elif fixture_name == "05_irq_only":
                    verdict, detail = run_case_05_style(gt, func_name, "irq_buf", cwe)
                elif fixture_name == "07_magic_gate":
                    address = int(case["address"], 16)
                    verdict, detail = run_case_07_style(gt, func_name, address, cwe)
                else:
                    print(f"  [SKIP] unknown fixture kind {fixture_name}")
                    continue
            except Exception as e:
                verdict = None
                detail = f"EXCEPTION: {e!r}"

            status = PASS if verdict == expected_verdict else FAIL
            if verdict != expected_verdict:
                failed += 1
            print(f"  [{status}] {case['binary']}::{func_name} ({cwe}) "
                  f"expected={expected_verdict.value} got={verdict.value if verdict else verdict}")
            if verdict != expected_verdict:
                print(f"         detail: {detail}")

    print()
    print(f"{total - failed}/{total} cases passed")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
