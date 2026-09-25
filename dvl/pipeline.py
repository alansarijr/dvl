"""
Top-level orchestration: ties ingest -> reachability -> path-driving ->
CWE-specific oracle -> VerdictRecord together for an arbitrary
(binary, SAST report) pair.

Capability-tier detection: the fixtures/baremetal/* targets share one
concrete memory map (FLASH @ 0x0 with a real Cortex-M vector table, RAM @
0x20000000) that our Unicorn harness knows how to set up. A real-world
firmware image handed to this tool may not match that shape at all (e.g.
Firmware Samples/row_413_bad.arm.elf: entry 0x10418, load segments
starting at 0x10000 -- not our bare-metal vector-table layout). Rather
than guess wrong and silently emulate garbage, we detect this up front
and only apply techniques valid independent of memory-map assumptions
(static instruction re-validation, in particular) for anything that
doesn't match -- this is exactly what EngineTier.C_STATIC_ONLY exists
for in dvl.schema.

Generic path-driving strategy for CWE-121/125/787 (step 4 of the
pipeline, prompt section 4): run_fixtures.py's per-scenario drivers
(run_case_01_style / _04_style / _05_style) exist because each fixture
was hand-built to isolate ONE hard problem. A real finding doesn't come
labeled with which of those shapes it is, so this module picks between
exactly two generic strategies automatically, using
oracle_reachability.is_irq_only() as the sole signal:

  - IRQ-only (fixture-05 shape): seed emulation directly at the flagged
    function's own entry point, repeatedly, once per simulated
    interrupt -- a plain reset-vector run provably never reaches it.
  - everything else (fixtures 01/04/06 shape -- input baked into a call
    site OR fed through the UART RX queue): a single reset-vector run
    with a generous generic UART payload preloaded covers both, since
    an MMIO-gated read loop consumes it if present, and a baked-in call
    site ignores it if not.

Neither strategy performs angr-style symbolic path search; both are
concrete-input strategies per the prompt's step 4 "concrete/directed
execution" option. A finding whose real trigger condition needs a
specific, non-generic input value (e.g. an exact magic number an
if-check compares against) is outside what this generic driver can
find -- exactly the situation run_fixtures.py's INCONCLUSIVE fixture
case (06's good twin, before the resolvability fix) was designed to
exercise, and why the "Inconclusive" verdict class exists.
"""
from __future__ import annotations

from typing import Optional

from . import elfinfo, oracle_allocsize, oracle_reachability, oracle_bounds, oracle_pathsolve, oracle_retaddr
from . import target
from .emulator_cortexm import CortexM3Harness
from .schema import Finding, Verdict, VerdictRecord, Evidence, EngineTier

GENERIC_ISR_PAYLOAD = bytes([ord('A')] * 16)              # no '\n' -> any index-reset logic never fires
GENERIC_RESET_PAYLOAD = bytes([ord('A')] * 64) + b'\n'     # generous, terminated, for UART-fed loops


def _drive(gt: elfinfo.ElfGroundTruth, profile, finding: Finding, func, irq_only: bool):
    """Runs the generic concrete driver. Returns (run_result, description)."""
    harness = CortexM3Harness(gt, profile)
    harness.watch(finding.address)
    if irq_only:
        # Let reset and main() set up whatever state the handler relies on,
        # then deliver one interrupt per queued UART byte from that idle
        # point, as the NVIC would.
        boot = harness.run_from(gt.entry, stop_at_idle=True)
        harness.set_input_queue(GENERIC_ISR_PAYLOAD)
        run_result = boot
        for _ in range(len(GENERIC_ISR_PAYLOAD)):
            run_result = harness.deliver_irq(func.address)
        desc = (f"IRQ driver: '{func.name}' is reachable only via the vector table, so the "
                f"firmware ran from reset until it went idle ({boot.stopped_reason}) and "
                f"{len(GENERIC_ISR_PAYLOAD)} interrupts were then delivered to it, each with "
                f"one queued UART byte.")
    else:
        harness.set_input_queue(GENERIC_RESET_PAYLOAD)
        run_result = harness.run_from(gt.entry, stop_at_idle=True)
        desc = (f"Reset driver: ran from the reset handler with a generic "
                f"{len(GENERIC_RESET_PAYLOAD)}-byte UART payload preloaded "
                f"(stopped: {run_result.stopped_reason}).")
    return run_result, desc


def _check_run(gt, finding: Finding, func, run_result):
    """Runs the trigger oracles on one run. Returns (tp, kind, detail,
    objects_known): the DWARF bounds oracle first, then, for write CWEs,
    the return-address oracle, which also works without debug info."""
    res = oracle_bounds.check(gt, finding.cwe_id, func, run_result)
    if res.verdict == Verdict.TP:
        return True, "bounds", res.detail, res.objects_known
    if finding.cwe_id in oracle_bounds.WRITE_CWES:
        ra = oracle_retaddr.check(gt, func, run_result, bytes(run_result.mmio.input_queue))
        if ra.verdict == Verdict.TP:
            return True, "retaddr", ra.detail, res.objects_known
        if res.objects_known == 0:
            return False, "retaddr", ra.detail, 0
    return False, "bounds", res.detail, res.objects_known


def _run_generic_dynamic_check(gt: elfinfo.ElfGroundTruth, profile, finding: Finding, func) -> VerdictRecord:
    irq_only = oracle_reachability.is_irq_only(gt, finding.address)
    run_result, driver_desc = _drive(gt, profile, finding, func, irq_only)
    tp, kind, detail, objects_known = _check_run(gt, finding, func, run_result)
    exercised = run_result.watch_hits.get(finding.address, 0) > 0

    def record(verdict, confidence, detail, notes="", tier=EngineTier.A_FULL_DYNAMIC, kind="bounds"):
        return VerdictRecord(finding_id=finding.finding_id, verdict=verdict, confidence=confidence,
                             engine_tier=tier, evidence=Evidence(kind=kind, detail=detail), notes=notes)

    if tp:
        return record(Verdict.TP, "high", f"[{driver_desc}] {detail}", kind=kind)

    if objects_known == 0 and exercised:
        return record(Verdict.INCONCLUSIVE, "low",
                      f"[{driver_desc}] The flagged instruction executed. {detail} There are no "
                      f"DWARF-described objects, so an overflow that stops short of the saved "
                      f"registers would go unseen.",
                      notes="No debug info: the return-address check can confirm a stack smash "
                            "but cannot clear a finding. Needs DWARF or manual review.",
                      kind=kind)

    if exercised:
        return record(Verdict.FP, "high", f"[{driver_desc}] Flagged instruction executed "
                                          f"{run_result.watch_hits[finding.address]} time(s). {detail}")

    if run_result.deterministic and not irq_only:
        return record(Verdict.FP, "high",
                      f"[{driver_desc}] The flagged instruction never executed, and the run read "
                      f"no input and ran to completion ({run_result.stopped_reason}), so this is the "
                      f"program's only behavior: the flagged code cannot run.")

    if not irq_only:
        # The generic payload never reached the flagged instruction; solve
        # for an input that does. Seeded at the flagged function's own
        # entry, so earlier UART consumers in main() cannot eat the solved
        # bytes before its gate check.
        solved = oracle_pathsolve.solve_driving_input(gt, profile, func.address, finding.address)
        if solved is not None:
            harness = CortexM3Harness(gt, profile)
            harness.watch(finding.address)
            harness.set_input_queue(solved.uart_bytes)
            replay = harness.run_from(func.address, r0=solved.args[0], r1=solved.args[1],
                                      r2=solved.args[2], r3=solved.args[3])
            r_tp, r_kind, r_detail, r_objects = _check_run(gt, finding, func, replay)
            replay_hit = replay.watch_hits.get(finding.address, 0) > 0
            notes = ("Driven by an angr-solved input from the flagged function's own entry, "
                     "not from reset: this shows the bug can be triggered once that function "
                     "runs with these arguments and bytes, not that reset leads there with them. "
                     "Medium confidence for that reason.")
            if r_tp:
                return record(Verdict.TP, "medium", f"[{solved.detail}] {r_detail}",
                              notes=notes, tier=EngineTier.B_PARTIAL_DYNAMIC, kind="pathsolve")
            if replay_hit and r_objects:
                return record(Verdict.FP, "medium", f"[{solved.detail}] {r_detail}",
                              notes=notes, tier=EngineTier.B_PARTIAL_DYNAMIC, kind="pathsolve")

    return record(Verdict.INCONCLUSIVE, "low",
                  f"[{driver_desc}] The flagged instruction at 0x{finding.address:x} never executed "
                  f"({run_result.stopped_reason}; {run_result.input_consumed} input byte(s) consumed).",
                  notes=("The driving input(s) tried never reached the flagged code"
                         + ("" if irq_only else ", and the angr path-solve fallback found no input "
                            "that does (or angr is unavailable)")
                         + ". Needs a more targeted driver or manual review."))


def adjudicate(gt: elfinfo.ElfGroundTruth, finding: Finding,
               profile: Optional[target.TargetProfile] = None) -> VerdictRecord:
    """profile: a target profile (dvl.target.load) or None to derive
    everything from the ELF. Resolved once per binary."""
    if profile is None or not profile.resolved:
        profile = target.resolve(gt, profile)

    def record(verdict, confidence, tier, kind, detail, notes="", extra=None):
        return VerdictRecord(finding_id=finding.finding_id, verdict=verdict, confidence=confidence,
                             engine_tier=tier, notes=notes,
                             evidence=Evidence(kind=kind, detail=detail, extra=extra or {}))

    # Static reachability is valid for any ARM image and any CWE: code that
    # cannot run cannot be a true positive.
    r = oracle_reachability.check(gt, finding.address)
    if r.verdict == Verdict.FP:
        return record(Verdict.FP, r.confidence, EngineTier.C_STATIC_ONLY, "reachability", r.detail,
                      notes="Refuted by static reachability triage; emulation was not necessary.",
                      extra=r.facts)

    if finding.cwe_id == "CWE-789":
        ram = profile.ram if profile.emulation_blocker(gt) is None else None
        res = oracle_allocsize.check(gt, finding.address, profile.cwe789_stack_threshold,
                                     stack_size=ram.size if ram else None)
        return record(res.verdict, res.confidence, EngineTier.C_STATIC_ONLY, "allocsize", res.detail,
                      notes="" if res.verdict != Verdict.INCONCLUSIVE else "Needs manual review.")

    if finding.cwe_id in oracle_bounds.READ_CWES | oracle_bounds.WRITE_CWES:
        blocker = profile.emulation_blocker(gt)
        if blocker is not None:
            return record(Verdict.INCONCLUSIVE, "low", EngineTier.C_STATIC_ONLY, "recovery",
                          f"Not emulated: {blocker} (target profile: {profile.source}). {r.detail}",
                          notes="Needs a target profile (--target) describing this image's memory "
                                "map, or manual review.")

        func = gt.function_at(finding.address)
        if func is None:
            return record(Verdict.INCONCLUSIVE, "low", EngineTier.A_FULL_DYNAMIC, "reachability", r.detail,
                          notes="The flagged address is not inside any known function, so there is "
                                "no function to drive or frame to check. Needs manual review.")
        return _run_generic_dynamic_check(gt, profile, finding, func)

    return record(Verdict.INCONCLUSIVE, "low", EngineTier.C_STATIC_ONLY, "recovery",
                  f"No verification oracle is implemented for {finding.cwe_id}. {r.detail}",
                  notes="Unsupported CWE class; needs manual review.")


def run(binary_path: str, findings, profile: Optional[target.TargetProfile] = None) -> list:
    gt = elfinfo.load(binary_path)
    resolved = target.resolve(gt, profile)
    return [adjudicate(gt, f, resolved) for f in findings]
