"""
Top-level orchestration: finding -> static reachability -> CWE-specific
oracle -> VerdictRecord, for any (binary, SAST report) pair.

Order of checks for a finding:

  1. Static reachability (any image, any CWE). Unreachable code is FP.
  2. CWE-789: static allocation-size check against the profile's threshold.
  3. CWE-121/125/787: if the target profile says the image can be emulated
     as a Cortex-M, drive it and run the trigger oracles; otherwise
     Inconclusive with the reason.

Driving (CWE-121/125/787) picks one of two generic concrete strategies:

  - IRQ-only functions (reachable only through the vector table): run
    reset until the firmware idles, then deliver the handler as
    interrupts, one queued UART byte each.
  - Everything else: run from reset with a generic UART payload, which
    covers input baked into a call site and input read over UART.

If the flagged instruction never executes, a run that read no input and
ended naturally proves it cannot (FP). Otherwise angr solves for an input
from the flagged function's entry (oracle_pathsolve) and the result is
replayed in Unicorn; a verdict from that path is medium confidence.

Every driving strategy is a DriverSpec so a run can be replayed exactly,
which is how the register snapshot at a violation is captured.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import elfinfo, oracle_allocsize, oracle_reachability, oracle_bounds, oracle_pathsolve, oracle_retaddr
from . import target
from .emulator_cortexm import CortexM3Harness
from .schema import Finding, Verdict, VerdictRecord, Evidence, EngineTier

GENERIC_ISR_PAYLOAD = bytes([ord('A')] * 16)              # no '\n' -> any index-reset logic never fires
GENERIC_RESET_PAYLOAD = bytes([ord('A')] * 64) + b'\n'     # generous, terminated, for UART-fed loops
TRACE_CONTEXT = 16   # accesses shown before the violating one


@dataclass(frozen=True)
class DriverSpec:
    kind: str                  # "reset" | "irq" | "function"
    payload: bytes
    entry: int = 0             # IRQ handler or function to seed at
    entry_name: str = ""
    irq_count: int = 0
    args: tuple = (0, 0, 0, 0)
    source: str = "generic"    # "generic" | "angr"

    def describe(self, stopped: str) -> str:
        if self.kind == "irq":
            return (f"IRQ driver: '{self.entry_name}' is reachable only via the vector table, so the "
                    f"firmware ran from reset until it went idle ({stopped}) and {self.irq_count} "
                    f"interrupts were then delivered to it, each with one queued UART byte.")
        if self.kind == "reset":
            return (f"Reset driver: ran from the reset handler with a generic {len(self.payload)}-byte "
                    f"UART payload preloaded (stopped: {stopped}).")
        return (f"Function driver: ran '{self.entry_name}' from its entry with r0-r3="
                f"({', '.join(hex(a) for a in self.args)}) and a {len(self.payload)}-byte "
                f"{self.source} UART payload (stopped: {stopped}).")


@dataclass
class Outcome:
    tp: bool
    kind: str                  # "bounds" | "retaddr"
    detail: str
    objects_known: int
    violation: object = None   # MemAccess, when the oracle pinned one


def _execute(gt, profile, finding: Finding, spec: DriverSpec, snapshot_at: Optional[int] = None):
    """Runs a DriverSpec. Returns (run_result, harness, boot_or_run_stop_reason)."""
    harness = CortexM3Harness(gt, profile, snapshot_at=snapshot_at)
    harness.watch(finding.address)
    if spec.kind == "irq":
        # Let reset and main() set up whatever state the handler relies on,
        # then deliver interrupts from that idle point, as the NVIC would.
        boot = harness.run_from(gt.entry, stop_at_idle=True)
        harness.set_input_queue(spec.payload)
        run_result = boot
        for _ in range(spec.irq_count):
            run_result = harness.deliver_irq(spec.entry)
        return run_result, harness, boot.stopped_reason
    harness.set_input_queue(spec.payload)
    if spec.kind == "reset":
        run_result = harness.run_from(gt.entry, stop_at_idle=True)
    else:
        a = spec.args
        run_result = harness.run_from(spec.entry, r0=a[0], r1=a[1], r2=a[2], r3=a[3])
    return run_result, harness, run_result.stopped_reason


def _check_run(gt, finding: Finding, func, run_result) -> Outcome:
    """The DWARF bounds oracle first, then, for write CWEs, the
    return-address oracle, which also works without debug info."""
    res = oracle_bounds.check(gt, finding.cwe_id, func, run_result)
    if res.verdict == Verdict.TP:
        return Outcome(True, "bounds", res.detail, res.objects_known, res.violation)
    if finding.cwe_id in oracle_bounds.WRITE_CWES:
        ra = oracle_retaddr.check(gt, func, run_result, bytes(run_result.mmio.input_queue))
        if ra.verdict == Verdict.TP:
            return Outcome(True, "retaddr", ra.detail, res.objects_known, ra.violation)
        if res.objects_known == 0:
            return Outcome(False, "retaddr", ra.detail, 0)
    return Outcome(False, "bounds", res.detail, res.objects_known)


def _func_name(gt, addr: int) -> str:
    f = gt.function_at(addr)
    return f.name if f else hex(addr)


def _trace_entry(gt, acc, violation: bool = False) -> dict:
    return {
        "pc": f"0x{acc.pc:x}", "function": _func_name(gt, acc.pc), "line": gt.line_for_address(acc.pc),
        "op": "write" if acc.is_write else "read", "address": f"0x{acc.address:x}", "size": acc.size,
        "value": f"0x{acc.value:x}" if acc.value is not None else None,
        **({"unmapped": True} if acc.unmapped else {}), **({"violation": True} if violation else {}),
    }


def _evidence(gt, profile, finding: Finding, func, spec: DriverSpec, run_result, stopped: str,
              outcome: Outcome, kind: str, detail: str) -> Evidence:
    uart = profile.uart
    ev = Evidence(kind=kind, detail=detail)
    ev.triggering_input = {
        "channel": uart.name if uart else None,
        "bytes": spec.payload.decode("latin-1"),
        "bytes_hex": spec.payload.hex(),
        "consumed": run_result.input_consumed,
        "source": spec.source,
        "entry": {"reset": "reset handler", "irq": f"interrupt '{spec.entry_name}' x{spec.irq_count}",
                  "function": f"function '{spec.entry_name}'"}[spec.kind],
        **({"args": [f"0x{a:x}" for a in spec.args]} if spec.kind == "function" else {}),
    }
    ev.extra = {"driver": spec.describe(stopped), "stopped": run_result.stopped_reason,
                "flagged_instruction_hits": run_result.watch_hits.get(finding.address, 0)}
    if run_result.recoveries:
        ev.extra["smashed_returns_recovered"] = run_result.recoveries

    v = outcome.violation
    if v is not None:
        idx = next(i for i, a in enumerate(run_result.accesses) if a is v)
        own = v.frame_of(func.address)
        before = [a for a in run_result.accesses[:idx] if own is not None and own in a.frames]
        ev.trace = [_trace_entry(gt, a) for a in before[-TRACE_CONTEXT:]] + [_trace_entry(gt, v, True)]
        ev.extra["call_path"] = [_func_name(gt, fr.func) for fr in v.frames]
        ev.extra["violation_line"] = gt.line_for_address(v.pc)
        _, replay_harness, _ = _execute(gt, profile, finding, spec, snapshot_at=idx)
        if replay_harness.snapshot is not None:
            ev.extra["registers_at_violation"] = replay_harness.snapshot
    return ev


def _run_generic_dynamic_check(gt: elfinfo.ElfGroundTruth, profile, finding: Finding, func) -> VerdictRecord:
    irq_only = oracle_reachability.is_irq_only(gt, finding.address)
    if irq_only:
        spec = DriverSpec("irq", GENERIC_ISR_PAYLOAD, entry=func.address, entry_name=func.name,
                          irq_count=len(GENERIC_ISR_PAYLOAD))
    else:
        spec = DriverSpec("reset", GENERIC_RESET_PAYLOAD)
    run_result, _, stopped = _execute(gt, profile, finding, spec)
    outcome = _check_run(gt, finding, func, run_result)
    exercised = run_result.watch_hits.get(finding.address, 0) > 0
    driver_desc = spec.describe(stopped)

    def record(verdict, confidence, detail, notes="", tier=EngineTier.A_FULL_DYNAMIC, kind="bounds",
               spec=spec, run_result=run_result, stopped=stopped, outcome=outcome):
        ev = _evidence(gt, profile, finding, func, spec, run_result, stopped, outcome, kind, detail)
        return VerdictRecord(finding_id=finding.finding_id, verdict=verdict, confidence=confidence,
                             engine_tier=tier, evidence=ev, notes=notes)

    if outcome.tp:
        return record(Verdict.TP, "high", f"[{driver_desc}] {outcome.detail}", kind=outcome.kind)

    if outcome.objects_known == 0 and exercised:
        return record(Verdict.INCONCLUSIVE, "low",
                      f"[{driver_desc}] The flagged instruction executed. {outcome.detail} There are no "
                      f"DWARF-described objects, so an overflow that stops short of the saved "
                      f"registers would go unseen.",
                      notes="No debug info: the return-address check can confirm a stack smash "
                            "but cannot clear a finding. Needs DWARF or manual review.",
                      kind=outcome.kind)

    if exercised:
        return record(Verdict.FP, "high", f"[{driver_desc}] Flagged instruction executed "
                                          f"{run_result.watch_hits[finding.address]} time(s). {outcome.detail}")

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
            s_spec = DriverSpec("function", solved.uart_bytes, entry=func.address, entry_name=func.name,
                                args=solved.args, source="angr")
            replay, _, r_stopped = _execute(gt, profile, finding, s_spec)
            r_outcome = _check_run(gt, finding, func, replay)
            replay_hit = replay.watch_hits.get(finding.address, 0) > 0
            notes = ("Driven by an angr-solved input from the flagged function's own entry, "
                     "not from reset: this shows the bug can be triggered once that function "
                     "runs with these arguments and bytes, not that reset leads there with them. "
                     "Medium confidence for that reason.")
            again = dict(spec=s_spec, run_result=replay, stopped=r_stopped, outcome=r_outcome,
                         notes=notes, tier=EngineTier.B_PARTIAL_DYNAMIC, kind="pathsolve")
            if r_outcome.tp:
                return record(Verdict.TP, "medium", f"[{solved.detail}] {r_outcome.detail}", **again)
            if replay_hit and r_outcome.objects_known:
                return record(Verdict.FP, "medium", f"[{solved.detail}] {r_outcome.detail}", **again)

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
