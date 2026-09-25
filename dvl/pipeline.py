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

from . import elfinfo, oracle_allocsize, oracle_reachability, oracle_bounds, oracle_pathsolve
from .emulator_cortexm import CortexM3Harness, RAM_BASE, RAM_SIZE
from .schema import Finding, Verdict, VerdictRecord, Evidence, EngineTier

GENERIC_ISR_PAYLOAD = bytes([ord('A')] * 16)              # no '\n' -> any index-reset logic never fires
GENERIC_RESET_PAYLOAD = bytes([ord('A')] * 64) + b'\n'     # generous, terminated, for UART-fed loops
GENERIC_INSTRUCTION_BUDGET = 4_000_000


def _looks_like_cortexm_fixture_target(gt: elfinfo.ElfGroundTruth) -> bool:
    """Heuristic capability-negotiation check: does this binary match the
    bare-metal Cortex-M vector-table-at-address-0 layout our emulation
    harness is built for? If isr_vector[0] doesn't look like a plausible
    initial SP (in some RAM-like high region) or isr_vector[1] doesn't
    equal the ELF entry point, this is not that kind of target and full
    dynamic verification is not attempted."""
    data = gt.read_bytes(0x0, 8)
    if not data or len(data) < 8:
        return False
    initial_sp = int.from_bytes(data[0:4], "little")
    reset_handler = int.from_bytes(data[4:8], "little") & ~1
    plausible_sp = initial_sp != 0 and (initial_sp & 0xFFFF0000) != 0
    matches_entry = reset_handler == gt.entry
    return plausible_sp and matches_entry


def _run_generic_dynamic_check(gt: elfinfo.ElfGroundTruth, finding: Finding, func) -> VerdictRecord:
    entry_addrs = {f.address for f in gt.functions}
    irq_only = oracle_reachability.is_irq_only(gt, finding.address)

    harness = CortexM3Harness(gt)
    if irq_only:
        isr_sp = RAM_BASE + RAM_SIZE - 0x400
        harness.set_input_queue(GENERIC_ISR_PAYLOAD)
        run_result = None
        for _ in range(len(GENERIC_ISR_PAYLOAD)):
            run_result = harness.run_from(func.address, sp=isr_sp)
        driver_desc = (f"ISR-seeded driver: '{func.name}' is reachable only via the "
                        f"vector table (no path from the reset vector's own call "
                        f"graph), so execution was seeded directly at its entry "
                        f"point 0x{func.address:x}, {len(GENERIC_ISR_PAYLOAD)} times "
                        f"-- once per simulated interrupt -- each consuming one "
                        f"queued UART byte.")
    else:
        harness.set_instruction_budget(GENERIC_INSTRUCTION_BUDGET)
        harness.set_input_queue(GENERIC_RESET_PAYLOAD)
        run_result = harness.run_from(gt.entry)
        driver_desc = (f"Reset-vector driver: ran from the reset vector with a "
                        f"generic {len(GENERIC_RESET_PAYLOAD)}-byte UART payload "
                        f"preloaded (covers both input baked directly into a call "
                        f"site and input fed through the UART RX MMIO queue).")

    candidates = []   # list[(var, owning_function, sibling_vars_or_None)]
    local_vars = gt.variables_for(func)
    global_vars = list(gt.global_variables.values())
    for v in local_vars:
        candidates.append((v, func, local_vars))
    for v in global_vars:
        # Sibling set includes other globals (so a global laid out right
        # next to `v` in .bss/.data isn't misattributed as `v` overflowing
        # -- see oracle_bounds._contained_in_sibling) but deliberately NOT
        # local_vars: locals live in a different function's stack frame
        # entirely, never adjacent to a global in any meaningful sense.
        candidates.append((v, func, global_vars))

    if not candidates:
        return VerdictRecord(
            finding_id=finding.finding_id,
            verdict=Verdict.INCONCLUSIVE,
            confidence="low",
            engine_tier=EngineTier.A_FULL_DYNAMIC,
            evidence=Evidence(kind="bounds",
                               detail=f"[{driver_desc}] No DWARF local or global variables "
                                      f"were found to check bounds against for '{func.name}'."),
            notes="Needs manual review or richer debug info -- DWARF has no candidate "
                  "variable to anchor a bounds check against.",
        )

    def _best_bounds_result(result):
        """Returns (best, access_gap). access_gap is True iff at least one
        of the flagged function's OWN LOCAL variables was cleared as FP
        with ZERO observed accesses -- meaning the driver merely
        returned/branched away before ever exercising that variable's
        code (e.g. a magic-value gate it never satisfied), not that it
        was verified safe. Deliberately scoped to locals only: a global
        candidate (added to the pool so cross-function cases like a
        shared lookup table still resolve) showing no access is entirely
        normal -- most of a real program's globals are unrelated to any
        one given function -- and must NOT be treated as a gap, or every
        FP in a multi-global program would look suspicious. A single
        unrelated always-touched local clearing cleanly must not paper
        over a genuine gap in another local, which is why this checks
        every local candidate rather than trusting whichever one 'best'
        happens to land on."""
        best = None
        access_gap = False
        for var, owning, siblings in candidates:
            res = oracle_bounds.check(finding.cwe_id, var, owning, result,
                                        all_function_vars=siblings,
                                        function_entry_addrs=entry_addrs)
            if res.verdict == Verdict.FP and not res.saw_any_access and not var.is_global:
                access_gap = True
            if res.verdict == Verdict.TP:
                return res, access_gap
            if best is None or (best.verdict == Verdict.INCONCLUSIVE and res.verdict == Verdict.FP):
                best = res
        return best, access_gap

    best, access_gap = _best_bounds_result(run_result)

    if (best.verdict == Verdict.INCONCLUSIVE or access_gap) and not irq_only:
        # The generic fixed-pattern payload never reached/triggered the
        # finding -- try solving for a specific driving input before
        # giving up. See dvl.oracle_pathsolve for why this is scoped to
        # non-IRQ findings and how it avoids the MMIO-symbolic-explosion
        # trap.
        #
        # Seeded at the flagged function's OWN entry point, not the reset
        # vector -- same rationale as the IRQ-seeded strategy above. A
        # real firmware's main() typically calls several UART-consuming
        # functions before the flagged one; solving/replaying from the
        # reset vector would burn the solved prefix (and the replayed
        # bytes) on those earlier, unrelated reads before ever reaching
        # this function's own gate check.
        solved = oracle_pathsolve.solve_driving_input(gt, func.address, finding.address)
        if solved is not None:
            solved_harness = CortexM3Harness(gt)
            solved_harness.set_instruction_budget(GENERIC_INSTRUCTION_BUDGET)
            solved_harness.set_input_queue(solved.uart_bytes)
            solved_result = solved_harness.run_from(func.address)
            solved_best, solved_access_gap = _best_bounds_result(solved_result)
            if solved_best is not None and (
                    solved_best.verdict == Verdict.TP or
                    (solved_best.verdict == Verdict.FP and not solved_access_gap)):
                return VerdictRecord(
                    finding_id=finding.finding_id,
                    verdict=solved_best.verdict,
                    confidence="medium",
                    engine_tier=EngineTier.B_PARTIAL_DYNAMIC,
                    evidence=Evidence(kind="pathsolve",
                                       detail=f"[{solved.detail}] {solved_best.detail}"),
                    notes="Confirmed via a symbolically-solved driving input, not the "
                          "generic fixed-pattern payload -- medium rather than high "
                          "confidence because the input-synthesis step relies on angr's "
                          "own (separately modeled) MMIO stubbing rather than the "
                          "Unicorn harness's, even though the final trigger check ran "
                          "on the real Unicorn trace.",
                )

    final_verdict = best.verdict
    confidence = "high" if final_verdict != Verdict.INCONCLUSIVE else "low"
    notes = ""
    if final_verdict == Verdict.INCONCLUSIVE:
        notes = ("Emulation ran to completion but no candidate variable's window "
                 "could be resolved conclusively with this generic driving "
                 "strategy, and a symbolic path-solve fallback (dvl.oracle_pathsolve) "
                 "either found no satisfying input within budget or is unavailable "
                 "(angr not installed). Flagging for manual review or a "
                 "scenario-specific driver.")
    elif final_verdict == Verdict.FP and access_gap:
        # best.verdict is FP, but at least one candidate cleared with ZERO
        # observed accesses -- the driver (and, if attempted, the
        # path-solve fallback) never actually drove into that candidate's
        # code, so this is not a verified-safe FP. Report it honestly
        # rather than letting "no access" quietly masquerade as "checked
        # and fine". Deliberately does NOT touch a TP verdict here -- a
        # confirmed out-of-bounds access on ONE candidate is real evidence
        # regardless of what any OTHER, unrelated candidate variable saw.
        final_verdict = Verdict.INCONCLUSIVE
        confidence = "low"
        notes = ("The driving input(s) tried (generic payload" +
                 (", plus an angr-solved input," if not irq_only else "") +
                 ") never caused any access to the candidate variable(s) at all -- "
                 "the flagged code path was not actually exercised, so this cannot "
                 "be reported as a confirmed FP. Needs a more targeted driver or "
                 "manual review.")

    return VerdictRecord(
        finding_id=finding.finding_id,
        verdict=final_verdict,
        confidence=confidence,
        engine_tier=EngineTier.A_FULL_DYNAMIC,
        evidence=Evidence(kind="bounds", detail=f"[{driver_desc}] {best.detail}"),
        notes=notes,
    )


def adjudicate(gt: elfinfo.ElfGroundTruth, finding: Finding) -> VerdictRecord:
    is_cortexm_target = _looks_like_cortexm_fixture_target(gt)

    if finding.cwe_id == "CWE-789":
        # Pure static instruction-identity / constant-immediate check --
        # valid for ANY arch/target, needs no emulation at all.
        res = oracle_allocsize.check(gt, finding.address)
        return VerdictRecord(
            finding_id=finding.finding_id,
            verdict=res.verdict,
            confidence=res.confidence,
            engine_tier=EngineTier.C_STATIC_ONLY,
            evidence=Evidence(kind="allocsize", detail=res.detail),
            notes="" if res.verdict != Verdict.INCONCLUSIVE else
                  "Allocation size is register-derived; static refutation "
                  "cannot resolve provenance. Needs dataflow/taint analysis "
                  "or emulation to confirm/refute.",
        )

    if finding.cwe_id in ("CWE-121", "CWE-125", "CWE-787"):
        if not is_cortexm_target:
            return VerdictRecord(
                finding_id=finding.finding_id,
                verdict=Verdict.INCONCLUSIVE,
                confidence="low",
                engine_tier=EngineTier.C_STATIC_ONLY,
                evidence=Evidence(kind="recovery",
                                   detail="Binary does not match the bare-metal "
                                          "Cortex-M vector-table memory layout "
                                          "this tool's emulation harness assumes "
                                          "(isr_vector[0]/[1] do not resolve to a "
                                          "plausible initial SP + matching Reset_Handler). "
                                          "No dynamic verification capability for "
                                          "this target/arch."),
                notes="Manual review required: this target needs a dedicated "
                      "memory-map/harness profile before dynamic verification is "
                      "possible.",
            )

        r = oracle_reachability.check(gt, finding.address)
        if r.verdict == Verdict.FP:
            return VerdictRecord(
                finding_id=finding.finding_id,
                verdict=Verdict.FP,
                confidence="high",
                engine_tier=EngineTier.A_FULL_DYNAMIC,
                evidence=Evidence(kind="reachability", detail=r.detail),
                notes="Refuted by static reachability triage -- emulation "
                      "was not necessary.",
            )

        func = gt.function_at(finding.address)
        if func is None:
            return VerdictRecord(
                finding_id=finding.finding_id,
                verdict=Verdict.INCONCLUSIVE,
                confidence="low",
                engine_tier=EngineTier.A_FULL_DYNAMIC,
                evidence=Evidence(kind="reachability", detail=r.detail),
                notes="The flagged address does not fall inside any known function's "
                      "boundary -- cannot select a driving strategy or a candidate "
                      "variable. Needs manual review.",
            )

        return _run_generic_dynamic_check(gt, finding, func)

    return VerdictRecord(
        finding_id=finding.finding_id,
        verdict=Verdict.INCONCLUSIVE,
        confidence="low",
        engine_tier=EngineTier.C_STATIC_ONLY,
        evidence=Evidence(kind="recovery",
                           detail=f"No verification oracle implemented for {finding.cwe_id} in this MVP."),
        notes="Unsupported CWE class -- needs manual review.",
    )


def run(binary_path: str, findings) -> list:
    gt = elfinfo.load(binary_path)
    return [adjudicate(gt, f) for f in findings]
