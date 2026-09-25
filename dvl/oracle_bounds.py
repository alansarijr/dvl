"""
CWE-121/787/125 trigger-verification oracle (prompt pipeline step 5).

"apply a CWE-specific oracle ... check if the resulting write/read is
out-of-bounds relative to the buffer's actual allocated size at that
point in emulated memory, not just what the static analyzer inferred."

We use DWARF-recovered variable windows (dvl.elfinfo.VariableInfo) --
the *actual* allocated size at that point in memory -- rather than
whatever bound the SAST tool guessed, and check every memory access
Unicorn observed during emulation against that window.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .elfinfo import VariableInfo
from .emulator_cortexm import MemAccess, RAM_BASE, RAM_SIZE, FLASH_BASE, FLASH_SIZE
from .schema import Verdict



@dataclass
class BoundsOracleResult:
    verdict: Verdict
    detail: str
    violation: Optional[MemAccess] = None
    window: Optional[tuple] = None   # (lo, hi) resolved concrete address range
    saw_any_access: bool = True      # False only for the "reached the function but
                                      # never touched this variable at all" FP case --
                                      # lets a caller distinguish "verified safe" from
                                      # "this run just never exercised the code path"


READ_CWES = {"CWE-125", "CWE_125"}
WRITE_CWES = {"CWE-121", "CWE_121", "CWE-787", "CWE_787"}

# How far past a variable's declared end an access can land and still
# plausibly be evidence of THAT variable's own sequential overflow,
# rather than some completely unrelated access (most commonly: a stack
# write from a totally different function's frame, landing far above a
# small, fixed-address global) that merely happens to share the same
# broad RAM/FLASH region. Without this cap, a small global's [lo, hi)
# window matches "acc_lo >= lo" against literally any higher RAM address
# in the whole 64K region, misattributing unrelated stack traffic as a
# multi-kilobyte "overrun" of an 8-byte buffer. Sized generously above
# the largest buffer these fixtures declare (init_diagnostics_buffer's
# 2048 bytes) so a genuine large sequential overflow still triggers.
MAX_PLAUSIBLE_OVERRUN = 4096


def _window_for_access(var: VariableInfo, owning_function: str, acc: MemAccess) -> Optional[tuple]:
    """Resolve the variable's concrete address window using the frame-base
    snapshot captured AT THE TIME of this specific access (acc.frame_bases),
    not a single run-wide snapshot. This matters because a function can be
    entered multiple times (or not yet entered at all when an earlier,
    unrelated access happens to reuse the same stack bytes) -- using a
    stale/future frame base would silently produce false matches against
    completely unrelated writes."""
    size = var.byte_size or 1
    if var.is_global:
        return (var.address, var.address + size)
    fb = acc.frame_bases.get(owning_function)
    if fb is None:
        return None
    lo = fb + var.fbreg_offset
    return (lo, lo + size)


def _contained_in_sibling(acc_lo: int, acc_hi: int, var: VariableInfo,
                           all_vars: list, cfa: Optional[int]) -> bool:
    """A write/read that lands entirely inside some OTHER declared
    variable's own DWARF window is that sibling variable being
    legitimately accessed (e.g. a clamped-length local computed right
    after `buf` in the same frame, or -- for globals -- the next static
    laid out immediately after `var` in .bss, which startup code's
    bulk zero-init loop will touch as one contiguous pass regardless of
    individual variable boundaries) -- not evidence of `var` overflowing.
    Handles both global siblings (absolute .address, cfa-independent)
    and local siblings (frame-relative fbreg_offset, needs cfa) in the
    same pass, since the candidate pool mixes both kinds. Uses exact
    per-variable windows (not an address-range heuristic), so it cannot
    accidentally swallow a genuine overflow: a real smash's write
    extends past every declared variable's own bounds, so it will never
    be "fully contained" in a sibling's window."""
    for v in all_vars:
        if v is var:
            continue
        size = v.byte_size or 1
        if v.is_global:
            v_lo = v.address
        elif v.fbreg_offset is not None and cfa is not None:
            v_lo = cfa + v.fbreg_offset
        else:
            continue
        v_hi = v_lo + size
        if acc_lo >= v_lo and acc_hi <= v_hi:
            return True
    return False


def check(cwe_id: str, var: VariableInfo, owning_function: str, run_result,
          all_function_vars: Optional[list] = None,
          function_entry_addrs: Optional[set] = None) -> BoundsOracleResult:

    """
    Direction-aware overflow check with prologue-push exclusion.

    Two design points, both learned the hard way from real emulation
    traces on these fixtures:

    1. Direction awareness -- a real sequential buffer overflow (what
       CWE-121/125/787 findings describe) always writes/reads starting
       AT-OR-AFTER the buffer's own base address and then runs past its
       upper bound. An access that starts *before* the buffer's lower
       bound is a different piece of memory entirely (a sibling local's
       own slot, a nested callee's own frame at a lower stack address,
       etc.) and must not be misattributed to `var` overflowing.

    2. Prologue-push exclusion -- GCC ARM/Thumb -O0 begins every
       function with 'push {r7,lr}' (a register spill) as its literal
       first instruction. That single instruction is NOT a variable
       access, and critically, the bytes it writes (right above the
       highest local) can be EITHER innocuous framework bookkeeping
       (a callee just being called) OR, in a real overflow, exactly the
       bytes a runaway copy loop smashes through on its way past the
       buffer -- so an address-range "guard band" heuristic can't
       reliably tell the two apart. What *can* tell them apart: the
       push instruction executes exactly once at a fixed, known PC
       (the function's entry address), while a real overflow's writes
       come from a *different* PC (the copy loop's store instruction),
       typically executed repeatedly. So we exclude accesses purely by
       PC == a known function-entry address, independent of address
       range -- this correctly keeps a genuine overflow's smash through
       that same byte range visible (since the smashing writes carry
       the copy loop's PC, not the entry PC).
    """
    want_write = cwe_id.upper().replace("_", "-") in WRITE_CWES or cwe_id in WRITE_CWES
    want_read = cwe_id.upper().replace("_", "-") in READ_CWES or cwe_id in READ_CWES

    # Whether `var`'s concrete address window is resolvable AT ALL during
    # this run is a property of the run (did we ever observe
    # owning_function's frame base?), NOT of whether any particular
    # access happened to relate to it. These are deliberately kept
    # separate: a safe function that bounds-checks and returns BEFORE
    # ever touching `var` produces zero relevant accesses to it, but its
    # frame was still perfectly resolvable -- that is a legitimate FP
    # ("reached the code, no OOB access occurred"), not an Inconclusive
    # ("we have no idea what memory this variable even lives in").
    if var.is_global:
        var_resolvable = True
    else:
        var_resolvable = run_result.entry_sp_snapshots.get(owning_function) is not None

    last_window = None
    saw_any_resolvable_access = False

    for acc in run_result.accesses:

        if want_write and not acc.is_write:
            continue
        if want_read and acc.is_write:
            continue

        if function_entry_addrs is not None and acc.pc in function_entry_addrs:
            # A function's own 'push {r7,lr}' prologue instruction --
            # register-spill housekeeping, never a variable access.
            continue

        window = _window_for_access(var, owning_function, acc)
        if window is None:
            # owning_function hadn't been entered yet at the time of this
            # access -- it cannot possibly be the access the finding is
            # about, so skip rather than mis-attribute it.
            continue

        lo, hi = window
        acc_lo = acc.address
        acc_hi = acc.address + acc.size

        # An access outside the memory region `var` itself lives in
        # (e.g. an MMIO peripheral register write while `var` is a
        # stack local in RAM) is categorically unrelated -- numeric
        # address comparisons alone can't tell "past the buffer" from
        # "a totally different address space" apart, so gate on region
        # membership explicitly.
        var_region = None
        if RAM_BASE <= lo < RAM_BASE + RAM_SIZE:
            var_region = (RAM_BASE, RAM_BASE + RAM_SIZE)
        elif FLASH_BASE <= lo < FLASH_BASE + FLASH_SIZE:
            var_region = (FLASH_BASE, FLASH_BASE + FLASH_SIZE)
        if var_region is not None:
            r_lo, r_hi = var_region
            if not (r_lo <= acc_lo < r_hi):
                continue

        if acc_lo < lo:

            # Access begins before the buffer even starts -- this is a
            # different piece of memory entirely, not `var` overflowing.
            continue

        if acc_hi - hi > MAX_PLAUSIBLE_OVERRUN:
            # Implausibly far past the end -- almost certainly an
            # unrelated access elsewhere in the same broad region, not
            # `var` overflowing. See MAX_PLAUSIBLE_OVERRUN above.
            continue

        if all_function_vars is not None:
            cfa = acc.frame_bases.get(owning_function)
            if _contained_in_sibling(acc_lo, acc_hi, var, all_function_vars, cfa):
                # A legitimate access to a *different* declared variable
                # (local or global) that happens to sit immediately
                # adjacent to `var` -- not `var` overflowing. cfa may be
                # None here (e.g. this access predates owning_function's
                # own entry, such as startup code zero-initializing
                # .bss); _contained_in_sibling degrades gracefully by
                # only matching global siblings in that case.
                continue

        saw_any_resolvable_access = True

        last_window = window

        if acc_hi > hi:
            kind = "write" if acc.is_write else "read"
            return BoundsOracleResult(
                verdict=Verdict.TP,
                detail=(f"Out-of-bounds {kind} at PC=0x{acc.pc:x}: accessed "
                        f"[0x{acc_lo:x}, 0x{acc_hi:x}) but '{var.name}' is only "
                        f"[0x{lo:x}, 0x{hi:x}) ({hi - lo} bytes). "
                        f"Overrun = {acc_hi - hi} bytes past the end."),
                violation=acc,
                window=window,
            )

    if not var_resolvable:
        return BoundsOracleResult(
            verdict=Verdict.INCONCLUSIVE,
            detail=(f"Could not resolve a concrete address window for variable "
                    f"'{var.name}' (owning function '{owning_function}' never "
                    f"executed during this run, so its frame base was never "
                    f"observed)."),
        )

    # var_resolvable is True but we may never have seen a single relevant
    # access to it (e.g. a bounds-checked function that returns before
    # ever touching var) -- compute its window directly for the report
    # rather than relying on last_window, which requires at least one
    # qualifying access to have been set.
    if last_window is None:
        if var.is_global:
            last_window = (var.address, var.address + (var.byte_size or 1))
        else:
            fb = run_result.entry_sp_snapshots[owning_function]
            lo = fb + var.fbreg_offset
            last_window = (lo, lo + (var.byte_size or 1))

    lo, hi = last_window
    no_access_note = "" if saw_any_resolvable_access else (
        " (in fact, no access to it was observed at all -- the flagged "
        "code path evidently returned or branched away before ever "
        "touching it)")
    return BoundsOracleResult(
        verdict=Verdict.FP,
        detail=(f"Emulated execution reached the flagged code and performed all "
                f"its accesses to '{var.name}' strictly within its actual "
                f"DWARF-recovered bounds [0x{lo:x}, 0x{hi:x}) ({hi - lo} bytes)"
                f"{no_access_note}. No out-of-bounds access was observed."),
        window=last_window,
        saw_any_access=saw_any_resolvable_access,
    )

