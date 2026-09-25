# Dynamic Verification Layer for Bare-Metal SAST Findings

## Goal

Build a dynamic verification layer that sits downstream of a bare-metal SAST pipeline (r2pipe + cwe_checker) and adjudicates each static finding as **True Positive**, **False Positive**, or **Unreachable/Inconclusive** by emulating the firmware and attempting to actually reach and trigger the flagged code path.

## Inputs

- The raw firmware binary (bare-metal, no OS — specify target architecture: ARM Cortex-M / AVR / MIPS32, since bare-metal emulation setup differs a lot by arch)
- The SAST findings report (CWE ID, function/address, and whatever context cwe_checker emits — e.g. tainted register, call chain)
- Memory map / peripheral layout if known (MMIO regions, reset vector, interrupt vector table) — bare-metal emulation lives or dies on this

## Core Pipeline

1. **Finding ingestion** — parse the SAST output into a normalized schema: `{address, function, CWE class, confidence, associated basic block/instruction}`.

2. **Reachability analysis (static, pre-emulation filter)** — use angr to build a CFG from the reset vector and check whether the flagged address is reachable at all from any entry point (interrupt handlers included). Anything statically unreachable gets auto-classified FP without needing emulation — saves cycles.

3. **Harness/emulation setup** — use Unicorn (or angr's own engine) to emulate the target architecture, with a synthetic memory map: load the binary at its real base, stub/mock MMIO reads (peripherals, timers, UART) since bare-metal code often blocks on register polls that will hang a naive emulator.

4. **Path-driving to the finding** — either:
   - concrete/directed execution: fuzz or brute-force input space to drive control flow toward the flagged address, or
   - symbolic execution (angr) to solve for register/memory state at the finding's entry point, and directly seed emulation there for the "does the bug actually trigger" check.

5. **Trigger verification** — once execution reaches the finding, apply a CWE-specific oracle (e.g. for CWE-787/125, check if the resulting write/read is out-of-bounds relative to the buffer's actual allocated size at that point in emulated memory, not just what the static analyzer inferred).

6. **Verdict + evidence** — output a verdict per finding with the concrete input, register/memory trace, and call path that produced it. This trace is the artifact that actually proves-or-disproves the bug.

## Known Hard Problems to Design Around

- **ARM Thumb-2 mode detection** has already caused issues upstream — make sure the emulator's mode-switching matches what disassembly determined, or the same class of bug will resurface at the emulation layer.
- **Function boundary detection errors** upstream will produce wrong "reachability" answers even if angr's CFG logic is correct — garbage in, garbage out. Consider re-validating boundaries at this layer rather than trusting cwe_checker's output blindly.
- **Peripheral/MMIO stubbing** is the single biggest source of emulation hangs/false unreachability for bare-metal — decide early whether to go per-project custom stubs or reuse something like a QEMU peripheral model.

## Output Format

A structured report (JSON + human-readable) mapping each original finding to:

```json
{
  "finding_id": "...",
  "verdict": "TP | FP | Inconclusive",
  "confidence": "...",
  "triggering_input": "... (if TP)",
  "reachability_proof": "... (if FP)",
  "notes": "... (if inconclusive, what's needed for manual review)"
}
```

## Open Questions to Pin Down Before Starting

- Target architecture(s) to support first (single arch MVP vs. multi-arch from day one)
- Whether reachability filtering runs standalone (fast triage pass) before committing to full symbolic/emulation runs
- How MMIO/peripheral behavior will be modeled — hand-written stubs vs. existing emulator peripheral models
- Where this plugs into the existing AVT pipeline (post-LLM-auditor stage, or parallel/independent verification pass)