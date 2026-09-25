# Dynamic Verification Layer (DVL) for Bare-Metal SAST Findings

A dynamic verification layer that sits downstream of a bare-metal SAST
pipeline (r2pipe + cwe_checker) and adjudicates each static finding as
**TP**, **FP**, or **Inconclusive** by re-deriving ground truth from the
binary and, where possible, emulating the firmware to actually reach and
trigger the flagged code path.

Target tier implemented: **ARM Cortex-M3, bare-metal** (full dynamic
verification via Unicorn). Any other target/arch falls through to
static-only refutation (`EngineTier.C_STATIC_ONLY`) rather than guessing.

## Layout

```
dvl/
  schema.py              normalized Finding / VerdictRecord / Evidence / EngineTier
  elfinfo.py              ELF/DWARF ground truth: functions, ARM/Thumb mode
                          (via mapping symbols, NOT trusted from upstream),
                          DWARF locals/globals (fbreg / addr resolution)
  callgraph.py            static call-graph builder + vector-table roots
  mmio.py                 UART0/SIM peripheral model + poll-breaker
  emulator_cortexm.py     Unicorn-based Cortex-M3 harness (memory map,
                          frame-base tracking, access-trace collection)
  oracle_reachability.py  CWE-agnostic static reachability pre-filter
  oracle_bounds.py        CWE-121/125/787 trigger-verification oracle
  oracle_allocsize.py     CWE-789 oracle (constant-immediate proof +
                          instruction re-validation)
  oracle_pathsolve.py     angr-based symbolic path-solve fallback (only
                          when the generic concrete driver can't reach a
                          magic-value-gated finding) -- see below
  ingest.py               parses cwe_checker-style SAST report JSON
  pipeline.py             ties ingest -> capability detection -> oracle
  report.py               JSON + human-readable output

fixtures/baremetal/       7 bad/good ELF fixture pairs + expected.json
                          ground truth, covering every "hard problem"
                          named in the brief (see below)
run_fixtures.py           end-to-end fixture validator (11/11 passing)
main.py                   CLI: run the pipeline against a real SAST report
```

## Running

```bash
# Set up the venv (angr is a heavy dependency -- kept out of system Python)
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Rebuild all fixtures from source and validate the pipeline against them
cd fixtures/baremetal && make all && cd ../..
.venv/bin/python3 run_fixtures.py

# Run the full pipeline against the real-world sample
.venv/bin/python3 main.py "Firmware Samples/row_413_bad.arm.elf" "Firmware Samples/result.json" --json /tmp/report.json
```

angr is optional at runtime: if it isn't installed, `pipeline.py` simply
skips the symbolic path-solve fallback (see below) and falls back to its
prior Inconclusive-with-a-note behavior -- so `main.py`/`run_fixtures.py`
also work fine under plain system `python3` for anything that doesn't
need fixture 07's magic-gate case.

## Fixtures -- one per named "hard problem"

| # | Scenario | Hard problem exercised |
|---|----------|-------------------------|
| 01 | Stack buffer overflow (write) | Baseline TP/FP bounds-oracle correctness |
| 02 | Large (4096B) but constant-immediate `sub sp` | CWE-789 false-positive-by-threshold; provenance of the size operand |
| 03 | Real overflow in dead code | Static reachability filter must root at ALL entry points, not just `main()` |
| 04 | Overflow gated behind a UART `RXNE` busy-poll | "Peripheral/MMIO stubbing... biggest source of emulation hangs/false unreachability" |
| 05 | Overflow reachable ONLY via an interrupt handler | Reachability rooted at every vector-table slot, not just call-graph from `main()` |
| 06 | Out-of-bounds *read* | Read-side (not just write-side) oracle correctness |
| 07 | Overflow gated behind a magic UART byte (`gate == 0xA5`) | The generic fixed-pattern concrete driver can never satisfy an equality gate on its own -- requires the angr symbolic path-solve fallback (`oracle_pathsolve.py`) |

All 11 cases (bad+good twins where applicable) pass against
`expected.json` ground truth after a clean rebuild.

## Symbolic path-solve fallback (angr)

`pipeline.py`'s generic dynamic driver reaches every finding whose
trigger just needs "enough" input (buffer overflows via long-enough
padding), but by construction can never satisfy a finding gated behind a
*specific* value it doesn't know about, e.g. `if (cmd[0] == 0xA5) ...`.
When the concrete driver's result comes back with no relevant memory
access observed at all (the code path plausibly wasn't exercised, not
"verified safe"), `oracle_pathsolve.py` uses angr to symbolically solve
for a short input prefix (default 4 bytes) that gets past the gate, then
appends a generic 'A'-filled/newline-terminated suffix -- identical in
spirit to the plain concrete driver's own payload -- so a real loop-based
overflow still has room to actually happen once replayed. That solved
input is replayed through the same Unicorn harness + `oracle_bounds`
used everywhere else; angr never performs trigger verification itself,
it only synthesizes an input. Findings resolved this way are tagged
`EngineTier.B_partial_dynamic` / `confidence: medium` (lower than the
generic driver's `high`, since input-synthesis leans on angr's own,
separately-modeled MMIO stubbing) and carry `evidence_kind: "pathsolve"`
in the JSON report.

Scoped to reset-vector-rooted (non-IRQ) findings only, and the UART
status register is kept concrete (same poll-break-after-N-reads rule as
the Unicorn harness) rather than symbolic, specifically to avoid the
MMIO-symbolic-explosion trap called out in the Known Hard Problems below
-- only the small solved prefix is ever left as a genuine unknown for the
solver.

## Real-world sample result

`Firmware Samples/row_413_bad.arm.elf` does not match the bare-metal
Cortex-M vector-table memory layout the emulation harness targets (it's
a much larger image with a different entry/load layout), so the pipeline
correctly falls back to **static-only refutation** for its two CWE-789
findings. Independently re-disassembling the flagged addresses (using
our own ELF-mapping-symbol-derived ARM/Thumb mode, not the upstream
tool's) reveals they *are* genuine `sub sp, sp, #imm` allocation
instructions with literal immediate sizes (8 and 92 bytes) -- proving
both are compile-time constants and refuting CWE-789 with high
confidence, resolving the upstream AI-audit's own "UNCERTAIN / LOW
confidence" verdict with concrete evidence.

## Known limitations (by design, for this MVP)

- Single-arch depth (ARM Cortex-M3 Thumb); AVR/MIPS32 were evaluated and
  ruled out for this pass (tooling support gaps in Unicorn/capstone/angr
  for AVR in particular).
- Symbolic execution (angr) is scoped narrowly to a path-solve fallback
  for reset-vector-rooted findings the generic concrete driver can't
  reach (see above) -- it is not a general symbolic-execution engine,
  does not run for IRQ-only findings, and only leaves a small input
  prefix symbolic (everything else, including the UART status register,
  stays concrete) to keep it fast and bounded.
- `oracle_allocsize`'s register-operand (non-immediate) case is flagged
  Inconclusive rather than resolved via real taint analysis.
