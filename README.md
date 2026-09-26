# Dynamic Verification Layer (DVL) for Bare-Metal SAST Findings

DVL sits downstream of a bare-metal SAST pipeline (r2pipe + cwe_checker)
and adjudicates each finding as **TP**, **FP** or **Inconclusive**. It
re-derives ground truth from the binary (ARM/Thumb mode, function
boundaries, buffer sizes) instead of trusting the upstream tool. Where it
can, it emulates the firmware to reach the flagged code and trigger the bug.

Full dynamic verification targets **ARM Cortex-M** (Unicorn). Other images
get static checks only (reachability, CWE-789) and are otherwise reported as
Inconclusive with the reason.

**Full usage and testing guide: [docs/USAGE.md](docs/USAGE.md).**

## Running

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'   # angr is large

# Converted pipeline report or raw `cwe_checker --json` output
.venv/bin/dvl firmware.elf findings.json --json report.json
.venv/bin/dvl firmware.elf findings.json --target targets/my-board.toml
.venv/bin/dvl firmware.elf findings.json --svd STM32F103.svd --svd-uart USART1

# Tests: every fixture goes through the same pipeline as the CLI
make -C fixtures/baremetal all
.venv/bin/pytest                 # ~5 s
.venv/bin/pytest -m "not slow"   # skips angr and whole-sample runs
```

`main.py` runs the same CLI from a checkout without installing. angr is
optional (`pip install -e '.[angr]'`): without it, findings that need an
input-solving step stay Inconclusive.

## How a finding is decided

1. **Static reachability** (`callgraph.py`, `oracle_reachability.py`),
   for any image and CWE. The entry points are the reset handler, every
   vector-table slot, and every function whose address is taken (found in
   data words, literal pools, `movw/movt`, `adr`). Unreachable functions,
   and code no path inside a live function reaches, are FP. Confidence is
   *medium* when reachable code has indirect branches.
2. **CWE-789** (`oracle_allocsize.py`): the flagged instruction is
   re-disassembled in the mode given by the ELF's mapping symbols.
   - `sub sp, sp, #N` with N above the profile threshold (7500 by
     default, as in cwe_checker) is TP (*medium*).
   - At or below the threshold it is FP.
   - A register-sized allocation, or an instruction that allocates
     nothing, is Inconclusive.
3. **CWE-121/125/787**, when the target profile allows emulation. The
   firmware runs in Unicorn (`emulator_cortexm.py`) with a shadow call
   stack, and two oracles check the trace:
   - `oracle_bounds.py` (needs DWARF): an access made while the flagged
     function is live that lands outside every live object, or that runs
     contiguously from one object into the next.
   - `oracle_retaddr.py` (for CWE-121/787; no DWARF needed): a write to a
     live frame's saved return address. It can confirm a smash, never
     clear one.

   Driving the firmware:
   - Findings reachable only through the vector table: run reset until
     the firmware idles, then deliver interrupts.
   - Everything else: run from reset with a generic UART payload.
   - If the flagged instruction never runs and the run read no input,
     that run is the program's only behavior, so the finding is FP.
     Otherwise `oracle_pathsolve.py` (angr) solves for bytes and arguments
     from the function's entry, and the replay is judged the same way
     (*medium*).

The emulator keeps going past one bug to reach the next:
- A return through a smashed LR is repaired (callee-saved registers, SP
  and PC restored from the frame's entry).
- A guard region above RAM records accesses that would bus-fault
  instead of ending the run.

Both are noted in the evidence.

## Target profiles

`targets/*.toml` describes a board: memory regions, vector table,
peripherals, the UART used for input, optional test-harness exit register,
and limits (instruction budget, CWE-789 threshold). **Every field is
optional.** Omitted fields are derived from the ELF:
- the vector table, from `.isr_vector`, known symbols, or the
  SP/reset-handler shape
- the initial SP
- flash and RAM, along the architectural Cortex-M map
- generic MMIO over the peripheral region and the PPB

`svd = "device.svd"` maps every SVD peripheral and takes the UART's
register layout from it. `targets/dvl-fixtures.toml` is the synthetic
board the fixtures use; `fixtures/baremetal/12_stm32_layout/target.toml`
shows a profile that only names an SVD.

## Evidence

Every dynamic verdict records:
- **the input**: channel, bytes, how many were consumed, generic or angr,
  and how the run was entered
- **for a violation**: the call path, the violating access with the 16
  before it (PC, function, source line), and the registers at that access,
  captured by replaying the run deterministically

Reachability FPs list the entry points, address-taken functions and
indirect branch sites considered.

## Layout

```
dvl/
  cli.py                 command line (installed as `dvl`)
  ingest.py              converted report or raw cwe_checker JSON -> Finding
  elfinfo.py             ELF/DWARF ground truth: functions, ARM/Thumb mode from
                         mapping symbols, DWARF locals/globals (incl. location
                         lists), line table
  target.py, svd.py      target profiles, ELF-derived defaults, SVD import
  callgraph.py           capstone call graph, address-taken roots, vector table,
                         intra-function reachability
  mmio.py                UART / exit-register models, generic poll-breaker
  emulator_cortexm.py    Unicorn harness: shadow call stack, access trace,
                         idle/starvation stops, IRQ delivery, hijack recovery
  oracle_*.py            reachability, bounds, return address, alloc size, angr
  pipeline.py            orchestration and evidence
  report.py, schema.py   output
fixtures/baremetal/      bad/good ELF pairs + expected.json per hard problem
targets/                 target profiles
tests/                   pytest suite
docs/Init_prompt.md      the original brief
```

## Fixtures

Each `expected.json` names the flagged line (`"line": "bad.c:34"`,
resolved through the DWARF line table so rebuilds don't break it) and the
expected verdict. Every case goes through `pipeline.adjudicate`.

| # | Scenario | What it exercises |
|---|----------|-------------------|
| 01 | Stack overflow via `mem_copy` | Baseline bounds oracle |
| 02 | Constant 4 KiB / 16 KiB frames | CWE-789 threshold, both sides |
| 03 | Overflow in an uncalled function; dead code in a live one | Reachability from all roots; intra-function walk |
| 04 | Overflow behind a UART `RXNE` poll | MMIO modeling |
| 05 | Overflow reachable only from an IRQ handler | Vector-table roots; IRQ delivery after reset |
| 06 | Out-of-bounds read | Read-side oracle; epilogue `pop` is not a read of a variable |
| 07 | Overflow behind a magic UART byte | angr path-solve fallback |
| 08 | Handler called only through a function pointer | Address-taken roots |
| 09 | Caller reuses a returned callee's stack | Frame liveness |
| 10 | Fixture 04 at `-O2` / `-Os` | DWARF location lists |
| 11 | Fixture 01 with debug info stripped | Return-address oracle without DWARF |
| 12 | Fixtures 01/04 on an STM32-like layout | ELF-derived memory map, SVD UART |

## Known limitations

- Cortex-M (Thumb) only for dynamic verification.
- The input channel is one UART. Other peripherals only get the generic
  poll-breaker, so logic that depends on real peripheral behavior may not
  be reached.
- Binaries with no symbol table at all are out of scope: function
  boundaries would need recovery first.
- An FP from a run that reached the flagged code means "no violation with
  the inputs tried", not a proof for all inputs. An FP from the angr path
  rests on one solved input.
- The bounds oracle attributes an access to the nearest object below it.
  A bug in a callee that corrupts a global while the flagged function is
  live is attributed to the flagged finding.
