# CLAUDE.md

Guidance for working in this repository.

## What this is

**DVL (Dynamic Verification Layer)** adjudicates bare-metal SAST findings
as **TP**, **FP**, or **Inconclusive**. It sits downstream of a bare-metal
SAST pipeline (r2pipe + cwe_checker), re-derives ground truth from the
binary itself (ARM/Thumb mode, function boundaries, buffer sizes) rather
than trusting the upstream tool, and where possible emulates the firmware
to reach and trigger the flagged bug.

Full dynamic verification targets **ARM Cortex-M** via Unicorn. Other
images get static checks only (reachability, CWE-789) and are otherwise
reported Inconclusive with a reason.

The user-facing overview lives in [README.md](README.md); the usage and
testing walkthrough is in [docs/USAGE.md](docs/USAGE.md); the original
brief is [docs/Init_prompt.md](docs/Init_prompt.md). Keep those in sync
when behavior changes.

## Environment & commands

Python **>=3.11** (uses `tomllib`). Work inside the checkout's venv.

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'   # angr is large

# Run the CLI (installed as `dvl`, or via main.py without installing)
.venv/bin/dvl firmware.elf findings.json --json report.json
.venv/bin/dvl firmware.elf findings.json --target targets/my-board.toml
.venv/bin/dvl firmware.elf findings.json --svd STM32F103.svd --svd-uart USART1
python3 main.py firmware.elf findings.json          # same CLI, no install

# Build fixture binaries (needs arm-none-eabi toolchain)
make -C fixtures/baremetal all

# Tests
.venv/bin/pytest                 # ~5 s, full suite
.venv/bin/pytest -m "not slow"   # skips angr + whole-sample runs
```

- **angr is optional** (`pip install -e '.[angr]'`). Without it, findings
  that need an input-solving step stay Inconclusive rather than failing.
- Dependency versions are **pinned** in [pyproject.toml](pyproject.toml)
  and [requirements.txt](requirements.txt) — keep them in sync. angr in
  particular breaks APIs between releases, so do not bump it casually.
- The `slow` pytest marker covers the angr path-solve fallback and whole
  sample-report runs.

## Architecture

The pipeline (`dvl/pipeline.py`) orchestrates everything and builds the
evidence record. A finding is decided in stages:

1. **Static reachability** (`callgraph.py`, `oracle_reachability.py`) —
   any image/CWE. Roots: reset handler, every vector-table slot, every
   address-taken function. Unreachable code is FP.
2. **CWE-789** (`oracle_allocsize.py`) — re-disassembles the flagged
   instruction in the ELF's mapping-symbol mode; `sub sp, sp, #N` above
   the profile threshold (default 7500) is TP.
3. **CWE-121/125/787** (emulation) — runs the firmware in Unicorn
   (`emulator_cortexm.py`) with a shadow call stack, then checks the
   trace with `oracle_bounds.py` (needs DWARF) and `oracle_retaddr.py`
   (no DWARF needed; can confirm a smash, never clear one). Inputs come
   from a generic UART payload or, as a fallback, from angr
   (`oracle_pathsolve.py`).

Module map:

- `cli.py` — argument parsing / entry point (`dvl` console script)
- `ingest.py` — converted report or raw `cwe_checker --json` → `Finding`
- `elfinfo.py` — ELF/DWARF ground truth (functions, ARM/Thumb mode,
  DWARF locals/globals incl. location lists, line table)
- `target.py`, `svd.py` — target profiles, ELF-derived defaults, SVD import
- `callgraph.py` — capstone call graph, address-taken roots, vector table
- `mmio.py` — UART / exit-register models, generic poll-breaker
- `emulator_cortexm.py` — Unicorn harness: shadow stack, access trace,
  idle/starvation stops, IRQ delivery, hijack recovery
- `oracle_*.py` — reachability, bounds, return address, alloc size, angr
- `pipeline.py` — orchestration and evidence
- `report.py`, `schema.py` — output (human + JSON)

## Conventions

- **Re-derive ground truth from the binary; don't trust the upstream
  tool.** This is the project's whole premise — mode, boundaries, and
  sizes come from the ELF/DWARF, not the SAST report.
- **Target profile fields are all optional** — every omitted field must
  fall back to an ELF-derived default (see `target.py`). Don't add a
  required profile field.
- Verdicts carry a **confidence** and an **evidence** record. When adding
  or changing a verdict path, populate evidence the same way existing
  oracles do (triggering input, call path, access trace, registers).
- An FP from an emulated run means "no violation with the inputs tried",
  not a proof for all inputs — keep verdict wording honest.

## Testing changes

Every fixture in `fixtures/baremetal/NN_*/` has a bad/good ELF pair and
an `expected.json` (flagged line + expected verdict), and each case goes
through `pipeline.adjudicate` — the same path as the CLI. When you change
adjudication logic, run the full `pytest` suite and confirm fixture
verdicts still match. If you add a scenario, add a numbered fixture with
its `expected.json` and a table row in the README.
