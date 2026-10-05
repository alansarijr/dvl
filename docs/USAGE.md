# DVL: Usage and Testing Guide

This guide covers installing DVL, running it on your firmware and SAST
reports, reading its output, and testing it (running the suite and adding
new test cases). For how the tool decides verdicts internally, see the
[README](../README.md).

- [1. Install](#1-install)
- [2. Quick start](#2-quick-start)
- [3. Inputs](#3-inputs)
- [4. Running the tool](#4-running-the-tool)
- [5. Target profiles](#5-target-profiles)
- [6. Reading the output](#6-reading-the-output)
- [7. Troubleshooting Inconclusive verdicts](#7-troubleshooting-inconclusive-verdicts)
- [8. Using DVL from Python](#8-using-dvl-from-python)
- [9. Testing](#9-testing)
- [10. Adding a test fixture](#10-adding-a-test-fixture)

---

## 1. Install

**Requirements**

| What | Why | Needed for |
|------|-----|------------|
| Python ≥ 3.11 | uses the standard-library `tomllib` | everything |
| Python ≥ 3.12 | the pinned `angr==9.3.2` is 3.12-only | the angr path-solve fallback |
| `arm-none-eabi-gcc` toolchain | builds the test fixtures | rebuilding fixtures only |
| `cwe_checker` | produces SAST reports | only if you generate reports yourself |

**Install into a virtual environment**

```bash
cd "Cyperpunk Dynamic"
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'     # runtime + angr + pytest + pyflakes
```

Choose an extra to match what you need:

| Command | Installs |
|---------|----------|
| `pip install -e .` | Core only (pyelftools, capstone, unicorn). Findings that need input solving stay Inconclusive. |
| `pip install -e '.[angr]'` | Core plus the angr path-solve fallback (a large download). On Python 3.11 angr is skipped and you get core only. |
| `pip install -e '.[dev]'` | Everything above, plus the test tools. |

Dependency versions are pinned in `pyproject.toml` and `requirements.txt`
to the versions the test suite runs against. angr in particular changes
its API between releases.

Installing puts a `dvl` command in `.venv/bin/`. From a checkout,
`python3 main.py …` does the same thing without installing.

---

## 2. Quick start

```bash
# 1. The bundled sample firmware and its SAST report
.venv/bin/dvl sample_firmware/gateway_fw.elf sample_firmware/gateway_fw_report.json \
    --target targets/dvl-fixtures.toml

# 2. The same run, also writing machine-readable output
.venv/bin/dvl sample_firmware/gateway_fw.elf sample_firmware/gateway_fw_report.json \
    --target targets/dvl-fixtures.toml --json report.json

# 3. The test suite
.venv/bin/pytest
```

The first command should report `TP=4  FP=2  Inconclusive=0`.

---

## 3. Inputs

### 3.1 The firmware image

DVL takes an **ELF** file. What it can do depends on what the ELF contains:

| The ELF has… | What you get |
|--------------|--------------|
| A symbol table (function symbols) | **Required.** Without function boundaries, every finding is Inconclusive. |
| DWARF debug info (`-g`) | Buffer sizes, so the bounds oracle can confirm **and** clear stack, global and read findings. Also source lines in the evidence. |
| No DWARF (debug info stripped) | Stack-overflow findings (CWE-121/787) can still be **confirmed** through return-address corruption, but not cleared. |
| A Cortex-M vector table (Thumb reset vector, initial SP in RAM) | Full dynamic verification (emulation). |
| Anything else (e.g. a Linux ARM binary) | Static checks only: reachability and CWE-789. |

To strip only the debug info (keeping symbols): `arm-none-eabi-strip --strip-debug`.

### 3.2 The SAST report

Two JSON formats are accepted, and DVL detects which one it has.

**Converted pipeline report**: a top-level object with `findings`:

```json
{
  "findings": [
    {
      "cwe_id": "CWE_121",
      "addresses": ["0x16a"],
      "symbols": ["process_uart_command"],
      "tids": ["finding_uart_cmd_overflow"],
      "description": "Unbounded write into cmd_buf",
      "ai_audit": {"confidence": 0.6}
    }
  ]
}
```

**Raw `cwe_checker --json` output**: a top-level list:

```json
[
  {"name": "CWE476", "addresses": ["172"], "tids": ["instr_0x000000ac_0_load0"],
   "symbols": [], "description": "(NULL Pointer Dereference) ..."}
]
```

Field handling:

- **Address.** Only the first entry in `addresses` is used.
  - Addresses starting with `0x`, or containing a–f, are read as hex.
  - Plain digits are read as **decimal**, which is cwe_checker's own
    convention: `"172"` is `0xac`.
  - If an `instr_0x…` tid shows the string was meant as hex, the tid wins.
- **Finding ID.** Taken from the first `tid`; duplicate IDs get `#1`, `#2`, …
- **CWE ID.** `CWE_121`, `CWE121` and `cwe-121` all normalize to `CWE-121`.
- **Skipped records.** A record with no addresses (e.g. cwe_checker's
  CWE-215 "binary has debug symbols") is ignored.

**Which CWEs are verified**

| CWE | Check |
|-----|-------|
| Any | Static reachability. Unreachable code is FP. |
| CWE-121, CWE-787 (stack/out-of-bounds write) | Emulation, bounds oracle, return-address oracle |
| CWE-125 (out-of-bounds read) | Emulation, bounds oracle |
| CWE-789 (excessive allocation) | Static stack-allocation size vs threshold |
| Others (e.g. CWE-476) | Inconclusive after the reachability check ("no verification oracle") |

---

## 4. Running the tool

```text
dvl <firmware.elf> <sast_report.json>
    [--target PROFILE.toml]
    [--svd DEVICE.svd [--svd-uart NAME]]
    [--json OUT.json]
```

| Option | Meaning |
|--------|---------|
| `--target` | A target profile (section 5). Fields it leaves out are derived from the ELF. |
| `--svd` | A CMSIS-SVD file. Every peripheral in it is mapped, and a UART from it becomes the input channel. |
| `--svd-uart` | Which SVD peripheral is the input UART (default: the first `UART`/`USART`/`LPUART` that has a recognizable status/data register layout). |
| `--json` | Also write the full JSON report. |

The human-readable report always goes to stdout.

### Choosing how to describe the board

There are three ways to tell DVL about the board, from least to most setup:

1. **No flags.** Memory map and vector table are derived from the ELF.
   Peripherals are generic: every read of the peripheral region returns
   0, then toggles after a few reads, so status polls terminate. **There is
   no input channel**, so code that waits for UART input never gets any.
   Good enough for static checks and for firmware whose bugs don't depend
   on input.
2. **`--svd`.** As above, but the SVD's peripherals are mapped, and its UART
   is modeled with real status bits (RXNE/TXE) and delivers the input
   payload. Usually the best choice for real vendor firmware:

   ```bash
   dvl firmware.elf findings.json --svd STM32F103.svd --svd-uart USART1
   ```

3. **`--target profile.toml`.** Full control: memory regions, a UART
   written out by hand, the test-harness exit register, limits, and the
   CWE-789 threshold. A profile can itself name an SVD file.

`--target` and `--svd` combine: the SVD's UART is put first, so it becomes
the input channel.

### Example: a raw cwe_checker report

```bash
cwe_checker --json --quiet firmware.elf > cc.json
dvl firmware.elf cc.json --svd device.svd
```

cwe_checker reports many CWE classes. The ones DVL has no oracle for
(CWE-476, for instance) still go through the reachability check, then come
back Inconclusive with `No verification oracle is implemented for CWE-476`.

---

## 5. Target profiles

A profile is a TOML file; see `targets/dvl-fixtures.toml` for a complete
one. **Every section is optional.**

```toml
name = "my-board"

# Optional: map these peripherals and take the input UART from the SVD.
svd = "STM32F103.svd"         # relative to this file
svd_uart = "USART1"

[[memory]]                    # repeatable; omit to derive from the ELF
name = "flash"
kind = "flash"                # "flash" or "ram"
base = 0x08000000
size = 0x00080000

[[memory]]
name = "ram"
kind = "ram"
base = 0x20000000
size = 0x00020000

[vector_table]                # omit to find it automatically
address = 0x08000000
# count = 84                  # slots incl. the initial SP; omit to scan

# initial_sp = 0x20020000     # omit to read vector table slot 0

[[peripheral]]                # repeatable; generic MMIO windows
name = "apb"
base = 0x40000000
size = 0x00030000

[[uart]]                      # the first one is the input channel
name = "USART1"
base = 0x40013800
status = 0x00                 # offset of the status register
data = 0x04                   # offset of the receive data register
# tx_data = 0x28              # offset of a separate transmit register, if any
rxne = 0x20                   # status mask: byte available
txe  = 0x80                   # status mask: transmitter ready

[sim]                         # test-harness registers (fixtures only)
exit = 0x40002000             # a write here ends the run
print = 0x40002004

[limits]
instruction_budget = 4000000  # per run
max_plausible_overrun = 4096  # bytes past a buffer still attributed to it

[cwe789]
stack_threshold = 7500        # bytes; cwe_checker's default
```

**What is derived when a field is omitted**

| Field | Derived from |
|-------|--------------|
| `vector_table` | The `.isr_vector` / `.vectors` section, a known symbol (`g_pfnVectors`, `__isr_vector`, …), or the Cortex-M shape at the lowest loaded address (initial SP, then a reset vector equal to the ELF entry) |
| `initial_sp` | Vector table slot 0 |
| `memory` | Loaded segments split along the architectural Cortex-M map: code below `0x20000000` is flash; SRAM runs from `0x20000000` up to the initial SP |
| `peripheral` | The whole peripheral region `0x40000000–0x5FFFFFFF` plus the private peripheral bus at `0xE0000000` |

**Emulation happens only if** a vector table was found, its reset vector is
a Thumb address, the initial SP is inside a RAM region, and the reset
handler is inside a mapped region. Otherwise dynamic findings come back
Inconclusive with `Not emulated: <reason>`.

---

## 6. Reading the output

### 6.1 Verdicts, confidence, tiers

| Verdict | Meaning |
|---------|---------|
| **TP** | The bug was demonstrated. For CWE-789, the flagged allocation really is over the threshold. |
| **FP** | Refuted: the code cannot run, the allocation is small, or the code ran and every access stayed in bounds. |
| **Inconclusive** | Neither could be shown. The `Notes:` line says what is missing. |

Confidence levels:

- **high**: shown directly, e.g. an emulated trace from reset, or static
  unreachability with no indirect branches in reachable code.
- **medium**: shown under an assumption:
  - an input angr solved from the function's entry rather than from reset
  - unreachability when indirect branches exist
  - a CWE-789 TP, where the real stack budget is unknown
- **low**: always paired with Inconclusive.

| Tier (`engine_tier`) | Meaning |
|----------------------|---------|
| `A_full_dynamic` | Decided from an emulated run from reset, or from interrupts after reset |
| `B_partial_dynamic` | Decided from a replay of an angr-solved input seeded at the function's entry |
| `C_static_only` | No emulation: reachability, CWE-789, or a target that can't be emulated |

| Evidence kind | Produced by |
|---------------|-------------|
| `reachability` | Static call graph / intra-function walk |
| `bounds` | DWARF bounds oracle on the emulated trace |
| `retaddr` | Saved-return-address oracle (works without DWARF) |
| `pathsolve` | angr-solved input, replayed in the emulator |
| `allocsize` | CWE-789 static check |
| `recovery` | Nothing could be checked (unsupported CWE, target not emulated) |

### 6.2 The human-readable report

```text
Finding:     cmd_overflow
Verdict:     TP  (confidence: high, tier: A_full_dynamic)
Evidence:    [bounds] [Reset driver: ... (stopped: fault).] Out-of-bounds write at PC=0x8000126
             in handle_command: accessed [...] but 'cmd' (handle_command) is only [...] (8 bytes); ...
Input:       65 bytes on USART1 (generic), 13 consumed, entered via reset handler: 'AAAA...\n'
Call path:   main -> handle_command
Source:      bad.c:34
Registers:   r0=0x00000041 ... r3=0x2001ffe8 ... sp=0x2001ffe0 lr=... pc=0x08000126
```

- **Evidence**: the driver used and how the run stopped, then the
  oracle's finding. The stop reason is one of:

  | Stop reason | Meaning |
  |-------------|---------|
  | `sim_exit` | The firmware wrote the harness exit register |
  | `returned` | The entry function returned |
  | `idle` | Reached `wfi`, `wfe` or a branch-to-self |
  | `input_exhausted` | Kept polling an empty UART |
  | `fault` | Invalid memory access or instruction |
  | `budget_exceeded` | Ran out of instructions |

- **Input**: the bytes fed to the UART and how many the firmware actually
  read (13 here: the overflow happened on the 13th byte). With angr it also
  shows the solved `r0`–`r3`.
- **Call path**: the live call stack at the violating access.
- **Source** and **Registers**: the source line of the violating
  instruction, and the registers at that exact access. The registers are
  captured by replaying the run deterministically up to that access.
- **Recovered** (when present): the run hit a smashed return address and
  DVL repaired it to keep going. Findings after that point were still
  evaluated.
- **Roots** (on a reachability FP): the entry points, address-taken
  functions and indirect branch sites that were considered.

### 6.3 The JSON report (`--json`)

A list with one object per finding:

| Key | Content |
|-----|---------|
| `finding_id`, `verdict`, `confidence`, `engine_tier` | As above |
| `triggering_input` | TP only: `channel`, `bytes`, `bytes_hex`, `consumed`, `source`, `entry`, and `args` for angr inputs |
| `reachability_proof` | FP only: the evidence text |
| `notes` | What to do next (mostly for Inconclusive) |
| `evidence_kind`, `evidence_detail` | As above |
| `call_path` | List of function names at the violation, or null |
| `trace` | The violating access and up to 16 accesses before it, made under the flagged function. Each has `pc`, `function`, `line`, `op`, `address`, `size`, `value`; the last has `"violation": true` |
| `evidence_extra` | Driver description, stop reason, `flagged_instruction_hits`, `registers_at_violation`, `violation_line`, `smashed_returns_recovered`, reachability `roots` / `address_taken_functions` / `indirect_branch_sites` |

---

## 7. Troubleshooting Inconclusive verdicts

The `Evidence:` and `Notes:` lines name the cause. The common ones:

| Message contains | Cause | What to do |
|------------------|-------|------------|
| `does not fall inside any known function's boundary` | The address isn't in any function in this ELF: wrong binary for the report, a stripped symbol table, or an upstream address error | Check that the report matches the ELF. Look at `arm-none-eabi-objdump -d` around the address. |
| `Not emulated: no Cortex-M vector table was found` | Not a Cortex-M image, or the vector table isn't where it's expected | Add `[vector_table] address = …` to a profile |
| `Not emulated: the initial SP does not fall inside a RAM region` | RAM derived wrongly, or unusual RAM placement | Add `[[memory]]` entries to a profile |
| `The flagged instruction ... never executed (input_exhausted ...)` | The firmware waited for more input, or for input on a channel DVL doesn't model | Give it the right UART (`--svd` / `[[uart]]`). Check which peripheral the code actually reads. |
| `never executed (budget_exceeded ...)` | Stuck in a loop the models don't break (often a peripheral status poll) | Map that peripheral (`--svd` or `[[peripheral]]`), or raise `instruction_budget` |
| `never executed ... angr path-solve fallback found no input` | The trigger condition is beyond the generic payload and a 4-byte solved prefix | Manual review, or install angr if it isn't installed (`pip install -e '.[angr]'`) |
| `there are no DWARF-described objects` | No debug info, and the return address was intact | Build with `-g` if you can; otherwise review by hand |
| `No verification oracle is implemented for CWE-…` | Unsupported CWE class | Manual review (reachability was still checked) |
| `not a stack allocation` (CWE-789) | The upstream address or ARM/Thumb mode is wrong | Look for the real `sub sp` nearby in the disassembly |

---

## 8. Using DVL from Python

```python
from dvl import elfinfo, ingest, pipeline, report, target
from dvl.schema import AddressSpace, Finding

# Whole report
findings = ingest.load_report("findings.json")
profile = target.load("targets/my-board.toml")        # or None to derive everything
records = pipeline.run("firmware.elf", findings, profile)
print(report.to_human(records))

# One hand-made finding
gt = elfinfo.load("firmware.elf")
addr = gt.address_for_line("uart.c", 42)               # needs DWARF
rec = pipeline.adjudicate(gt, Finding("f1", addr, AddressSpace.CODE, "CWE-121"), profile)
print(rec.verdict, rec.to_json()["call_path"])
```

---

## 9. Testing

### 9.1 Running the suite

```bash
.venv/bin/pytest                    # everything, ~5 seconds
.venv/bin/pytest -m "not slow"      # skip angr cases and whole-sample runs
.venv/bin/pytest -k 08_fnptr -v     # one fixture
.venv/bin/pytest tests/test_ingest.py
.venv/bin/python3 -m pyflakes dvl tests main.py   # lint
```

When a fixture case fails, the assertion message shows
`[tier/evidence_kind] evidence detail`, which is the same text the CLI
would print.

### 9.2 What the tests cover

| File | Tests |
|------|-------|
| `tests/test_fixtures.py` | Every case in every `fixtures/baremetal/*/expected.json`, run through `pipeline.adjudicate` (the CLI's code path). Checks the verdict, plus confidence and tier when the case specifies them. |
| `tests/test_samples.py` | End-to-end runs of the two sample reports (`sample_firmware/`, `Firmware Samples/`), including completeness of the TP evidence |
| `tests/test_ingest.py` | Both report formats, decimal vs hex addresses, duplicate IDs |
| `tests/test_target.py` | Memory map and vector-table derivation, SVD parsing (including `derivedFrom`), MMIO window merging, poll-breaker behavior |

Tests marked `slow` run angr or a whole report.

### 9.3 The fixtures

`fixtures/baremetal/` holds small C programs, each built as a buggy
`bad.elf` and (usually) a fixed `good.elf`. Each one isolates one hard
problem:

| # | Scenario |
|---|----------|
| 01 | Stack overflow via `mem_copy` |
| 02 | Constant 4 KiB (FP) and 16 KiB (TP) stack frames, CWE-789 |
| 03 | Overflow in a never-called function; dead code inside a live function |
| 04 | Overflow behind a UART poll loop |
| 05 | Overflow reachable only from an interrupt handler |
| 06 | Out-of-bounds read |
| 07 | Overflow behind a magic byte (needs angr) |
| 08 | Handler called only through a function pointer |
| 09 | A caller reusing a returned function's stack |
| 10 | Fixture 04 built with `-O2` / `-Os` |
| 11 | Fixture 01 with debug info stripped |
| 12 | Fixtures 01/04 on an STM32-like layout, with an SVD |

The compiled `.elf` files are committed, so the tests run without an ARM
toolchain. To rebuild everything from source:

```bash
make -C fixtures/baremetal all       # only rebuilds what changed
make -C fixtures/baremetal -B all    # force a full rebuild
.venv/bin/pytest
```

The shared board is described in `fixtures/baremetal/common/`:
`startup.s` (vector table), `linker.ld` (memory map) and `mmio.h` (UART and
exit register). `targets/dvl-fixtures.toml` is the matching target profile.

### 9.4 Testing on a new board

To check DVL against your own hardware before trusting it on real reports:

1. Build one of the fixture sources (01 and 04 are good choices) with your
   linker script and your UART's address and bits:
   `-DUART0_BASE=… '-DUART_SR_RXNE=(1U << n)' '-DUART_SR_TXE=(1U << m)'`.
   Fixture 12's Makefile is a worked example. `mmio.h` assumes the status
   register at offset 0 and the data register at offset 4, so adjust it if
   your UART differs.
2. Write a profile, or pass `--svd`, and add the pair as a fixture
   (section 10) with `"target"` pointing at the profile.
3. `bad` should come back TP and `good` FP. If they don't, the profile is
   usually the cause (see section 7).

---

## 10. Adding a test fixture

**1. Create the directory and sources.** For example
`fixtures/baremetal/13_my_case/bad.c` and `good.c`:

```c
#include "mmio.h"

__attribute__((noinline))
void parse(void)
{
    char buf[8];
    for (int i = 0; i < 16; i++) {
        buf[i] = uart_getc();      /* BUG: no bound check */
    }
    uart_putc(buf[0]);
}

int main(void)
{
    parse();
    sim_exit(0);                   /* ends the emulated run cleanly */
    return 0;
}
```

Useful helpers from `common/mmio.h`: `uart_getc()`, `uart_putc()`,
`mem_copy()` and `sim_exit()`. Mark functions under test `noinline` so
they keep their own symbol and frame.

**2. Add a `Makefile`:**

```make
include ../common/Makefile.inc

all: bad.elf good.elf

clean: clean-common
```

Also add the directory to `DIRS` in `fixtures/baremetal/Makefile`. Then
build:

```bash
make -C fixtures/baremetal 13_my_case
```

**3. Write `expected.json`:**

```json
{
  "fixture": "13_my_case",
  "description": "What hard problem this isolates.",
  "cases": [
    {
      "binary": "bad.elf",
      "function": "parse",
      "line": "bad.c:8",
      "cwe": "CWE-121",
      "expected_verdict": "TP",
      "expected_confidence": "high",
      "reason": "Why this is the right answer."
    }
  ]
}
```

| Key | Required | Meaning |
|-----|----------|---------|
| `binary` | yes | ELF in this fixture directory |
| `function` | yes | The function containing the finding (checked against the resolved address) |
| `line` | one of `line` / `locate` | `file.c:N`; the finding's address is the first instruction of that line, from the DWARF line table |
| `locate` | one of `line` / `locate` | `"prologue_sub_sp"`: the function's `sub sp` instruction (for CWE-789) |
| `debug_twin` | no | For a stripped binary: a path (relative to the fixture) to its byte-identical debug build, used to resolve `line` |
| `cwe` | yes | `CWE-121`, `CWE-125`, `CWE-787` or `CWE-789` |
| `expected_verdict` | yes | `TP`, `FP` or `Inconclusive` |
| `expected_confidence` | no | Asserted when present |
| `expected_engine_tier` | no | Asserted when present. `B_partial_dynamic` also marks the case `slow`. |
| `xfail` | no | A known-wrong case: the text says why. The test is a *strict* expected failure, so it fails once the bug is fixed, reminding you to remove the marker. |
| `target` (top level) | no | Profile path relative to the fixture. Default: `targets/dvl-fixtures.toml`. |

**4. Run it:**

```bash
.venv/bin/pytest -k 13_my_case -v
```

**5. Commit** the sources, `Makefile`, `expected.json` and the built `.elf`
files. The `.map` and `.lst` build outputs are git-ignored.

To reproduce a real-world false verdict, first build the smallest program
that shows it, then add it as a fixture with `xfail` describing the problem.
Remove the `xfail` once it's fixed.

## Exit codes and empty reports

| Exit | Meaning |
|---|---|
| 0 | Ran to completion. A valid report with **zero findings** also exits 0 and (with `--json`) writes `[]`. |
| 1 | The report had records but none were usable (e.g. no `addresses`), or its shape was unrecognized. Per-record reasons are printed to stderr as `warning: skipped ...`. |
| 2 | The report file could not be read or is not valid JSON. |

Accepted report shapes: a top-level list, or an object with the list under
`findings` (also `results`, `report`, `data`). A record's address comes from
`addresses[0]`, or a singular `address`.
