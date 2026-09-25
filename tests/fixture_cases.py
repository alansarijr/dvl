"""Loads fixtures/baremetal/*/expected.json into pipeline Findings."""
from __future__ import annotations

import functools
import json
from pathlib import Path

import capstone as cs

from dvl import elfinfo, target
from dvl.schema import AddressSpace, Finding

ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = ROOT / "fixtures" / "baremetal"
FIXTURE_PROFILE = ROOT / "targets" / "dvl-fixtures.toml"


@functools.lru_cache(maxsize=None)
def load_gt(path: str) -> elfinfo.ElfGroundTruth:
    return elfinfo.load(path)


def all_cases() -> list:
    cases = []
    for exp_path in sorted(FIXTURES_DIR.glob("*/expected.json")):
        expected = json.loads(exp_path.read_text())
        for case in expected["cases"]:
            case.setdefault("target", expected.get("target"))
            cases.append((exp_path.parent, case))
    return cases


def load_profile(fixture_dir: Path, case: dict) -> target.TargetProfile:
    """The fixture's own profile ("target" in expected.json, relative to the
    fixture) or the shared one for the synthetic fixture board."""
    path = fixture_dir / case["target"] if case.get("target") else FIXTURE_PROFILE
    return target.load(str(path))


def case_id(fixture_dir: Path, case: dict) -> str:
    return f"{fixture_dir.name}/{case['binary']}"


def _prologue_sub_sp(gt, func) -> int:
    data = gt.read_bytes(func.address, min(func.size or 64, 64))
    mode = cs.CS_MODE_THUMB if gt.mode_at(func.address) == "thumb" else cs.CS_MODE_ARM
    for insn in cs.Cs(cs.CS_ARCH_ARM, mode).disasm(data, func.address):
        if insn.mnemonic.startswith("sub") and insn.op_str.replace(" ", "").startswith("sp,"):
            return insn.address
    raise LookupError(f"no 'sub sp' in the prologue of {func.name}")


def build_finding(fixture_dir: Path, case: dict):
    """Returns (gt, Finding). The flagged address comes from the DWARF line
    table ("line": "bad.c:34") so it survives rebuilds, or from a named
    locator for cases that point at an instruction rather than a line."""
    gt = load_gt(str(fixture_dir / case["binary"]))
    func = gt.function_by_name(case["function"])
    assert func is not None, f"{case['function']} not in {case['binary']}"

    if "line" in case:
        # A stripped binary has no line table; its byte-identical debug
        # build ("debug_twin") provides the address.
        line_gt = load_gt(str((fixture_dir / case["debug_twin"]).resolve())) if "debug_twin" in case else gt
        filename, line = case["line"].rsplit(":", 1)
        address = line_gt.address_for_line(filename, int(line))
        assert address is not None, f"no code for {case['line']} in {case['binary']}"
    elif case.get("locate") == "prologue_sub_sp":
        address = _prologue_sub_sp(gt, func)
    else:
        raise KeyError(f"case for {case['function']} has no 'line' or 'locate'")

    assert func.contains(address), (
        f"{case['line'] if 'line' in case else case['locate']} resolved to 0x{address:x}, "
        f"outside {func.name} [0x{func.address:x}, 0x{func.end:x})")

    finding = Finding(
        finding_id=f"{fixture_dir.name}:{case['binary']}:{case['function']}",
        address=address,
        space=AddressSpace.CODE,
        cwe_id=case["cwe"],
        function=case["function"],
    )
    return gt, finding
