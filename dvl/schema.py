"""
Normalized schema for findings and verdicts.

Every SAST finding, regardless of which upstream tool produced it, gets
parsed into a Finding. Every Finding, after passing through the pipeline,
produces exactly one Verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class AddressSpace(str, Enum):
    """Which address space a raw integer address refers to.

    Non-Harvard architectures (ARM, MIPS, RISC-V, x86...) only ever use
    CODE/DATA interchangeably over one space; Harvard architectures (AVR,
    some DSPs) do not, and a bare address is ambiguous without this tag.
    """
    CODE = "code"
    DATA = "data"
    IO = "io"


class Verdict(str, Enum):
    TP = "TP"
    FP = "FP"
    INCONCLUSIVE = "Inconclusive"


class EngineTier(str, Enum):
    """Which capability tier actually produced the verdict.

    A = full dynamic (emulation available for this arch)
    B = partial dynamic (partial/lower-confidence emulation)
    C = static-only (no emulator for this arch; refutation only, never a
        confirmed TP)
    """
    A_FULL_DYNAMIC = "A_full_dynamic"
    B_PARTIAL_DYNAMIC = "B_partial_dynamic"
    C_STATIC_ONLY = "C_static_only"


@dataclass
class Finding:
    """A normalized SAST finding, arch-agnostic."""
    finding_id: str
    address: int
    space: AddressSpace
    cwe_id: str
    cwe_name: str = ""
    function: Optional[str] = None
    severity: str = ""
    confidence: float = 0.0
    arch_mode: Optional[str] = None       # "thumb" | "arm" | None (unknown/n-a)
    description: str = ""
    raw: dict = field(default_factory=dict)   # original upstream record, kept for audit


@dataclass
class Evidence:
    """The proof artifact backing a verdict -- concrete input, trace, path."""
    kind: str                       # "reachability" | "bounds" | "allocsize" | "recovery"
    detail: str = ""
    trace: list = field(default_factory=list)      # list of {pc, instr, ...}
    triggering_input: Optional[dict] = None
    extra: dict = field(default_factory=dict)


@dataclass
class VerdictRecord:
    finding_id: str
    verdict: Verdict
    confidence: str                 # "high" | "medium" | "low"
    engine_tier: EngineTier
    evidence: Evidence
    notes: str = ""
    ground_truth_corrections: list = field(default_factory=list)

    def to_json(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "engine_tier": self.engine_tier.value,
            "triggering_input": self.evidence.triggering_input if self.verdict == Verdict.TP else None,
            "reachability_proof": self.evidence.detail if self.verdict == Verdict.FP else None,
            "notes": self.notes,
            "evidence_kind": self.evidence.kind,
            "evidence_detail": self.evidence.detail,
            "trace": self.evidence.trace,
            "ground_truth_corrections": self.ground_truth_corrections,
        }
