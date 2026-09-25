"""
Output formatting: a JSON report and a human-readable one mapping each
finding to its verdict, confidence and evidence (input, call path and
access trace for dynamic verdicts; what is needed for manual review for
Inconclusive ones).
"""
from __future__ import annotations

import json

from .schema import Verdict

_MAX_INPUT_SHOWN = 72


def to_json(records: list) -> str:
    return json.dumps([r.to_json() for r in records], indent=2)


def _input_line(inp: dict) -> str:
    raw = inp["bytes"]
    shown = raw if len(raw) <= _MAX_INPUT_SHOWN else raw[:_MAX_INPUT_SHOWN] + "..."
    where = f" on {inp['channel']}" if inp.get("channel") else ""
    args = f", args r0-r3=({', '.join(inp['args'])})" if inp.get("args") else ""
    return (f"{len(raw)} bytes{where} ({inp['source']}), {inp['consumed']} consumed, "
            f"entered via {inp['entry']}{args}: {shown!r}")


def to_human(records: list) -> str:
    lines = []
    counts = {Verdict.TP: 0, Verdict.FP: 0, Verdict.INCONCLUSIVE: 0}
    for r in records:
        counts[r.verdict] += 1

    lines.append("=" * 72)
    lines.append("Dynamic Verification Layer -- Adjudication Report")
    lines.append("=" * 72)
    lines.append(f"Total findings: {len(records)}   "
                 f"TP={counts[Verdict.TP]}  FP={counts[Verdict.FP]}  "
                 f"Inconclusive={counts[Verdict.INCONCLUSIVE]}")
    lines.append("")

    for r in records:
        ev = r.evidence
        extra = ev.extra or {}
        lines.append("-" * 72)
        lines.append(f"Finding:     {r.finding_id}")
        lines.append(f"Verdict:     {r.verdict.value}  (confidence: {r.confidence}, "
                     f"tier: {r.engine_tier.value})")
        lines.append(f"Evidence:    [{ev.kind}] {ev.detail}")
        if r.verdict == Verdict.TP and ev.triggering_input:
            lines.append(f"Input:       {_input_line(ev.triggering_input)}")
        if extra.get("call_path"):
            lines.append(f"Call path:   {' -> '.join(extra['call_path'])}")
        if extra.get("violation_line"):
            lines.append(f"Source:      {extra['violation_line']}")
        if extra.get("registers_at_violation"):
            regs = extra["registers_at_violation"]
            lines.append("Registers:   " + " ".join(f"{k}={v}" for k, v in regs.items()))
        if extra.get("smashed_returns_recovered"):
            funcs = ", ".join(x["function"] for x in extra["smashed_returns_recovered"])
            lines.append(f"Recovered:   smashed return(s) in {funcs}; the run continued past them")
        if ev.kind == "reachability" and extra.get("roots") is not None:
            lines.append(f"Roots:       {len(extra['roots'])} entry points, "
                         f"{extra['address_taken_functions']} address-taken functions, "
                         f"{len(extra['indirect_branch_sites'])} indirect branch sites in reachable code")
        if r.notes:
            lines.append(f"Notes:       {r.notes}")
    lines.append("-" * 72)
    return "\n".join(lines)
