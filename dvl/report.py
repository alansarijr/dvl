"""
Output formatting (prompt "Output Format" section): a structured report
(JSON + human-readable) mapping each original finding to its verdict,
confidence, evidence, and (for inconclusive verdicts) what's needed for
manual review.
"""
from __future__ import annotations

import json

from .schema import VerdictRecord, Verdict


def to_json(records: list) -> str:
    return json.dumps([r.to_json() for r in records], indent=2)


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
        lines.append("-" * 72)
        lines.append(f"Finding:     {r.finding_id}")
        lines.append(f"Verdict:     {r.verdict.value}  (confidence: {r.confidence}, "
                     f"tier: {r.engine_tier.value})")
        lines.append(f"Evidence:    [{r.evidence.kind}] {r.evidence.detail}")
        if r.notes:
            lines.append(f"Notes:       {r.notes}")
    lines.append("-" * 72)
    return "\n".join(lines)
