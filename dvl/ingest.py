"""
Finding ingestion (prompt pipeline step 1): parse an upstream SAST
report into the normalized dvl.schema.Finding shape.

Handles the actual cwe_checker-derived report format seen in
Firmware Samples/result.json (top-level {"findings": [...]}, each with
cwe_id / addresses / description / disassembly / ai_audit), normalizing
CWE_789 -> CWE-789 and taking the first address in `addresses` as the
finding's primary address (bare-metal SAST findings from this pipeline
are single-address; multi-address findings would need a real per-tool
extension, out of scope here).
"""
from __future__ import annotations

import json
from typing import Iterable

from .schema import Finding, AddressSpace


def _normalize_cwe(raw: str) -> str:
    return raw.upper().replace("_", "-")


def load_report(path: str) -> list:
    with open(path) as f:
        data = json.load(f)
    return list(parse_findings(data))


def parse_findings(data: dict) -> Iterable[Finding]:
    findings = data.get("findings", [])
    for i, raw in enumerate(findings):
        addrs = raw.get("addresses") or []
        if not addrs:
            continue
        addr = int(addrs[0], 16) if isinstance(addrs[0], str) else int(addrs[0])

        cwe_id = _normalize_cwe(raw.get("cwe_id", ""))
        symbols = raw.get("symbols") or []
        function = symbols[0] if symbols else None

        ai_audit = raw.get("ai_audit") or {}
        confidence = float(ai_audit.get("confidence", 0.0))

        yield Finding(
            finding_id=raw.get("tids", [f"finding_{i}"])[0] if raw.get("tids") else f"finding_{i}",
            address=addr,
            space=AddressSpace.CODE,
            cwe_id=cwe_id,
            cwe_name=raw.get("cwe_name", ""),
            function=function,
            severity=raw.get("severity", ""),
            confidence=confidence,
            arch_mode=None,   # deliberately NOT trusted from upstream; re-derived downstream
            description=raw.get("description", ""),
            raw=raw,
        )
