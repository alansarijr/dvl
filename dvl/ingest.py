"""
Finding ingestion: parse an upstream SAST report into dvl.schema.Finding.

Two shapes are accepted:

- The converted pipeline report ({"findings": [...]}, as in
  Firmware Samples/result.json), with cwe_id / addresses / symbols /
  tids / ai_audit.
- Raw `cwe_checker --json` output: a top-level list whose records use
  "name": "CWE476" and print addresses in decimal ("172" == 0xac).

Only the first address of each record is used; the bare-metal findings
this tool targets are single-address.
"""
from __future__ import annotations

import json
import re
from typing import Iterable, Optional

from .schema import Finding, AddressSpace

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)
_TID_ADDR_RE = re.compile(r"instr_0x([0-9a-fA-F]+)")
_DESC_NAME_RE = re.compile(r"^\(([^)]+)\)")


def _normalize_cwe(raw: str) -> str:
    m = _CWE_RE.search(raw or "")
    return f"CWE-{m.group(1)}" if m else (raw or "").upper().replace("_", "-")


def _parse_address(value, tids: list) -> Optional[int]:
    """'0x...' and anything containing a-f is hex. Bare digits are decimal,
    which is cwe_checker's own convention, unless an 'instr_0x<hex>' tid on
    the same record says the string was meant as hex."""
    if isinstance(value, int):
        return value
    s = str(value).strip().lower()
    if not s:
        return None
    if s.startswith("0x") or any(c in "abcdef" for c in s):
        return int(s, 16)
    tid_addrs = {int(m.group(1), 16) for t in tids for m in [_TID_ADDR_RE.search(str(t))] if m}
    if int(s, 16) in tid_addrs and int(s, 10) not in tid_addrs:
        return int(s, 16)
    return int(s, 10)


def _confidence(raw: dict) -> float:
    try:
        return float((raw.get("ai_audit") or {}).get("confidence", 0.0))
    except (TypeError, ValueError):
        return 0.0


def load_report(path: str) -> list:
    with open(path) as f:
        data = json.load(f)
    return list(parse_findings(data))


def parse_findings(data) -> Iterable[Finding]:
    records = data if isinstance(data, list) else data.get("findings", [])
    seen_ids: dict = {}
    for i, raw in enumerate(records):
        tids = raw.get("tids") or []
        addrs = raw.get("addresses") or []
        if not addrs:
            continue
        addr = _parse_address(addrs[0], tids)
        if addr is None:
            continue

        finding_id = str(tids[0]) if tids else f"finding_{i}"
        n = seen_ids.get(finding_id, 0)
        seen_ids[finding_id] = n + 1
        if n:
            finding_id = f"{finding_id}#{n}"

        description = raw.get("description", "")
        cwe_name = raw.get("cwe_name") or ""
        if not cwe_name:
            m = _DESC_NAME_RE.match(description)
            cwe_name = m.group(1) if m else ""

        symbols = raw.get("symbols") or []
        yield Finding(
            finding_id=finding_id,
            address=addr,
            space=AddressSpace.CODE,
            cwe_id=_normalize_cwe(raw.get("cwe_id") or raw.get("name", "")),
            cwe_name=cwe_name,
            function=symbols[0] if symbols else None,
            severity=raw.get("severity", ""),
            confidence=_confidence(raw),
            arch_mode=None,   # deliberately NOT trusted from upstream; re-derived downstream
            description=description,
            raw=raw,
        )
