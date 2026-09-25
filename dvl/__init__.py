"""
DVL -- Dynamic Verification Layer for bare-metal SAST findings.

Sits downstream of a SAST pipeline (r2pipe + cwe_checker-style tools) and
adjudicates each static finding as TP / FP / Inconclusive by re-deriving
ground truth from the binary (ISA mode, function boundaries, DWARF) and,
where possible, emulating the firmware to actually reach and trigger the
flagged code path.
"""

__version__ = "0.1.0"
