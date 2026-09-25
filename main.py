#!/usr/bin/env python3
"""
DVL CLI entrypoint.

Usage:
    python3 main.py <firmware.elf> <sast_report.json> [--json out.json]

Runs the full pipeline (ingest -> capability-tier detection ->
reachability/CWE-specific oracle -> verdict) against a real SAST report
and prints both a human-readable and JSON report.
"""
import argparse
import sys

from dvl import ingest, pipeline, report


def main():
    ap = argparse.ArgumentParser(description="Dynamic Verification Layer for bare-metal SAST findings")
    ap.add_argument("binary", help="path to the firmware ELF")
    ap.add_argument("sast_report", help="path to the upstream SAST findings JSON")
    ap.add_argument("--json", help="also write the JSON report to this path")
    args = ap.parse_args()

    findings = ingest.load_report(args.sast_report)
    if not findings:
        print("No findings parsed from report.", file=sys.stderr)
        sys.exit(1)

    records = pipeline.run(args.binary, findings)

    print(report.to_human(records))

    if args.json:
        with open(args.json, "w") as f:
            f.write(report.to_json(records))
        print(f"\nJSON report written to {args.json}")


if __name__ == "__main__":
    main()
