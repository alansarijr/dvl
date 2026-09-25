#!/usr/bin/env python3
"""
DVL CLI entrypoint.

Usage:
    python3 main.py <firmware.elf> <sast_report.json> [--target profile.toml]
                    [--svd device.svd [--svd-uart USART1]] [--json out.json]

Runs the full pipeline (ingest -> static reachability -> CWE-specific
oracle -> verdict) against a SAST report (converted format or raw
cwe_checker JSON) and prints a human-readable and optionally a JSON report.
"""
import argparse
import sys

from dvl import ingest, pipeline, report, target


def main():
    ap = argparse.ArgumentParser(description="Dynamic Verification Layer for bare-metal SAST findings")
    ap.add_argument("binary", help="path to the firmware ELF")
    ap.add_argument("sast_report", help="path to the upstream SAST findings JSON")
    ap.add_argument("--target", help="target profile (TOML, see targets/); omitted fields are derived from the ELF")
    ap.add_argument("--svd", help="CMSIS-SVD file: map its peripherals and use its UART as the input channel")
    ap.add_argument("--svd-uart", help="which SVD peripheral is the input UART (default: first UART found)")
    ap.add_argument("--json", help="also write the JSON report to this path")
    args = ap.parse_args()

    findings = ingest.load_report(args.sast_report)
    if not findings:
        print("No findings parsed from report.", file=sys.stderr)
        sys.exit(1)

    profile = target.load(args.target) if args.target else None
    if args.svd:
        from dvl import svd
        dev = svd.load(args.svd)
        profile = profile or target.TargetProfile(source=args.svd)
        profile.peripherals.extend(dev.ranges())
        uart = dev.uart(args.svd_uart)
        if uart is not None:
            profile.uarts.insert(0, uart)

    records = pipeline.run(args.binary, findings, profile)

    print(report.to_human(records))

    if args.json:
        with open(args.json, "w") as f:
            f.write(report.to_json(records))
        print(f"\nJSON report written to {args.json}")


if __name__ == "__main__":
    main()
