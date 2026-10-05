"""
Command-line entry point (installed as `dvl`, also run by main.py).

    dvl <firmware.elf> <sast_report.json> [--target profile.toml]
        [--svd device.svd [--svd-uart USART1]] [--json out.json]

Runs the pipeline against a SAST report (converted format or raw
cwe_checker JSON) and prints a human-readable report, optionally also
writing the JSON one.
"""
import argparse
import sys

from . import ingest, pipeline, report, target


def main():
    ap = argparse.ArgumentParser(description="Dynamic Verification Layer for bare-metal SAST findings")
    ap.add_argument("binary", help="path to the firmware ELF")
    ap.add_argument("sast_report", help="path to the upstream SAST findings JSON")
    ap.add_argument("--target", help="target profile (TOML, see targets/); omitted fields are derived from the ELF")
    ap.add_argument("--svd", help="CMSIS-SVD file: map its peripherals and use its UART as the input channel")
    ap.add_argument("--svd-uart", help="which SVD peripheral is the input UART (default: first UART found)")
    ap.add_argument("--json", help="also write the JSON report to this path")
    args = ap.parse_args()

    skipped: list = []
    try:
        findings = ingest.load_report(args.sast_report, skipped)
    except (OSError, ValueError) as e:
        print(f"Cannot read SAST report {args.sast_report}: {e}", file=sys.stderr)
        sys.exit(2)
    for reason in skipped:
        print(f"warning: skipped {reason}", file=sys.stderr)
    if not findings:
        if skipped:
            # Records were present but none usable: the report format is
            # wrong, which the caller needs to know about.
            print(f"No findings parsed from report: all {len(skipped)} record(s) skipped.", file=sys.stderr)
            sys.exit(1)
        # A valid report with nothing in it is a clean result, not a failure.
        print("0 findings in report; nothing to adjudicate.")
        if args.json:
            with open(args.json, "w") as f:
                f.write(report.to_json([]))
            print(f"JSON report written to {args.json}")
        return

    profile = target.load(args.target) if args.target else None
    if args.svd:
        from . import svd
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

