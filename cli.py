#!/usr/bin/env python3

import argparse
import json
from typing import List

from scanner import parse_ports, scan_multiple_hosts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyportscan",
        description="A simple threaded TCP port scanner in Python for authorized security testing.",
    )

    parser.add_argument(
        "-t",
        "--targets",
        nargs="+",
        required=True,
        help="Target host(s) to scan (IP or hostname).",
    )

    parser.add_argument(
        "-p",
        "--ports",
        required=True,
        help='Ports to scan, e.g. "80", "80,443,8080", "1-1024", "22,80,8000-8100".',
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout in seconds for each connection (default: 1.0).",
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of concurrent threads per host (default: 100).",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Write JSON results to the given file.",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output.",
    )

    return parser


def print_human_readable(result: dict, verbose: bool = False) -> None:
    print("=" * 60)
    print(f"Target: {result['target']} ({result['resolved_ip']})")

    open_ports = [r for r in result["results"] if r["open"]]

    if not open_ports:
        print("No open TCP ports found.")
        return

    print("Open ports:")
    for r in open_ports:
        line = f"  - {r['port']}/tcp open"
        if r["banner"]:
            line += f" | banner: {r['banner']}"
        print(line)

    if verbose:
        closed_count = sum(1 for r in result["results"] if not r["open"])
        print(f"\nScanned ports: {len(result['results'])} total")
        print(f"Open: {len(open_ports)}, Closed/Filtered: {closed_count}")


def main(argv: List[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        parser.error(f"Invalid ports specification: {e}")

    if not ports:
        parser.error("No valid ports to scan after parsing.")

    if args.verbose:
        print(f"[+] Targets: {args.targets}")
        print(f"[+] Ports: {ports[0]}..{ports[-1]} (total {len(ports)})")
        print(f"[+] Timeout: {args.timeout}s | Threads: {args.threads}")

    combined = scan_multiple_hosts(
        targets=args.targets,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
    )

    for host_result in combined["targets"]:
        print_human_readable(host_result, verbose=args.verbose)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(combined, f, indent=2)
            if args.verbose:
                print(f"[+] Results written to {args.output}")
        except OSError as e:
            print(f"[!] Failed to write output file: {e}")


if __name__ == "__main__":
    main()
