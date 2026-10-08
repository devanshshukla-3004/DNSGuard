from __future__ import annotations

import argparse

from .analyzer import analyze, summarize
from .reporter import report_dict, write_csv, write_json
from .resolver import DNSResolver


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="DNSGuard — defensive DNS security analyzer")
    p.add_argument("domain", help="Domain name to analyze, e.g. example.com")
    p.add_argument("--timeout", type=float, default=3.0, help="DNS query timeout in seconds")
    p.add_argument("--json", metavar="PATH", help="Write a JSON report")
    p.add_argument("--csv", metavar="PATH", help="Write findings to CSV")
    p.add_argument("--quiet", action="store_true", help="Suppress terminal findings")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    domain = args.domain.rstrip(".").lower()
    resolver = DNSResolver(timeout=args.timeout)
    data = resolver.collect(domain)
    findings = analyze(data)
    score, grade = summarize(findings)

    if args.json:
        write_json(args.json, report_dict(domain, data, findings, score, grade))
    if args.csv:
        write_csv(args.csv, findings)

    if not args.quiet:
        print(f"\nDNSGuard — {domain}")
        print("=" * 60)
        print(f"Security posture: {score}/100  Grade: {grade}")
        print(f"Resolver(s): {', '.join(data.resolver_nameservers)}")
        print()
        for f in findings:
            print(f"[{f.status.value:<14}] {f.severity.value:<8} {f.check_id:<16} {f.title} — {f.score}/100")
            print(f"  Evidence: {f.evidence}")
            print(f"  Fix:      {f.remediation}")
        if data.errors:
            print(f"\nDNS query errors: {len(data.errors)} (see JSON report for details)")

    return 1 if any(f.status.value == "FAIL" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
