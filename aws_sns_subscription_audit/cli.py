"""Command line entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .model import AwsError, severity_rank
from .report import render, sort_findings
from .rules import RULE_NAMES, evaluate_all

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_AWS_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-sns-subscription-audit",
        description="Audit SNS topics and subscriptions for alerting paths that "
                    "cannot deliver.",
        epilog="rules: " + ", ".join(RULE_NAMES),
    )
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--region", action="append", default=[], metavar="REGION",
                        help="region to scan (repeatable)")
    parser.add_argument("--all-regions", action="store_true",
                        help="scan every region enabled for the account")
    parser.add_argument("--topic", action="append", default=[], metavar="NAME_OR_ARN",
                        help="limit to this topic (repeatable)")
    parser.add_argument("--format", choices=("table", "json", "csv"), default="table")
    parser.add_argument("--fail-on", choices=("high", "medium", "low", "never"),
                        default="high", help="lowest severity that exits 1 (default: high)")
    parser.add_argument("--ignore", default="", metavar="RULE,RULE",
                        help="comma separated rules to drop from output and exit code")
    parser.add_argument("--show-endpoints", action="store_true",
                        help="print email and sms endpoints unmasked")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def resolve_regions(session, args) -> list[str]:
    from .collect import enabled_regions

    if args.all_regions:
        return enabled_regions(session)
    if args.region:
        seen: list[str] = []
        for region in args.region:
            if region not in seen:
                seen.append(region)
        return seen
    if session.region_name:
        return [session.region_name]
    raise AwsError("no region: pass --region, --all-regions or set AWS_DEFAULT_REGION")


def run(argv=None, session=None, stdout=None, stderr=None) -> int:
    args = build_parser().parse_args(argv)
    out = stdout or sys.stdout
    err = stderr or sys.stderr

    unknown = [r.strip().upper() for r in args.ignore.split(",") if r.strip()]
    for rule in unknown:
        if rule not in RULE_NAMES:
            print(f"error: unknown rule in --ignore: {rule}", file=err)
            return EXIT_AWS_ERROR

    try:
        if session is None:
            import boto3

            session = boto3.Session(profile_name=args.profile) if args.profile \
                else boto3.Session()
        regions = resolve_regions(session, args)

        from .collect import collect

        topics, errors = collect(session, regions, set(args.topic))
    except AwsError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_AWS_ERROR
    except Exception as exc:  # credential resolution, profile typos, endpoint problems
        print(f"error: {type(exc).__name__}: {exc}", file=err)
        return EXIT_AWS_ERROR

    findings = sort_findings(evaluate_all(topics, args.show_endpoints, unknown))
    out.write(render(args.format, findings, len(topics), errors))

    if args.format != "table":
        for error in errors:
            print(f"warning: {error}", file=err)

    if args.fail_on == "never":
        return EXIT_CLEAN
    threshold = severity_rank(args.fail_on)
    if any(severity_rank(f.severity) >= threshold for f in findings):
        return EXIT_FINDINGS
    return EXIT_CLEAN


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
