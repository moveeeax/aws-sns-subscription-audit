"""Command line entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .model import AwsError, severity_rank
from .report import render, sort_findings
from .rules import DEFAULT_MAX_FAILURE_RATIO, RULE_NAMES, evaluate_all

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_AWS_ERROR = 2

# CloudWatch keeps hourly datapoints for 455 days; the daily period is built from them.
MAX_METRICS_DAYS = 455


def _metrics_days(value: str) -> int:
    try:
        days = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number of days: {value}") from None
    if not 1 <= days <= MAX_METRICS_DAYS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_METRICS_DAYS}")
    return days


def _ratio(value: str) -> float:
    try:
        ratio = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {value}") from None
    if not ratio >= 0:  # also rejects nan
        raise argparse.ArgumentTypeError("must be 0 or more")
    return ratio


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
    parser.add_argument("--metrics-days", type=_metrics_days, default=0, metavar="DAYS",
                        help="read CloudWatch delivery metrics for the last DAYS days "
                             "(enables TOPIC_DELIVERY_FAILURES and TOPIC_UNUSED)")
    parser.add_argument("--max-failure-ratio", type=_ratio, default=None, metavar="RATIO",
                        help="failed deliveries per published message above which "
                             f"TOPIC_DELIVERY_FAILURES fires (default: "
                             f"{DEFAULT_MAX_FAILURE_RATIO})")
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
    if args.max_failure_ratio is not None and not args.metrics_days:
        print("error: --max-failure-ratio needs --metrics-days", file=err)
        return EXIT_AWS_ERROR
    max_failure_ratio = (DEFAULT_MAX_FAILURE_RATIO if args.max_failure_ratio is None
                         else args.max_failure_ratio)

    try:
        if session is None:
            import boto3

            session = boto3.Session(profile_name=args.profile) if args.profile \
                else boto3.Session()
        regions = resolve_regions(session, args)

        from .collect import collect

        topics, errors = collect(session, regions, set(args.topic), args.metrics_days)
    except AwsError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_AWS_ERROR
    except Exception as exc:  # credential resolution, profile typos, endpoint problems
        print(f"error: {type(exc).__name__}: {exc}", file=err)
        return EXIT_AWS_ERROR

    findings = sort_findings(evaluate_all(topics, args.show_endpoints, unknown,
                                               max_failure_ratio))
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
