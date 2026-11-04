"""table, json and csv renderings of the findings."""

from __future__ import annotations

import csv
import io
import json

from .model import SEVERITIES, Finding

COLUMNS = ("SEVERITY", "RULE", "REGION", "TOPIC")


def counts(findings) -> dict:
    tally = {s: 0 for s in SEVERITIES}
    for f in findings:
        tally[f.severity] += 1
    return tally


def _summary_line(findings, topics_scanned: int) -> str:
    if not findings:
        return f"no findings across {topics_scanned} topics"
    tally = counts(findings)
    parts = [f"{tally[s]} {s}" for s in SEVERITIES if tally[s]]
    return (f"{len(findings)} findings across {topics_scanned} topics "
            f"({', '.join(parts)})")


def render_table(findings, topics_scanned: int, errors=()) -> str:
    out = io.StringIO()
    if findings:
        rows = [(f.severity, f.rule, f.region, f.topic) for f in findings]
        widths = [max(len(COLUMNS[i]), max(len(r[i]) for r in rows)) for i in range(4)]
        header = "  ".join(COLUMNS[i].ljust(widths[i]) for i in range(4))
        out.write(header.rstrip() + "\n")
        for finding, row in zip(findings, rows):
            out.write("  ".join(row[i].ljust(widths[i]) for i in range(4)).rstrip() + "\n")
            out.write(f"    {finding.detail}\n")
            for target in finding.targets:
                out.write(f"      - {target}\n")
            out.write(f"    fix: {finding.remediation}\n")
            out.write("\n")
    for err in errors:
        out.write(f"warning: {err}\n")
    out.write(_summary_line(findings, topics_scanned) + "\n")
    return out.getvalue()


def render_json(findings, topics_scanned: int, errors=()) -> str:
    payload = {
        "topics_scanned": topics_scanned,
        "findings": [f.as_dict() for f in findings],
        "counts": counts(findings),
        "errors": [
            {"region": e.region, "topic": e.topic, "operation": e.operation,
             "message": e.message}
            for e in errors
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


def render_csv(findings, topics_scanned: int, errors=()) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["severity", "rule", "region", "topic", "topic_arn", "detail",
                     "targets", "remediation"])
    for f in findings:
        writer.writerow([f.severity, f.rule, f.region, f.topic, f.topic_arn, f.detail,
                         ";".join(f.targets), f.remediation])
    return buf.getvalue()


RENDERERS = {"table": render_table, "json": render_json, "csv": render_csv}


def render(fmt: str, findings, topics_scanned: int, errors=()) -> str:
    return RENDERERS[fmt](findings, topics_scanned, errors)


def sort_findings(findings) -> list[Finding]:
    order = {s: i for i, s in enumerate(SEVERITIES)}
    return sorted(findings, key=lambda f: (order[f.severity], f.region, f.topic, f.rule))
