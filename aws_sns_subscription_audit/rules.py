"""The checks. One finding per topic and rule, never one per endpoint."""

from __future__ import annotations

import json

from .model import Finding, Topic

RULE_SEVERITY = {
    "TOPIC_NO_SUBSCRIPTIONS": "high",
    "SUBSCRIPTION_PENDING_CONFIRMATION": "high",
    "TOPIC_OPEN_POLICY": "high",
    "TOPIC_DELIVERY_FAILURES": "high",
    "SUBSCRIPTION_INSECURE_ENDPOINT": "medium",
    "TOPIC_UNENCRYPTED": "medium",
    "SUBSCRIPTION_NO_DLQ": "low",
    "TOPIC_UNUSED": "low",
}

RULE_NAMES = tuple(RULE_SEVERITY)

# Protocols where a delivery failure is retried and then dropped without a redrive policy.
DLQ_PROTOCOLS = ("sqs", "lambda", "http", "https", "firehose")

MASKED_PROTOCOLS = ("email", "email-json", "sms")

DEFAULT_MAX_FAILURE_RATIO = 0.01


def mask_endpoint(endpoint: str, protocol: str, show: bool) -> str:
    """Hide the local part of an address so a report can be pasted into a ticket."""
    if show or protocol not in MASKED_PROTOCOLS or not endpoint:
        return endpoint
    if protocol == "sms":
        digits = [c for c in endpoint if c.isdigit()]
        return "*" * max(len(digits) - 4, 0) + "".join(digits[-4:]) if digits else "***"
    local, _, domain = endpoint.partition("@")
    if not domain:
        return "***"
    return f"{local[:1]}***@{domain}" if local else f"***@{domain}"


def _n(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _open_statements(policy_doc: str) -> list[str]:
    """Sids of Allow statements open to any principal with no Condition."""
    try:
        policy = json.loads(policy_doc)
    except (TypeError, ValueError):
        return []
    statements = policy.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]

    open_sids: list[str] = []
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition"):
            continue  # a condition is what scopes an open policy back down
        principal = statement.get("Principal")
        values: list[str] = []
        if isinstance(principal, str):
            values = [principal]
        elif isinstance(principal, dict):
            for key in ("AWS", "*"):
                entry = principal.get(key)
                if isinstance(entry, str):
                    values.append(entry)
                elif isinstance(entry, list):
                    values.extend(str(v) for v in entry)
        if "*" in values:
            open_sids.append(str(statement.get("Sid") or f"statement[{index}]"))
    return open_sids


def _actions(policy_doc: str, sids: list[str]) -> list[str]:
    try:
        policy = json.loads(policy_doc)
    except (TypeError, ValueError):
        return []
    statements = policy.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    found: list[str] = []
    for index, statement in enumerate(statements):
        sid = str(statement.get("Sid") or f"statement[{index}]")
        if sid not in sids:
            continue
        action = statement.get("Action") or []
        found.extend([action] if isinstance(action, str) else [str(a) for a in action])
    return sorted(set(found))


def _count(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:g}"


def evaluate(topic: Topic, show_endpoints: bool = False,
             max_failure_ratio: float = DEFAULT_MAX_FAILURE_RATIO) -> list[Finding]:
    """All findings for one topic, in severity-then-rule order of RULE_SEVERITY."""
    out: list[Finding] = []

    def add(rule: str, detail: str, remediation: str, targets=()) -> None:
        out.append(Finding(
            rule=rule,
            severity=RULE_SEVERITY[rule],
            region=topic.region,
            topic=topic.name,
            topic_arn=topic.arn,
            detail=detail,
            remediation=remediation,
            targets=list(targets),
        ))

    attrs = topic.attributes or {}
    subs = topic.subscriptions
    pending = [s for s in subs if s.pending]
    confirmed = [s for s in subs if not s.pending]

    if not subs:
        add(
            "TOPIC_NO_SUBSCRIPTIONS",
            "the topic has no subscriptions: a publish still returns 200 with a MessageId "
            "and the message is discarded",
            f"aws sns subscribe --region {topic.region} --topic-arn {topic.arn} "
            "--protocol https --notification-endpoint https://<receiver>",
        )

    if pending:
        add(
            "SUBSCRIPTION_PENDING_CONFIRMATION",
            f"{_n(len(pending), 'subscription')} of {len(subs)} never confirmed, "
            "delivering nothing" + ("; the topic has no confirmed subscriber at all"
                                    if not confirmed else ""),
            "resend the confirmation and have the owner accept it: "
            f"aws sns subscribe --region {topic.region} --topic-arn {topic.arn} "
            "--protocol <protocol> --notification-endpoint <endpoint>",
            targets=[f"{s.protocol}:{mask_endpoint(s.endpoint, s.protocol, show_endpoints)}"
                     for s in pending],
        )

    policy = attrs.get("Policy")
    if policy:
        sids = _open_statements(policy)
        if sids:
            actions = _actions(policy, sids)
            add(
                "TOPIC_OPEN_POLICY",
                "the access policy allows any principal with no condition"
                + (f" for {', '.join(actions)}" if actions else ""),
                f"aws sns set-topic-attributes --region {topic.region} "
                f"--topic-arn {topic.arn} --attribute-name Policy --attribute-value <policy> "
                "with aws:SourceOwner or aws:SourceArn in a Condition on each statement",
                targets=sids,
            )

    insecure = [s for s in subs if s.protocol == "http"]
    if insecure:
        add(
            "SUBSCRIPTION_INSECURE_ENDPOINT",
            f"{_n(len(insecure), 'subscription')} delivering over plaintext http",
            "re-subscribe the endpoint with --protocol https and delete the http subscription: "
            "aws sns unsubscribe --subscription-arn <arn>",
            targets=[mask_endpoint(s.endpoint, s.protocol, show_endpoints) for s in insecure],
        )

    # Only claim this when the attributes were actually read; an empty dict means the
    # GetTopicAttributes call failed, and that is already reported as a collection error.
    if attrs and not attrs.get("KmsMasterKeyId"):
        add(
            "TOPIC_UNENCRYPTED",
            "the topic has no KmsMasterKeyId, so messages are unencrypted at rest",
            f"aws sns set-topic-attributes --region {topic.region} --topic-arn {topic.arn} "
            "--attribute-name KmsMasterKeyId --attribute-value alias/aws/sns",
        )

    metrics = topic.metrics
    if metrics is not None and metrics.failed > 0:
        window = _n(metrics.days, "day")
        if metrics.published:
            ratio = metrics.failed / metrics.published
            detail = (f"{_count(metrics.failed)} failed deliveries for "
                      f"{_count(metrics.published)} published messages in the last {window} "
                      f"({ratio:.1%}, threshold {max_failure_ratio:.1%})")
        else:
            # Failures with nothing published: the publish fell just before the window.
            ratio = float("inf")
            detail = (f"{_count(metrics.failed)} failed deliveries in the last {window} "
                      "with no message published in the same window")
        if ratio > max_failure_ratio:
            add(
                "TOPIC_DELIVERY_FAILURES",
                detail,
                "turn on delivery status logging to see which subscription fails and why: "
                f"aws sns set-topic-attributes --region {topic.region} --topic-arn {topic.arn} "
                "--attribute-name <HTTP|Lambda|SQS|Firehose|Application>FailureFeedbackRoleArn "
                "--attribute-value <role-arn>",
            )

    no_dlq = [s for s in confirmed
              if s.protocol in DLQ_PROTOCOLS and not s.attributes.get("RedrivePolicy")]
    if no_dlq:
        add(
            "SUBSCRIPTION_NO_DLQ",
            f"{_n(len(no_dlq), 'confirmed subscription')} with no RedrivePolicy: a delivery "
            "that exhausts the retry policy is dropped",
            "aws sns set-subscription-attributes --subscription-arn <arn> "
            "--attribute-name RedrivePolicy --attribute-value "
            '\'{"deadLetterTargetArn":"<dlq-arn>"}\'',
            targets=[f"{s.protocol}:{mask_endpoint(s.endpoint, s.protocol, show_endpoints)}"
                     for s in no_dlq],
        )

    if metrics is not None and not metrics.published and not metrics.failed:
        add(
            "TOPIC_UNUSED",
            f"no message published in the last {_n(metrics.days, 'day')}",
            "an alarm topic can be quiet by design; otherwise check that the publisher still "
            "targets this topic, or delete it: "
            f"aws sns delete-topic --region {topic.region} --topic-arn {topic.arn}",
        )

    return out


def evaluate_all(topics, show_endpoints: bool = False, ignore=(),
                 max_failure_ratio: float = DEFAULT_MAX_FAILURE_RATIO) -> list[Finding]:
    skip = {r.strip().upper() for r in ignore if r.strip()}
    findings: list[Finding] = []
    for topic in topics:
        findings.extend(f for f in evaluate(topic, show_endpoints, max_failure_ratio)
                        if f.rule not in skip)
    return findings
