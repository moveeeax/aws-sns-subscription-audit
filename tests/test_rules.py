from __future__ import annotations

import json

import pytest

from aws_sns_subscription_audit.model import Subscription, Topic
from aws_sns_subscription_audit.rules import (
    RULE_SEVERITY,
    evaluate,
    evaluate_all,
    mask_endpoint,
)

REGION = "eu-central-1"
ARN = f"arn:aws:sns:{REGION}:123456789012:prod-alerts"


def policy(principal, condition=None, sid="s1", effect="Allow"):
    statement = {"Sid": sid, "Effect": effect, "Principal": principal,
                 "Action": ["SNS:Publish"], "Resource": ARN}
    if condition:
        statement["Condition"] = condition
    return json.dumps({"Version": "2008-10-17", "Statement": [statement]})


def scoped_policy():
    return policy({"AWS": "*"}, {"StringEquals": {"AWS:SourceOwner": "123456789012"}})


def healthy_topic(**over):
    attrs = {"Policy": scoped_policy(), "KmsMasterKeyId": "alias/aws/sns"}
    attrs.update(over)
    sub = Subscription(
        arn=f"{ARN}:00000001-1111-2222-3333-444444444444",
        protocol="https",
        endpoint="https://alerts.example.com/sns",
        attributes={"RedrivePolicy": json.dumps({"deadLetterTargetArn": "arn:aws:sqs:x"})},
    )
    return Topic(arn=ARN, region=REGION, attributes=attrs, subscriptions=[sub])


def rules_of(topic, **kw):
    return [f.rule for f in evaluate(topic, **kw)]


def test_healthy_topic_is_silent():
    assert evaluate(healthy_topic()) == []


def test_orphan_topic_names_the_silent_drop():
    topic = Topic(arn=ARN, region=REGION,
                  attributes={"Policy": scoped_policy(), "KmsMasterKeyId": "k"})
    findings = evaluate(topic)
    assert [f.rule for f in findings] == ["TOPIC_NO_SUBSCRIPTIONS"]
    finding = findings[0]
    assert finding.severity == "high"
    assert "MessageId" in finding.detail
    assert "discarded" in finding.detail
    assert "aws sns subscribe" in finding.remediation


def test_pending_subscription_is_high_and_masked_by_default():
    topic = healthy_topic()
    topic.subscriptions = [
        Subscription(arn="PendingConfirmation", protocol="email",
                     endpoint="alice@example.com"),
        Subscription(arn="PendingConfirmation", protocol="email",
                     endpoint="bob@example.com"),
    ]
    finding = next(f for f in evaluate(topic)
                   if f.rule == "SUBSCRIPTION_PENDING_CONFIRMATION")
    assert finding.severity == "high"
    assert finding.targets == ["email:a***@example.com", "email:b***@example.com"]
    assert "no confirmed subscriber" in finding.detail
    # A topic whose only subscriptions are unconfirmed still has subscriptions,
    # so it is not also reported as an orphan.
    assert "TOPIC_NO_SUBSCRIPTIONS" not in rules_of(topic)


def test_show_endpoints_prints_addresses_in_full():
    topic = healthy_topic()
    topic.subscriptions = [Subscription(arn="PendingConfirmation", protocol="email",
                                        endpoint="alice@example.com")]
    finding = evaluate(topic, show_endpoints=True)[0]
    assert finding.targets == ["email:alice@example.com"]


@pytest.mark.parametrize("principal", ["*", {"AWS": "*"}, {"AWS": ["*", "999999999999"]}])
def test_open_policy_detected_for_every_principal_shape(principal):
    topic = healthy_topic(Policy=policy(principal))
    finding = next(f for f in evaluate(topic) if f.rule == "TOPIC_OPEN_POLICY")
    assert finding.severity == "high"
    assert finding.targets == ["s1"]
    assert "SNS:Publish" in finding.detail
    assert "aws:SourceOwner" in finding.remediation


@pytest.mark.parametrize("attrs", [
    {"Policy": policy({"AWS": "*"}, {"StringEquals": {"AWS:SourceOwner": "1"}})},
    {"Policy": policy({"AWS": "999999999999"})},
    {"Policy": policy("*", effect="Deny")},
    {"Policy": "not json at all"},
])
def test_scoped_or_unparsable_policies_are_not_flagged_open(attrs):
    topic = healthy_topic(**attrs)
    assert "TOPIC_OPEN_POLICY" not in rules_of(topic)


def test_statement_without_sid_falls_back_to_an_index():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*",
                                     "Action": "SNS:Publish"}]})
    finding = next(f for f in evaluate(healthy_topic(Policy=doc))
                   if f.rule == "TOPIC_OPEN_POLICY")
    assert finding.targets == ["statement[0]"]


def test_http_endpoint_is_medium():
    topic = healthy_topic()
    topic.subscriptions = [Subscription(arn=f"{ARN}:abc", protocol="http",
                                        endpoint="http://hooks.example/sns",
                                        attributes={"RedrivePolicy": "{}"})]
    findings = {f.rule: f for f in evaluate(topic)}
    assert findings["SUBSCRIPTION_INSECURE_ENDPOINT"].severity == "medium"
    assert findings["SUBSCRIPTION_INSECURE_ENDPOINT"].targets == ["http://hooks.example/sns"]


def test_missing_kms_key_is_medium():
    topic = healthy_topic()
    del topic.attributes["KmsMasterKeyId"]
    finding = next(f for f in evaluate(topic) if f.rule == "TOPIC_UNENCRYPTED")
    assert finding.severity == "medium"
    assert "KmsMasterKeyId" in finding.remediation


def test_unreadable_attributes_do_not_fabricate_an_encryption_finding():
    topic = healthy_topic()
    topic.attributes = {}
    assert "TOPIC_UNENCRYPTED" not in rules_of(topic)
    assert "TOPIC_OPEN_POLICY" not in rules_of(topic)


def test_missing_redrive_policy_is_low_and_only_for_confirmed_subs():
    topic = healthy_topic()
    topic.subscriptions = [
        Subscription(arn=f"{ARN}:abc", protocol="sqs", endpoint="arn:aws:sqs:x:jobs"),
        Subscription(arn="PendingConfirmation", protocol="sqs",
                     endpoint="arn:aws:sqs:x:other"),
    ]
    finding = next(f for f in evaluate(topic) if f.rule == "SUBSCRIPTION_NO_DLQ")
    assert finding.severity == "low"
    assert finding.targets == ["sqs:arn:aws:sqs:x:jobs"]


def test_email_subscription_without_redrive_is_not_a_dlq_finding():
    topic = healthy_topic()
    topic.subscriptions = [Subscription(arn=f"{ARN}:abc", protocol="email",
                                        endpoint="ops@example.com")]
    assert "SUBSCRIPTION_NO_DLQ" not in rules_of(topic)


def test_ignore_drops_the_rule():
    topic = healthy_topic()
    del topic.attributes["KmsMasterKeyId"]
    assert evaluate_all([topic], ignore=["topic_unencrypted"]) == []


@pytest.mark.parametrize("endpoint,protocol,expected", [
    ("alice@example.com", "email", "a***@example.com"),
    ("alice@example.com", "email-json", "a***@example.com"),
    ("+4915112345678", "sms", "*********5678"),
    ("https://x.example/sns", "https", "https://x.example/sns"),
    ("@example.com", "email", "***@example.com"),
    ("nodomain", "email", "***"),
])
def test_mask_endpoint(endpoint, protocol, expected):
    assert mask_endpoint(endpoint, protocol, show=False) == expected
    assert mask_endpoint(endpoint, protocol, show=True) == endpoint


def test_counts_in_details_agree_with_the_noun():
    topic = healthy_topic()
    topic.subscriptions = [Subscription(arn="PendingConfirmation", protocol="email",
                                        endpoint="a@example.com")]
    assert "1 subscription of 1 never confirmed" in evaluate(topic)[0].detail
    topic.subscriptions.append(Subscription(arn="PendingConfirmation", protocol="email",
                                            endpoint="b@example.com"))
    assert "2 subscriptions of 2 never confirmed" in evaluate(topic)[0].detail


def test_every_rule_has_a_severity():
    assert set(RULE_SEVERITY.values()) <= {"high", "medium", "low"}
