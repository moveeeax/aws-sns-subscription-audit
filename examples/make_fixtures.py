#!/usr/bin/env python3
"""Regenerate the recorded API fixtures under examples/fixtures/.

The shapes match what boto3 returns for ListTopics, GetTopicAttributes,
ListSubscriptionsByTopic and GetSubscriptionAttributes; `metrics` holds the daily
CloudWatch sums GetMetricData returns for --metrics-days (a day with no activity has
no datapoint, so the lists can be shorter than the window). Nothing here talks to AWS;
the files exist so the tests can replay a realistic account offline.
"""

from __future__ import annotations

import json
import pathlib

ACCOUNT = "123456789012"
REGION = "eu-central-1"
HERE = pathlib.Path(__file__).resolve().parent / "fixtures"


def arn(name: str) -> str:
    return f"arn:aws:sns:{REGION}:{ACCOUNT}:{name}"


def policy(scoped: bool) -> str:
    statement = {
        "Sid": "__default_statement_ID",
        "Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": ["SNS:Publish", "SNS:Subscribe", "SNS:GetTopicAttributes"],
        "Resource": arn("placeholder"),
    }
    if scoped:
        statement["Condition"] = {"StringEquals": {"AWS:SourceOwner": ACCOUNT}}
    return json.dumps({"Version": "2008-10-17", "Id": "__default_policy_ID",
                       "Statement": [statement]})


def topic(name, attributes, subscriptions, sub_attributes=None, published=(), failed=()):
    return {
        "arn": arn(name),
        "attributes": attributes,
        "subscriptions": subscriptions,
        "subscription_attributes": sub_attributes or {},
        "metrics": {"published": list(published), "failed": list(failed)},
    }


def sub(topic_name, protocol, endpoint, index=1, pending=False):
    sub_arn = ("PendingConfirmation" if pending
               else f"{arn(topic_name)}:0000000{index}-1111-2222-3333-444444444444")
    return {
        "SubscriptionArn": sub_arn,
        "Owner": ACCOUNT,
        "Protocol": protocol,
        "Endpoint": endpoint,
        "TopicArn": arn(topic_name),
    }


def base_attrs(name, **over):
    attrs = {
        "TopicArn": arn(name),
        "DisplayName": name,
        "Owner": ACCOUNT,
        "SubscriptionsConfirmed": "1",
        "SubscriptionsPending": "0",
        "Policy": policy(scoped=True),
        "EffectiveDeliveryPolicy": json.dumps({"http": {"defaultHealthyRetryPolicy": {
            "numRetries": 3, "minDelayTarget": 20, "maxDelayTarget": 20}}}),
    }
    attrs.update(over)
    return attrs


HEALTHY = {
    "region": REGION,
    "topics": [
        topic(
            "prod-alerts",
            base_attrs("prod-alerts", KmsMasterKeyId="alias/aws/sns"),
            [sub("prod-alerts", "https", "https://alerts.example.com/sns", 1)],
            {f"{arn('prod-alerts')}:00000001-1111-2222-3333-444444444444": {
                "Protocol": "https",
                "Endpoint": "https://alerts.example.com/sns",
                "ConfirmationWasAuthenticated": "true",
                "RedrivePolicy": json.dumps(
                    {"deadLetterTargetArn": f"arn:aws:sqs:{REGION}:{ACCOUNT}:sns-dlq"}),
            }},
            published=[40, 52, 38, 61, 45, 30, 34],
            failed=[1],  # 1 of 300, under the default 1% threshold
        ),
    ],
}

MESSY = {
    "region": REGION,
    "topics": [
        topic(
            "billing-orphan",
            base_attrs("billing-orphan", KmsMasterKeyId="alias/aws/sns",
                       SubscriptionsConfirmed="0"),
            [],
            published=[20, 20, 20, 20, 20, 20, 20],
        ),
        topic(
            "oncall-email",
            base_attrs("oncall-email", KmsMasterKeyId="alias/aws/sns",
                       SubscriptionsConfirmed="0", SubscriptionsPending="2"),
            [
                sub("oncall-email", "email", "alice@example.com", pending=True),
                sub("oncall-email", "email", "bob@example.com", pending=True),
            ],
            published=[2, 3],
        ),
        topic(
            "legacy-webhook",
            base_attrs("legacy-webhook", Policy=policy(scoped=False)),
            [sub("legacy-webhook", "http", "http://hooks.internal.example/sns", 3)],
            {f"{arn('legacy-webhook')}:00000003-1111-2222-3333-444444444444": {
                "Protocol": "http",
                "Endpoint": "http://hooks.internal.example/sns",
                "ConfirmationWasAuthenticated": "false",
            }},
            # nothing published in the window: TOPIC_UNUSED
        ),
        topic(
            "jobs-fanout",
            base_attrs("jobs-fanout", KmsMasterKeyId="alias/aws/sns"),
            [sub("jobs-fanout", "sqs", f"arn:aws:sqs:{REGION}:{ACCOUNT}:jobs", 4)],
            {f"{arn('jobs-fanout')}:00000004-1111-2222-3333-444444444444": {
                "Protocol": "sqs",
                "Endpoint": f"arn:aws:sqs:{REGION}:{ACCOUNT}:jobs",
            }},
            published=[150, 140, 160, 155, 145, 130, 120],
            failed=[6, 4, 9, 5, 3, 7, 6],  # 40 of 1000: TOPIC_DELIVERY_FAILURES
        ),
    ],
}


def main() -> None:
    HERE.mkdir(parents=True, exist_ok=True)
    for name, data in (("healthy", HEALTHY), ("messy", MESSY)):
        path = HERE / f"{name}.json"
        path.write_text(json.dumps(data, indent=2) + "\n")
        print("wrote", path)


if __name__ == "__main__":
    main()
