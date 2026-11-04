#!/usr/bin/env python3
"""Run the audit against the recorded fixtures, with no AWS account involved.

    python examples/demo.py          # the messy account
    python examples/demo.py healthy  # the clean one

Everything goes through the real collector and the real rules; only the HTTP layer
is replaced by botocore's Stubber replaying examples/fixtures/<name>.json.
"""

from __future__ import annotations

import json
import pathlib
import sys

import boto3
from botocore.stub import Stubber

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from aws_sns_subscription_audit.cli import run  # noqa: E402

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


class FixtureSession:
    def __init__(self, client, region_name):
        self._client = client
        self.region_name = region_name

    def client(self, name, region_name=None):
        return self._client


def main() -> int:
    name = sys.argv[1] if len(sys.argv) > 1 else "messy"
    data = json.loads((FIXTURES / f"{name}.json").read_text())
    region = data["region"]

    client = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing",
                           region_name=region).client("sns", region_name=region)
    stubber = Stubber(client)
    stubber.add_response("list_topics",
                         {"Topics": [{"TopicArn": t["arn"]} for t in data["topics"]]}, {})
    for topic in data["topics"]:
        stubber.add_response("get_topic_attributes", {"Attributes": topic["attributes"]},
                             {"TopicArn": topic["arn"]})
        stubber.add_response("list_subscriptions_by_topic",
                             {"Subscriptions": topic["subscriptions"]},
                             {"TopicArn": topic["arn"]})
        for sub in topic["subscriptions"]:
            arn = sub["SubscriptionArn"]
            if arn == "PendingConfirmation":
                continue
            stubber.add_response("get_subscription_attributes",
                                 {"Attributes": topic["subscription_attributes"][arn]},
                                 {"SubscriptionArn": arn})
    stubber.activate()
    argv = ["--region", region] + sys.argv[2:]
    return run(argv, session=FixtureSession(client, region))


if __name__ == "__main__":
    raise SystemExit(main())
