#!/usr/bin/env python3
"""Run the audit against the recorded fixtures, with no AWS account involved.

    python examples/demo.py          # the messy account
    python examples/demo.py healthy  # the clean one
    python examples/demo.py messy --metrics-days 7   # plus the CloudWatch rules

Everything goes through the real collector and the real rules; only the HTTP layer
is replaced by botocore's Stubber replaying examples/fixtures/<name>.json.
"""

from __future__ import annotations

import json
import pathlib
import sys

import boto3
from botocore.stub import ANY, Stubber

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from aws_sns_subscription_audit.cli import run  # noqa: E402

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


class FixtureSession:
    def __init__(self, clients, region_name):
        self._clients = clients
        self.region_name = region_name

    def client(self, name, region_name=None):
        return self._clients[name]


def metrics_stub(data, region):
    """A cloudwatch client answering one GetMetricData call from the fixture."""
    client = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing",
                           region_name=region).client("cloudwatch", region_name=region)
    queries, results = [], []
    for index, topic in enumerate(data["topics"]):
        name = topic["arn"].rsplit(":", 1)[-1]
        for prefix, metric, key in (("p", "NumberOfMessagesPublished", "published"),
                                    ("f", "NumberOfNotificationsFailed", "failed")):
            queries.append({
                "Id": f"{prefix}{index}",
                "MetricStat": {
                    "Metric": {"Namespace": "AWS/SNS", "MetricName": metric,
                               "Dimensions": [{"Name": "TopicName", "Value": name}]},
                    "Period": 86400,
                    "Stat": "Sum",
                },
                "ReturnData": True,
            })
            results.append({"Id": f"{prefix}{index}", "Label": metric,
                            "Values": [float(v) for v in topic["metrics"][key]],
                            "StatusCode": "Complete"})
    stubber = Stubber(client)
    stubber.add_response("get_metric_data", {"MetricDataResults": results},
                         {"MetricDataQueries": queries, "StartTime": ANY, "EndTime": ANY})
    stubber.activate()
    return client


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
    clients = {"sns": client}
    if any(a == "--metrics-days" or a.startswith("--metrics-days=") for a in sys.argv[2:]):
        clients["cloudwatch"] = metrics_stub(data, region)
    argv = ["--region", region] + sys.argv[2:]
    return run(argv, session=FixtureSession(clients, region))


if __name__ == "__main__":
    raise SystemExit(main())
