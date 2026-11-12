from __future__ import annotations

import json
import pathlib

import boto3
import pytest
from botocore.stub import ANY, Stubber

FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "examples" / "fixtures"


def load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


class FakeSession:
    """Hands out the pre-stubbed clients instead of opening real ones."""

    def __init__(self, clients: dict, region_name: str = "eu-central-1"):
        self._clients = clients
        self.region_name = region_name

    def client(self, name: str, region_name: str | None = None):
        return self._clients[name]


def aws_client(service: str, region: str = "eu-central-1"):
    session = boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
        region_name=region,
    )
    return session.client(service, region_name=region)


def sns_client(region: str = "eu-central-1"):
    return aws_client("sns", region)


def metric_query(query_id: str, metric: str, topic_name: str) -> dict:
    return {
        "Id": query_id,
        "MetricStat": {
            "Metric": {
                "Namespace": "AWS/SNS",
                "MetricName": metric,
                "Dimensions": [{"Name": "TopicName", "Value": topic_name}],
            },
            "Period": 86400,
            "Stat": "Sum",
        },
        "ReturnData": True,
    }


def queue_metrics(stubber: Stubber, data: dict) -> None:
    """One GetMetricData call: published and failed per topic, in topic order."""
    queries, results = [], []
    for index, topic in enumerate(data["topics"]):
        name = topic["arn"].rsplit(":", 1)[-1]
        for prefix, metric, key in (("p", "NumberOfMessagesPublished", "published"),
                                    ("f", "NumberOfNotificationsFailed", "failed")):
            queries.append(metric_query(f"{prefix}{index}", metric, name))
            results.append({"Id": f"{prefix}{index}", "Label": metric,
                            "Values": [float(v) for v in topic["metrics"][key]],
                            "StatusCode": "Complete"})
    stubber.add_response(
        "get_metric_data",
        {"MetricDataResults": results},
        {"MetricDataQueries": queries, "StartTime": ANY, "EndTime": ANY},
    )


def queue_fixture(stubber: Stubber, data: dict) -> None:
    """Queue responses in exactly the order the collector issues the calls."""
    region = data["region"]
    stubber.add_response(
        "list_topics",
        {"Topics": [{"TopicArn": t["arn"]} for t in data["topics"]]},
        {},
    )
    for topic in data["topics"]:
        stubber.add_response(
            "get_topic_attributes",
            {"Attributes": topic["attributes"]},
            {"TopicArn": topic["arn"]},
        )
        stubber.add_response(
            "list_subscriptions_by_topic",
            {"Subscriptions": topic["subscriptions"]},
            {"TopicArn": topic["arn"]},
        )
        for sub in topic["subscriptions"]:
            arn = sub["SubscriptionArn"]
            if arn == "PendingConfirmation":
                continue  # the collector must not ask for attributes it cannot address
            stubber.add_response(
                "get_subscription_attributes",
                {"Attributes": topic["subscription_attributes"][arn]},
                {"SubscriptionArn": arn},
            )
    assert region  # fixtures always pin a region


@pytest.fixture
def stubbed():
    """Factory: (fixture name) -> (session, stubber) with everything queued.

    With metrics=True a cloudwatch client is stubbed too, with the fixture's
    GetMetricData response queued for --metrics-days.
    """
    made = []

    def build(name: str, metrics: bool = False):
        data = load(name)
        client = sns_client(data["region"])
        stubber = Stubber(client)
        queue_fixture(stubber, data)
        stubber.activate()
        made.append(stubber)
        clients = {"sns": client}
        if metrics:
            cloudwatch = aws_client("cloudwatch", data["region"])
            cw_stubber = Stubber(cloudwatch)
            queue_metrics(cw_stubber, data)
            cw_stubber.activate()
            made.append(cw_stubber)
            clients["cloudwatch"] = cloudwatch
        return FakeSession(clients, data["region"]), stubber

    yield build
    for stubber in made:
        stubber.deactivate()
