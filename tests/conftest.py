from __future__ import annotations

import json
import pathlib

import boto3
import pytest
from botocore.stub import Stubber

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


def sns_client(region: str = "eu-central-1"):
    session = boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
        region_name=region,
    )
    return session.client("sns", region_name=region)


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
    """Factory: (fixture name) -> (session, stubber) with everything queued."""
    made = []

    def build(name: str):
        data = load(name)
        client = sns_client(data["region"])
        stubber = Stubber(client)
        queue_fixture(stubber, data)
        stubber.activate()
        made.append(stubber)
        return FakeSession({"sns": client}, data["region"]), stubber

    yield build
    for stubber in made:
        stubber.deactivate()
