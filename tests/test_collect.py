from __future__ import annotations

import pytest
from botocore.stub import Stubber

from aws_sns_subscription_audit.collect import collect_region, enabled_regions
from aws_sns_subscription_audit.model import AwsError

from .conftest import FakeSession, load, sns_client

REGION = "eu-central-1"


def test_healthy_fixture_collects_one_topic_with_attributes(stubbed):
    session, stubber = stubbed("healthy")
    topics, errors = collect_region(session, REGION)
    stubber.assert_no_pending_responses()
    assert errors == []
    assert [t.name for t in topics] == ["prod-alerts"]
    assert topics[0].attributes["KmsMasterKeyId"] == "alias/aws/sns"
    assert topics[0].subscriptions[0].attributes["RedrivePolicy"]


def test_pending_subscription_never_queries_attributes(stubbed):
    """The fixture queues no GetSubscriptionAttributes for the pending pair.

    Stubber raises on any unqueued call, so a clean run is the assertion: an
    unconfirmed subscription has no ARN to address.
    """
    session, stubber = stubbed("messy")
    topics, errors = collect_region(session, REGION)
    stubber.assert_no_pending_responses()
    assert errors == []
    pending = next(t for t in topics if t.name == "oncall-email")
    assert all(s.pending for s in pending.subscriptions)
    assert all(s.attributes == {} for s in pending.subscriptions)


def test_topic_filter_skips_the_rest(stubbed):
    session, _ = stubbed("messy")
    # Only the matching topic is fetched, so the queued responses for the others
    # stay pending; that is fine, the filter is what is under test here.
    topics, _ = collect_region(session, REGION, {"billing-orphan"})
    assert [t.name for t in topics] == ["billing-orphan"]


def test_topic_filter_accepts_a_full_arn(stubbed):
    session, _ = stubbed("messy")
    data = load("messy")
    arn = data["topics"][0]["arn"]
    topics, _ = collect_region(session, REGION, {arn})
    assert [t.arn for t in topics] == [arn]


def test_denied_list_topics_raises_aws_error():
    client = sns_client()
    stubber = Stubber(client)
    stubber.add_client_error("list_topics", service_error_code="AuthorizationError",
                             service_message="User is not authorized to perform: SNS:ListTopics",
                             http_status_code=403)
    stubber.activate()
    session = FakeSession({"sns": client})
    with pytest.raises(AwsError) as excinfo:
        collect_region(session, REGION)
    stubber.deactivate()
    assert "ListTopics" in str(excinfo.value)
    assert "AuthorizationError" in str(excinfo.value)


def test_denied_topic_attributes_is_reported_and_the_scan_continues():
    data = load("messy")
    client = sns_client()
    stubber = Stubber(client)
    stubber.add_response("list_topics",
                         {"Topics": [{"TopicArn": t["arn"]} for t in data["topics"][:2]]}, {})
    first, second = data["topics"][0], data["topics"][1]
    stubber.add_client_error("get_topic_attributes", service_error_code="AuthorizationError",
                             service_message="denied", http_status_code=403)
    stubber.add_response("list_subscriptions_by_topic",
                         {"Subscriptions": first["subscriptions"]}, {"TopicArn": first["arn"]})
    stubber.add_response("get_topic_attributes", {"Attributes": second["attributes"]},
                         {"TopicArn": second["arn"]})
    stubber.add_response("list_subscriptions_by_topic",
                         {"Subscriptions": second["subscriptions"]}, {"TopicArn": second["arn"]})
    stubber.activate()
    session = FakeSession({"sns": client})
    topics, errors = collect_region(session, REGION)
    stubber.deactivate()

    assert [t.name for t in topics] == ["billing-orphan", "oncall-email"]
    assert len(errors) == 1
    assert errors[0].topic == "billing-orphan"
    assert errors[0].operation == "GetTopicAttributes"
    assert "billing-orphan" in str(errors[0])
    assert topics[1].attributes  # the second topic was still read


def test_denied_list_subscriptions_keeps_the_topic_without_subscriptions():
    data = load("messy")
    first = data["topics"][0]
    client = sns_client()
    stubber = Stubber(client)
    stubber.add_response("list_topics", {"Topics": [{"TopicArn": first["arn"]}]}, {})
    stubber.add_response("get_topic_attributes", {"Attributes": first["attributes"]},
                         {"TopicArn": first["arn"]})
    stubber.add_client_error("list_subscriptions_by_topic",
                             service_error_code="AuthorizationError",
                             service_message="denied", http_status_code=403)
    stubber.activate()
    topics, errors = collect_region(FakeSession({"sns": client}), REGION)
    stubber.deactivate()
    assert [t.name for t in topics] == ["billing-orphan"]
    assert errors[0].operation == "ListSubscriptionsByTopic"


def test_denied_subscription_attributes_is_reported_per_subscription():
    data = load("healthy")
    only = data["topics"][0]
    client = sns_client()
    stubber = Stubber(client)
    stubber.add_response("list_topics", {"Topics": [{"TopicArn": only["arn"]}]}, {})
    stubber.add_response("get_topic_attributes", {"Attributes": only["attributes"]},
                         {"TopicArn": only["arn"]})
    stubber.add_response("list_subscriptions_by_topic",
                         {"Subscriptions": only["subscriptions"]}, {"TopicArn": only["arn"]})
    stubber.add_client_error("get_subscription_attributes",
                             service_error_code="AuthorizationError",
                             service_message="denied", http_status_code=403)
    stubber.activate()
    topics, errors = collect_region(FakeSession({"sns": client}), REGION)
    stubber.deactivate()
    assert errors[0].operation == "GetSubscriptionAttributes"
    assert topics[0].subscriptions[0].attributes == {}


def test_enabled_regions_reads_ec2():
    client = sns_client()  # any client works; we stub ec2 separately
    import boto3

    ec2 = boto3.Session(aws_access_key_id="a", aws_secret_access_key="b",
                        region_name=REGION).client("ec2", region_name=REGION)
    stubber = Stubber(ec2)
    stubber.add_response("describe_regions",
                         {"Regions": [{"RegionName": "eu-west-1"},
                                      {"RegionName": "eu-central-1"}]},
                         {"AllRegions": False})
    stubber.activate()
    session = FakeSession({"ec2": ec2, "sns": client})
    assert enabled_regions(session) == ["eu-central-1", "eu-west-1"]
    stubber.deactivate()


def test_denied_describe_regions_raises_aws_error():
    import boto3

    ec2 = boto3.Session(aws_access_key_id="a", aws_secret_access_key="b",
                        region_name=REGION).client("ec2", region_name=REGION)
    stubber = Stubber(ec2)
    stubber.add_client_error("describe_regions", service_error_code="UnauthorizedOperation",
                             service_message="denied", http_status_code=403)
    stubber.activate()
    with pytest.raises(AwsError):
        enabled_regions(FakeSession({"ec2": ec2}))
    stubber.deactivate()
