from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from botocore.stub import Stubber

from aws_sns_subscription_audit.collect import (
    collect,
    collect_metrics,
    collect_region,
    enabled_regions,
)
from aws_sns_subscription_audit.model import AwsError, Topic

from .conftest import FakeSession, aws_client, load, metric_query, sns_client

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


NOW = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)


def topics_named(*names):
    return [Topic(arn=f"arn:aws:sns:{REGION}:123456789012:{n}", region=REGION) for n in names]


def queries_for(names):
    out = []
    for index, name in enumerate(names):
        out.append(metric_query(f"p{index}", "NumberOfMessagesPublished", name))
        out.append(metric_query(f"f{index}", "NumberOfNotificationsFailed", name))
    return out


def test_metrics_are_summed_per_topic_and_missing_data_is_zero(stubbed):
    session, stubber = stubbed("messy", metrics=True)
    topics, errors = collect(session, [REGION], metrics_days=7)
    stubber.assert_no_pending_responses()
    assert errors == []
    by_name = {t.name: t.metrics for t in topics}
    assert by_name["jobs-fanout"].published == 1000
    assert by_name["jobs-fanout"].failed == 40
    assert by_name["jobs-fanout"].days == 7
    assert by_name["legacy-webhook"].published == 0  # no datapoints at all
    assert by_name["billing-orphan"].failed == 0


def test_no_metrics_days_never_touches_cloudwatch(stubbed):
    session, _ = stubbed("healthy")  # the session has no cloudwatch client to hand out
    topics, errors = collect(session, [REGION])
    assert errors == []
    assert topics[0].metrics is None


def test_metric_window_ends_now_and_spans_the_days():
    cloudwatch = aws_client("cloudwatch")
    stubber = Stubber(cloudwatch)
    stubber.add_response("get_metric_data", {"MetricDataResults": []},
                         {"MetricDataQueries": queries_for(["a"]),
                          "StartTime": NOW - timedelta(days=14), "EndTime": NOW})
    stubber.activate()
    topics = topics_named("a")
    errors = collect_metrics(FakeSession({"cloudwatch": cloudwatch}), REGION, topics, 14,
                             now=NOW)
    stubber.assert_no_pending_responses()
    stubber.deactivate()
    assert errors == []
    assert (topics[0].metrics.published, topics[0].metrics.failed) == (0, 0)


def test_metric_values_continuing_on_the_next_page_are_added_up():
    cloudwatch = aws_client("cloudwatch")
    stubber = Stubber(cloudwatch)
    window = {"MetricDataQueries": queries_for(["a"]),
              "StartTime": NOW - timedelta(days=7), "EndTime": NOW}
    stubber.add_response("get_metric_data", {
        "MetricDataResults": [{"Id": "p0", "Values": [10.0, 20.0], "StatusCode": "PartialData"},
                              {"Id": "f0", "Values": [1.0], "StatusCode": "PartialData"}],
        "NextToken": "page-2",
    }, window)
    stubber.add_response("get_metric_data", {
        "MetricDataResults": [{"Id": "p0", "Values": [30.0], "StatusCode": "Complete"},
                              {"Id": "f0", "Values": [2.0], "StatusCode": "Complete"}],
    }, {**window, "NextToken": "page-2"})
    stubber.activate()
    topics = topics_named("a")
    collect_metrics(FakeSession({"cloudwatch": cloudwatch}), REGION, topics, 7, now=NOW)
    stubber.assert_no_pending_responses()
    stubber.deactivate()
    assert (topics[0].metrics.published, topics[0].metrics.failed) == (60, 3)


def test_more_than_250_topics_split_into_calls_of_500_queries():
    names = [f"t{i}" for i in range(251)]
    cloudwatch = aws_client("cloudwatch")
    stubber = Stubber(cloudwatch)
    window = {"StartTime": NOW - timedelta(days=7), "EndTime": NOW}
    first = queries_for(names[:250])
    assert len(first) == 500
    stubber.add_response("get_metric_data", {"MetricDataResults": []},
                         {"MetricDataQueries": first, **window})
    stubber.add_response("get_metric_data",
                         {"MetricDataResults": [{"Id": "p0", "Values": [5.0]}]},
                         {"MetricDataQueries": queries_for(names[250:]), **window})
    stubber.activate()
    topics = topics_named(*names)
    collect_metrics(FakeSession({"cloudwatch": cloudwatch}), REGION, topics, 7, now=NOW)
    stubber.assert_no_pending_responses()
    stubber.deactivate()
    assert topics[0].metrics.published == 0
    assert topics[250].metrics.published == 5  # ids restart per call


def test_denied_metrics_are_reported_and_the_audit_keeps_the_topics(stubbed):
    data = load("healthy")
    session, _ = stubbed("healthy")
    cloudwatch = aws_client("cloudwatch")
    stubber = Stubber(cloudwatch)
    stubber.add_client_error("get_metric_data", service_error_code="AccessDenied",
                             service_message="not authorized to perform: "
                                             "cloudwatch:GetMetricData",
                             http_status_code=403)
    stubber.activate()
    session._clients["cloudwatch"] = cloudwatch
    topics, errors = collect(session, [REGION], metrics_days=7)
    stubber.deactivate()
    assert [t.arn for t in topics] == [data["topics"][0]["arn"]]
    assert topics[0].metrics is None
    assert len(errors) == 1
    assert errors[0].operation == "GetMetricData"
    assert errors[0].topic == ""
    assert str(errors[0]).startswith(f"{REGION}: GetMetricData failed: AccessDenied")


def test_no_topics_means_no_metrics_call():
    assert collect_metrics(FakeSession({}), REGION, [], 7) == []
