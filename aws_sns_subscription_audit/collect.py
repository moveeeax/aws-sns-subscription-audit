"""Read every topic, subscription and attribute set out of SNS, once."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import BotoCoreError, ClientError

from .model import AwsError, CollectionError, Subscription, Topic, TopicMetrics

# GetMetricData accepts at most 500 queries per call; each topic needs two.
METRIC_QUERIES_PER_CALL = 500
METRIC_PERIOD = 86400  # one datapoint per day, summed over the window
METRIC_PUBLISHED = "NumberOfMessagesPublished"
METRIC_FAILED = "NumberOfNotificationsFailed"


def _message(err: Exception) -> str:
    if isinstance(err, ClientError):
        error = err.response.get("Error", {})
        return f"{error.get('Code', 'Error')}: {error.get('Message', '')}".strip()
    return str(err)


def enabled_regions(session) -> list[str]:
    """Regions this account has enabled, from EC2 (SNS has no such call)."""
    ec2 = session.client("ec2")
    try:
        resp = ec2.describe_regions(AllRegions=False)
    except (ClientError, BotoCoreError) as err:
        raise AwsError(f"DescribeRegions failed: {_message(err)}") from err
    return sorted(r["RegionName"] for r in resp.get("Regions", []))


def _wanted(arn: str, wanted: set[str]) -> bool:
    if not wanted:
        return True
    return arn in wanted or arn.rsplit(":", 1)[-1] in wanted


def collect_region(session, region: str, topics: set[str] | None = None):
    """Return (topics, errors) for one region.

    A failure to list topics is fatal: without the list there is nothing to audit.
    A failure on a single topic's attributes or subscriptions is recorded against
    that topic and the scan continues.
    """
    wanted = set(topics or ())
    client = session.client("sns", region_name=region)
    errors: list[CollectionError] = []

    try:
        found: list[str] = []
        for page in client.get_paginator("list_topics").paginate():
            found.extend(t["TopicArn"] for t in page.get("Topics", []))
    except (ClientError, BotoCoreError) as err:
        raise AwsError(f"ListTopics in {region} failed: {_message(err)}") from err

    collected: list[Topic] = []
    for arn in found:
        if not _wanted(arn, wanted):
            continue
        topic = Topic(arn=arn, region=region)

        try:
            topic.attributes = client.get_topic_attributes(TopicArn=arn).get("Attributes", {})
        except (ClientError, BotoCoreError) as err:
            # Reported against the topic; the remaining topics are still worth scanning.
            errors.append(CollectionError(region, topic.name, "GetTopicAttributes",
                                          _message(err)))

        try:
            pages = client.get_paginator("list_subscriptions_by_topic").paginate(TopicArn=arn)
            for page in pages:
                for raw in page.get("Subscriptions", []):
                    topic.subscriptions.append(Subscription(
                        arn=raw.get("SubscriptionArn", ""),
                        protocol=raw.get("Protocol", ""),
                        endpoint=raw.get("Endpoint", ""),
                        owner=raw.get("Owner", ""),
                    ))
        except (ClientError, BotoCoreError) as err:
            errors.append(CollectionError(region, topic.name, "ListSubscriptionsByTopic",
                                          _message(err)))
            collected.append(topic)
            continue

        for sub in topic.subscriptions:
            if sub.pending:
                continue  # no ARN exists yet, so there is nothing to query
            try:
                sub.attributes = client.get_subscription_attributes(
                    SubscriptionArn=sub.arn).get("Attributes", {})
            except (ClientError, BotoCoreError) as err:
                errors.append(CollectionError(region, topic.name, "GetSubscriptionAttributes",
                                              _message(err)))

        collected.append(topic)

    return collected, errors


def _metric_query(query_id: str, metric: str, topic_name: str) -> dict:
    return {
        "Id": query_id,
        "MetricStat": {
            "Metric": {
                "Namespace": "AWS/SNS",
                "MetricName": metric,
                "Dimensions": [{"Name": "TopicName", "Value": topic_name}],
            },
            "Period": METRIC_PERIOD,
            "Stat": "Sum",
        },
        "ReturnData": True,
    }


def collect_metrics(session, region: str, topics: list[Topic], days: int,
                    now: datetime | None = None) -> list[CollectionError]:
    """Attach published/failed sums over the last `days` days to each topic.

    SNS emits no datapoint for a day with no activity, so a metric with no values is
    a real zero, not missing data. A failed call leaves `metrics` as None on the
    topics it covered and is reported as a region-level error.
    """
    if not topics:
        return []
    end = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    start = end - timedelta(days=days)
    client = session.client("cloudwatch", region_name=region)
    errors: list[CollectionError] = []

    per_call = METRIC_QUERIES_PER_CALL // 2
    for offset in range(0, len(topics), per_call):
        batch = topics[offset:offset + per_call]
        queries: list[dict] = []
        for index, topic in enumerate(batch):
            queries.append(_metric_query(f"p{index}", METRIC_PUBLISHED, topic.name))
            queries.append(_metric_query(f"f{index}", METRIC_FAILED, topic.name))

        sums: dict[str, float] = {}
        try:
            pages = client.get_paginator("get_metric_data").paginate(
                MetricDataQueries=queries, StartTime=start, EndTime=end)
            for page in pages:
                # One query's values can continue on the next page, so sum by Id.
                for result in page.get("MetricDataResults", []):
                    sums[result["Id"]] = sums.get(result["Id"], 0.0) + \
                        sum(result.get("Values", []))
        except (ClientError, BotoCoreError) as err:
            errors.append(CollectionError(region, "", "GetMetricData", _message(err)))
            continue

        for index, topic in enumerate(batch):
            topic.metrics = TopicMetrics(days=days,
                                         published=sums.get(f"p{index}", 0.0),
                                         failed=sums.get(f"f{index}", 0.0))
    return errors


def collect(session, regions, topics=None, metrics_days: int = 0, now=None):
    """Collect across regions. Returns (topics, errors)."""
    all_topics: list[Topic] = []
    all_errors: list[CollectionError] = []
    for region in regions:
        found, errors = collect_region(session, region, topics)
        if metrics_days:
            errors.extend(collect_metrics(session, region, found, metrics_days, now))
        all_topics.extend(found)
        all_errors.extend(errors)
    return all_topics, all_errors
