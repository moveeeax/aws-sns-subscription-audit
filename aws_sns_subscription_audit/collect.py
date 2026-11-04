"""Read every topic, subscription and attribute set out of SNS, once."""

from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from .model import AwsError, CollectionError, Subscription, Topic

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


def collect(session, regions, topics=None):
    """Collect across regions. Returns (topics, errors)."""
    all_topics: list[Topic] = []
    all_errors: list[CollectionError] = []
    for region in regions:
        found, errors = collect_region(session, region, topics)
        all_topics.extend(found)
        all_errors.extend(errors)
    return all_topics, all_errors
