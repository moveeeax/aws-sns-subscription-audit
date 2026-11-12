"""Data shapes shared by the collector, the rules and the report."""

from __future__ import annotations

from dataclasses import dataclass, field

PENDING = "PendingConfirmation"

SEVERITIES = ("high", "medium", "low")
_ORDER = {"high": 3, "medium": 2, "low": 1, "never": 0}


def severity_rank(name: str) -> int:
    return _ORDER[name]


@dataclass
class Subscription:
    arn: str
    protocol: str
    endpoint: str
    owner: str = ""
    attributes: dict = field(default_factory=dict)

    @property
    def pending(self) -> bool:
        # An unconfirmed subscription has the literal string where its ARN belongs,
        # so there is nothing to call GetSubscriptionAttributes with.
        return self.arn == PENDING


@dataclass
class TopicMetrics:
    """CloudWatch sums for one topic over the --metrics-days window."""

    days: int
    published: float = 0.0
    failed: float = 0.0


@dataclass
class Topic:
    arn: str
    region: str
    attributes: dict = field(default_factory=dict)
    subscriptions: list[Subscription] = field(default_factory=list)
    # None when metrics were not requested or could not be read; the metric rules
    # only run on topics that actually have numbers.
    metrics: TopicMetrics | None = None

    @property
    def name(self) -> str:
        return self.arn.rsplit(":", 1)[-1]

    @property
    def is_fifo(self) -> bool:
        return self.name.endswith(".fifo")


@dataclass
class CollectionError:
    region: str
    topic: str
    operation: str
    message: str

    def __str__(self) -> str:
        where = f"{self.region} {self.topic}" if self.topic else self.region
        return f"{where}: {self.operation} failed: {self.message}"


@dataclass
class Finding:
    rule: str
    severity: str
    region: str
    topic: str
    topic_arn: str
    detail: str
    remediation: str
    targets: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "region": self.region,
            "topic": self.topic,
            "topic_arn": self.topic_arn,
            "detail": self.detail,
            "targets": list(self.targets),
            "remediation": self.remediation,
        }


class AwsError(Exception):
    """A credential or API failure that makes the scan meaningless (exit 2)."""
