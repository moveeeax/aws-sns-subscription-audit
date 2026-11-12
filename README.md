# aws-sns-subscription-audit

[![ci](https://github.com/moveeeax/aws-sns-subscription-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-sns-subscription-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Finds the SNS topics and subscriptions that accept a publish and deliver nothing.

An SNS topic with zero subscriptions returns `200` with a `MessageId` and drops the message.
A subscription whose `SubscriptionArn` is the literal string `PendingConfirmation` sits in the
console list looking like a subscriber and delivers nothing. Both failures are silent until the
night an alarm should have paged and did not. This reads every topic, every subscription and
their attributes once, and reports the paths that cannot deliver.

## Rules

| rule | severity | condition |
| --- | --- | --- |
| `TOPIC_NO_SUBSCRIPTIONS` | high | the topic has no subscriptions at all |
| `SUBSCRIPTION_PENDING_CONFIRMATION` | high | `SubscriptionArn` is `PendingConfirmation` |
| `TOPIC_OPEN_POLICY` | high | an `Allow` statement with `Principal` `*` and no `Condition` |
| `SUBSCRIPTION_INSECURE_ENDPOINT` | medium | `Protocol` is `http` |
| `TOPIC_UNENCRYPTED` | medium | no `KmsMasterKeyId` on the topic |
| `SUBSCRIPTION_NO_DLQ` | low | confirmed `sqs`/`lambda`/`http`/`https`/`firehose` subscription with no `RedrivePolicy` |
| `TOPIC_DELIVERY_FAILURES` | high | with `--metrics-days`: `NumberOfNotificationsFailed` / `NumberOfMessagesPublished` above `--max-failure-ratio` (default `0.01`) |
| `TOPIC_UNUSED` | low | with `--metrics-days`: no message published and no delivery failed in the window |

Every finding carries the remediation: the exact `aws sns` call shape, and for the open-policy
case the condition keys that scope it back down (`aws:SourceOwner`, `aws:SourceArn`).

The last two rules read CloudWatch and only run with `--metrics-days`. They catch the case the
configuration rules cannot see: everything is subscribed and confirmed, and deliveries still
fail (a throttled Lambda, an HTTPS receiver answering 4xx).

## Install

```bash
pip install git+https://github.com/moveeeax/aws-sns-subscription-audit
```

Needs Python 3.11+ and `boto3`. Read-only IAM: `sns:ListTopics`, `sns:GetTopicAttributes`,
`sns:ListSubscriptionsByTopic`, `sns:GetSubscriptionAttributes`, plus `ec2:DescribeRegions`
for `--all-regions` and `cloudwatch:GetMetricData` for `--metrics-days`.

## Usage

```bash
aws-sns-subscription-audit --region eu-central-1
aws-sns-subscription-audit --all-regions --format json --fail-on high
aws-sns-subscription-audit --topic prod-alerts --ignore SUBSCRIPTION_NO_DLQ --show-endpoints
aws-sns-subscription-audit --region eu-central-1 --metrics-days 7 --max-failure-ratio 0.02
```

```text
SEVERITY  RULE                               REGION        TOPIC
high      TOPIC_NO_SUBSCRIPTIONS             eu-central-1  billing-orphan
    the topic has no subscriptions: a publish still returns 200 with a MessageId and the message is discarded
    fix: aws sns subscribe --region eu-central-1 --topic-arn arn:aws:sns:eu-central-1:123456789012:billing-orphan --protocol https --notification-endpoint https://<receiver>

high      SUBSCRIPTION_PENDING_CONFIRMATION  eu-central-1  oncall-email
    2 subscriptions of 2 never confirmed, delivering nothing; the topic has no confirmed subscriber at all
      - email:a***@example.com
      - email:b***@example.com
    fix: resend the confirmation and have the owner accept it: aws sns subscribe --region eu-central-1 --topic-arn arn:aws:sns:eu-central-1:123456789012:oncall-email --protocol <protocol> --notification-endpoint <endpoint>

7 findings across 4 topics (3 high, 2 medium, 2 low)
```

### Flags

| flag | meaning |
| --- | --- |
| `--profile NAME` | AWS profile |
| `--region REGION` | region to scan, repeatable; defaults to the session region |
| `--all-regions` | every region enabled for the account, from `ec2:DescribeRegions` |
| `--topic NAME_OR_ARN` | limit to these topics, repeatable |
| `--format table\|json\|csv` | output shape, default `table` |
| `--fail-on high\|medium\|low\|never` | lowest severity that exits 1, default `high` |
| `--ignore RULE,RULE` | drop rules from the output *and* the exit code |
| `--show-endpoints` | print `email` and `sms` endpoints unmasked |
| `--metrics-days DAYS` | read CloudWatch delivery metrics for the last 1 to 455 days; off by default |
| `--max-failure-ratio RATIO` | failed deliveries per published message above which `TOPIC_DELIVERY_FAILURES` fires, default `0.01`; needs `--metrics-days` |

Exit codes: `0` clean, `1` a finding at or above `--fail-on`, `2` an AWS API or credential error.

## How it works

One pass per region, nothing cached between runs:

1. `ListTopics` (paginated) gives the topics. A failure here is fatal and exits `2` — without
   the list there is nothing to audit.
2. `GetTopicAttributes` per topic carries `KmsMasterKeyId` and `Policy`.
3. `ListSubscriptionsByTopic` (paginated) per topic gives the subscriptions.
4. `GetSubscriptionAttributes` per **confirmed** subscription carries `RedrivePolicy`.
5. With `--metrics-days`, `GetMetricData` per region (250 topics per call) sums the daily
   `NumberOfMessagesPublished` and `NumberOfNotificationsFailed` from `AWS/SNS` by `TopicName`
   over the window ending now.

A failure on a single topic is reported against that topic as a `warning:` line and the scan
continues, so one restrictive resource policy does not blind the whole report. A denied
`GetMetricData` is a region-level `warning:`; the configuration findings are still reported and
the metric rules are skipped for that region rather than guessed.

Findings are per topic and rule, not per endpoint: a topic with six unconfirmed email addresses
is one finding listing six endpoints. Email and SMS endpoints are masked
(`a***@example.com`, `*********5678`) so a report can go into a ticket as it is.

## One note

An unconfirmed subscription has no ARN, so `GetSubscriptionAttributes` is never called for it —
the literal `PendingConfirmation` is not an address. Which also means a topic whose only
subscriptions are unconfirmed is *not* reported as an orphan: it has subscriptions, they just
do not work. That case is called out inside the pending finding instead of being double counted.

On the metrics: SNS writes no datapoint for a quiet day, so no data counts as zero, which is how
`TOPIC_UNUSED` is decided. An alarm topic can be quiet for a week by design; `--ignore TOPIC_UNUSED`
if that is the norm. The failure ratio is failed over published, as CloudWatch reports them, not
per delivery: a topic fanning out to several subscriptions, or an HTTP/S endpoint whose every retry
counts as a failure, can sit above `1.0`. That makes the ratio err towards reporting. Failures with
nothing published in the window (the publish fell just before it) are reported, not divided by zero.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Tests run offline against recorded fixtures through botocore's `Stubber`; no AWS credentials
and no network. `examples/demo.py` replays the same fixtures through the real collector and
rules:

```bash
python examples/demo.py messy      # exits 1
python examples/demo.py healthy    # exits 0
python examples/demo.py messy --metrics-days 7   # adds the CloudWatch rules
```

Regenerate the fixtures with `python examples/make_fixtures.py`; CI fails if they drift.

## License

MIT
