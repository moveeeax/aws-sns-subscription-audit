from __future__ import annotations

import csv
import io
import json

import pytest

from aws_sns_subscription_audit.cli import run


def invoke(argv, session):
    out, err = io.StringIO(), io.StringIO()
    code = run(argv, session=session, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_healthy_account_exits_zero(stubbed):
    session, _ = stubbed("healthy")
    code, out, err = invoke(["--region", "eu-central-1"], session)
    assert code == 0
    assert "no findings across 1 topics" in out
    assert err == ""


def test_messy_account_exits_one_on_high(stubbed):
    session, _ = stubbed("messy")
    code, out, _ = invoke(["--region", "eu-central-1"], session)
    assert code == 1
    assert "TOPIC_NO_SUBSCRIPTIONS" in out
    assert "SUBSCRIPTION_PENDING_CONFIRMATION" in out
    assert "TOPIC_OPEN_POLICY" in out
    assert "a***@example.com" in out
    assert "alice@example.com" not in out


def test_table_output_starts_with_a_header_and_ends_with_a_tally(stubbed):
    session, _ = stubbed("messy")
    _, out, _ = invoke(["--region", "eu-central-1"], session)
    lines = out.strip().splitlines()
    assert lines[0].split() == ["SEVERITY", "RULE", "REGION", "TOPIC"]
    assert lines[-1].startswith("7 findings across 4 topics")
    assert "high" in lines[-1] and "medium" in lines[-1] and "low" in lines[-1]
    # highest severity first
    assert lines[1].startswith("high")


def test_fail_on_high_ignores_medium_and_low(stubbed):
    """Only TOPIC_UNENCRYPTED and SUBSCRIPTION_NO_DLQ remain after the two high rules go."""
    session, _ = stubbed("messy")
    argv = ["--region", "eu-central-1", "--fail-on", "high", "--ignore",
            "TOPIC_NO_SUBSCRIPTIONS,SUBSCRIPTION_PENDING_CONFIRMATION,"
            "TOPIC_OPEN_POLICY,SUBSCRIPTION_INSECURE_ENDPOINT"]
    code, out, _ = invoke(argv, session)
    assert code == 0
    assert "TOPIC_UNENCRYPTED" in out
    assert "SUBSCRIPTION_NO_DLQ" in out


def test_fail_on_medium_exits_one_for_the_same_findings(stubbed):
    session, _ = stubbed("messy")
    argv = ["--region", "eu-central-1", "--fail-on", "medium", "--ignore",
            "TOPIC_NO_SUBSCRIPTIONS,SUBSCRIPTION_PENDING_CONFIRMATION,"
            "TOPIC_OPEN_POLICY,SUBSCRIPTION_INSECURE_ENDPOINT"]
    code, _, _ = invoke(argv, session)
    assert code == 1


def test_fail_on_never_always_exits_zero(stubbed):
    session, _ = stubbed("messy")
    code, out, _ = invoke(["--region", "eu-central-1", "--fail-on", "never"], session)
    assert code == 0
    assert "TOPIC_NO_SUBSCRIPTIONS" in out


def test_show_endpoints_unmasks(stubbed):
    session, _ = stubbed("messy")
    _, out, _ = invoke(["--region", "eu-central-1", "--show-endpoints"], session)
    assert "alice@example.com" in out


def test_json_format_is_parsable_and_counts_match(stubbed):
    session, _ = stubbed("messy")
    code, out, _ = invoke(["--region", "eu-central-1", "--format", "json"], session)
    payload = json.loads(out)
    assert code == 1
    assert payload["topics_scanned"] == 4
    assert sum(payload["counts"].values()) == len(payload["findings"])
    first = payload["findings"][0]
    assert set(first) == {"rule", "severity", "region", "topic", "topic_arn", "detail",
                          "targets", "remediation"}
    assert payload["errors"] == []


def test_csv_format_has_a_header_and_one_row_per_finding(stubbed):
    session, _ = stubbed("messy")
    _, out, _ = invoke(["--region", "eu-central-1", "--format", "csv"], session)
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0][:4] == ["severity", "rule", "region", "topic"]
    assert len(rows) == 8  # header + 7 findings


def test_unknown_rule_in_ignore_exits_two(stubbed):
    session, _ = stubbed("healthy")
    code, _, err = invoke(["--region", "eu-central-1", "--ignore", "NOPE"], session)
    assert code == 2
    assert "unknown rule" in err


def test_denied_list_topics_exits_two_without_a_traceback():
    from botocore.stub import Stubber

    from .conftest import FakeSession, sns_client

    client = sns_client()
    stubber = Stubber(client)
    stubber.add_client_error("list_topics", service_error_code="AuthorizationError",
                             service_message="denied", http_status_code=403)
    stubber.activate()
    code, out, err = invoke(["--region", "eu-central-1"],
                            FakeSession({"sns": client}))
    stubber.deactivate()
    assert code == 2
    assert err.startswith("error: ListTopics in eu-central-1 failed")
    assert "Traceback" not in err
    assert out == ""


def test_missing_region_exits_two():
    from .conftest import FakeSession

    session = FakeSession({}, region_name=None)
    code, _, err = invoke([], session)
    assert code == 2
    assert "no region" in err


def test_repeated_region_is_deduplicated(stubbed):
    session, stubber = stubbed("healthy")
    code, _, _ = invoke(["--region", "eu-central-1", "--region", "eu-central-1"], session)
    # A second pass would have drained an empty stub queue and raised.
    assert code == 0
    stubber.assert_no_pending_responses()


@pytest.mark.parametrize("fmt", ["table", "json", "csv"])
def test_every_format_renders_the_healthy_account(stubbed, fmt):
    session, _ = stubbed("healthy")
    code, out, _ = invoke(["--region", "eu-central-1", "--format", fmt], session)
    assert code == 0
    assert out
