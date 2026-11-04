# aws-sns-subscription-audit
Audits every SNS topic and subscription for the alerting paths that fail silently: topics with zero subscriptions, subscriptions stuck in PendingConfirmation, plaintext HTTP endpoints, unencrypted topics, wildcard access policies and subscriptions with no redrive policy.
