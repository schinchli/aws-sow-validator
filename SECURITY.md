# Security Policy

## Reporting a Vulnerability

If you discover a potential security issue in this project, please do **not**
create a public GitHub issue. Instead, report it privately via
[GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository.

Please include the steps to reproduce, the affected component, and the impact
you believe the issue has.

## Scope and expectations

This is a sample application intended for evaluation and as a starting point for
your own deployment. It is not a managed service. Before running it with real
customer data, review at minimum:

- **Sign-up allowlist.** The hosted demo restricts sign-up via a Cognito
  PreSignUp Lambda trigger. A fork defaults to the same allowlist; set
  `-c signupAllowed=""` deliberately if you intend open sign-up, and understand
  that this means anyone can consume your Amazon Bedrock spend.
- **Prompt injection.** Documents are untrusted input. Enable
  [Amazon Bedrock Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html)
  before processing documents you did not author.
- **Cost exposure.** The agent path invokes Amazon Bedrock. The per-user run
  quota and AWS WAF rate limiting are the controls that bound this. Removing
  either exposes your account to unbounded spend.
- **Data retention.** Uploaded document text transits the Lambda and may appear
  in CloudWatch Logs depending on your log level. Review log retention before
  processing confidential material.

## What this project does deliberately

- The Lambda has **no public URL** — it is reachable only via CloudFront using
  Origin Access Control.
- IAM grants are scoped to specific resource ARNs rather than wildcards.
- The agent's Gateway runs a Cedar policy engine in `ENFORCE` mode, making
  read-only tool access a platform constraint rather than a prompt instruction.
- Recommendation URLs are validated against an AWS-domain allowlist at import
  time; a test asserts the rejection list is empty, so a bad URL fails CI.
