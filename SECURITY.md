# Security policy

## Reporting a vulnerability

Report privately through GitHub: open the **Security** tab of this repository and
choose **Report a vulnerability**. That opens a private advisory visible only to you
and the maintainers.

Please do not open a public issue for anything in the list below. Reeve is deployed to
decide whether an action is permitted, so a public report is a working description of
how to get past someone's controls before they have a fix.

You should get an acknowledgement within a week. This is a pre-alpha project
maintained in spare time, so please set your expectations for a fix accordingly; if
something is serious and unfixed, you are welcome to say so publicly after 90 days.

## What counts as a vulnerability here

This project exists to stop invisible failures, so the bar is different from a typical
library. Any of these is a vulnerability, not a bug:

- **The guard allows an action the policy denies.** Including by crashing, timing out,
  being handed a payload it does not understand, or replying in a shape the agent
  ignores. An agent that cannot parse a refusal treats it as no opinion and proceeds,
  so a malformed reply is an allow.
- **A rule is narrowed during compilation without being reported.** If
  `reeve policy compile` emits native configuration that enforces less than the rule
  it came from, and the coverage report calls it `native`, that is an operator being
  told they are covered when they are not.
- **A control is reported as present when it is not.** A scan that reports an
  administrator lock a developer can override, or a managed file that enforces
  nothing, closes a question with the wrong answer and nobody looks again.
- **Prompt or response content reaches the event store or the metrics endpoint.**
  Whatever an agent is configured to send, this must never be recorded.
- **A credential value is read into a report, a log, an event or a metric label.**
  Variable names, header names and server names are evidence and are recorded. The
  values never are.
- **Identity appears in the metrics endpoint.** Emails, subjects, sessions and
  repository names belong in the access-controlled event store, not in a system with
  different retention and wider read access.
- **An unbounded label from a client-controlled value.** Anything that lets a sender
  mint a new Prometheus time series per request can take down the monitoring that was
  meant to watch the agents.
- **Privilege or path handling** that lets an unprivileged user influence what an
  administrator-owned file is read as.

## What is out of scope

- The absence of a control a vendor does not offer. Reeve reports these; it cannot
  create them. Cursor having no administrator-owned settings file is a finding, not a
  vulnerability in Reeve.
- Findings you disagree with. Open an issue: every finding is meant to be arguable,
  and the reasoning is in the finding itself.
- Vulnerabilities in the agents Reeve reads. Report those to the vendor. If Reeve
  *misreports* one, that is in scope under the third bullet above.
- Anything requiring an attacker who can already write to the administrator-owned
  configuration or replace the `reeve` binary. At that point the machine is theirs.

## Supported versions

Pre-alpha: only the current `main` branch is supported. There are no maintained
release branches yet, and no backports.
