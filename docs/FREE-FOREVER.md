# What stays free, forever

This page is a commitment, published before the project had a single user, so that it
cannot be quietly walked back later.

Every capability listed below is Apache-2.0 licensed and will remain free for unlimited
developers in a single organisation, self-hosted, with no seat cap and no feature flag.
Features may be **added** to the paid tiers. Nothing listed here will ever be **moved**
into them.

## Free, forever

Most of this exists today. Some of it does not, and is marked, because a commitment
about something unbuilt is still a commitment and should not be mistaken for a feature
list. **Planned** means it has not been written yet; it does not soften the promise.

- **The scan command.** Discovery of installed agents, their versions, their effective
  permissions, configured MCP servers, installed hooks, and telemetry configuration.
- **Every agent adapter.** No adapter will ever be paid-only. If Reeve supports an agent,
  it supports it in the free edition.
- **The policy compiler.** Authoring policy once and compiling it to each vendor's native
  locked configuration, including the coverage report that says which rules the target
  cannot carry.
- **The local policy agent.** Hook-based enforcement, fail-closed evaluation, and the
  policy bundle format.
- **The telemetry pipeline.** Collector, normalisation to a common event model, cost
  computation at your own rates, team attribution, and the Prometheus metrics the
  collector reports about itself. Dashboards and alert rules: alert rules ship with the
  Helm chart, dashboards are *planned*.
- **The audit store.** The event and decision record, retained for as long as you
  configure and no less. Reeve will never shorten what the free edition keeps, or gate
  reading back what it has already written. A viewer for it is *planned*.
- **The MCP inventory and allow-lists.** What each agent is connected to, and the
  administrator-owned lists that restrict it. A registry with its own interface is
  *planned*.
- **Single sign-on.** OIDC login and group-based policy, against any compliant identity
  provider. Authentication is not a premium feature. *Planned*, and the most expensive
  promise on this page, which is the reason for making it in writing rather than
  deciding later under revenue pressure.
- **Deployment.** Container images and Helm charts for everything above.

## What is intended to be paid

Stated here for honesty, not as a commitment to build any of it.

Paid tiers are expected to cover capabilities that only matter once an organisation is
large or regulated: user provisioning and fine-grained role management, managing many
organisations from one console, tamper-evident audit retention with legal export,
connectors into commercial security platforms, packaged compliance evidence, approval
workflow, and commercial support.

Two boundaries on that list are thin enough to be worth stating plainly, so nobody has
to infer them later. Logging in and mapping a group to a policy is free; provisioning
accounts and defining custom roles is not. Knowing what something cost, per team and per
repository, is free; the billing-grade reporting an organisation recharges against is
not.

## If this changes

If a future version of this project ever removes something from the list above, the
commit that does it will be a lie, and you are entitled to say so publicly. The last
release before such a change will remain Apache-2.0 and forkable, permanently.
