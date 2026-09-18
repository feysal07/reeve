# What stays free, forever

This page is a commitment, published before the project had a single user, so that it
cannot be quietly walked back later.

Every capability listed below is Apache-2.0 licensed and will remain free for unlimited
developers in a single organisation, self-hosted, with no seat cap and no feature flag.
Features may be **added** to the paid tiers. Nothing listed here will ever be **moved**
into them.

## Free, forever

- **The scan command.** Discovery of installed agents, their versions, their effective
  permissions, configured MCP servers, installed hooks, and telemetry configuration.
- **Every agent adapter.** No adapter will ever be paid-only. If Reeve supports an agent,
  it supports it in the free edition.
- **The policy compiler.** Authoring policy once and compiling it to each vendor's native
  locked configuration.
- **The local policy agent.** Hook-based enforcement, fail-closed evaluation, and the
  policy bundle format.
- **Single sign-on.** OIDC login and group-based policy, against any compliant identity
  provider. Authentication is not a premium feature.
- **The telemetry pipeline.** Collector configuration, normalisation to a common event
  model, cost computation, dashboards and alert rules.
- **The audit store**, with a viewer and a default retention window.
- **The MCP registry**, including inventory and allow-lists.
- **Deployment.** Container images and Helm charts for everything above.

## What is intended to be paid

Stated here for honesty, not as a commitment to build any of it.

Paid tiers are expected to cover capabilities that only matter once an organisation is
large or regulated: provisioning and fine-grained role management, managing many
organisations from one console, long-term and tamper-evident audit retention with legal
export, connectors into commercial security platforms, packaged compliance evidence,
cross-agent chargeback reporting, approval workflow, and commercial support.

## If this changes

If a future version of this project ever removes something from the list above, the
commit that does it will be a lie, and you are entitled to say so publicly. The last
release before such a change will remain Apache-2.0 and forkable, permanently.
