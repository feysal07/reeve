# Contributing to Reeve

## Sign-off (DCO), not a CLA

Contributions are accepted under the
[Developer Certificate of Origin](https://developercertificate.org/). There is no
Contributor Licence Agreement and no copyright assignment. You keep the copyright in
your contribution; it is licensed to the project under Apache-2.0, the same licence the
project ships under.

Sign each commit:

```
git commit -s -m "your message"
```

This appends a `Signed-off-by` trailer, which certifies that you wrote the code or have
the right to submit it under the project's licence.

## Why no CLA

A CLA would let the project relicense your work later. Reeve does not need that right,
because paid functionality is developed in a separate repository and no contributed code
is ever relicensed. See [docs/FREE-FOREVER.md](docs/FREE-FOREVER.md).

## Writing an agent adapter

Adapters are the most valuable contribution. An adapter teaches Reeve how one agent
stores its configuration, what its hook protocol looks like, and what telemetry it emits.
Each adapter implements the interface in `internal/adapter` and ships with a contract
test pinned to specific agent versions, because vendors change these formats frequently.

## Ground rules

- Discovery is read-only. The scan command must never modify an agent's configuration.
- Enforcement fails closed. If policy cannot be evaluated, the answer is deny.
- No telemetry leaves the machine unless the operator configured a destination.
- Prompt and response content is never captured by default.
