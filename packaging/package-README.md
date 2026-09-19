# Reeve __VERSION__

A vendor-neutral, self-hosted control plane for AI coding agents.

## Start here

    ./reeve scan

Reads the configuration of every AI coding agent on this machine and reports what each
one is allowed to do: which settings came from a file an administrator owns and which
from one the developer can edit, what each agent may read, write, execute and reach,
which MCP servers it is connected to, and whether anything it does is recorded.

It is read-only. It makes no network calls and never modifies an agent's files.

    ./reeve scan --fail-on high

Exits non-zero when anything at or above that severity is found, which makes it usable
as a CI gate.

## Then

    ./reeve policy check   baseline-policy.yaml
    ./reeve policy test    baseline-policy.yaml --command "rm -rf /var"
    ./reeve policy compile baseline-policy.yaml --out ./dist --platform linux

`compile` renders the same policy as each agent's own administrator-owned
configuration. Read the coverage report it prints rather than just the files: native
configuration cannot express everything a policy can, and the report says which rules
a given agent has to leave to the guard rather than dropping them quietly.

## Verifying this download

    sha256sum -c checksums.txt
    gh attestation verify reeve-linux-amd64.tar.gz --repo feysal07/reeve

The checksum proves the file arrived intact. The attestation proves which workflow,
from which commit, produced it.

## Documentation

https://github.com/feysal07/reeve

Apache-2.0. See LICENSE.
