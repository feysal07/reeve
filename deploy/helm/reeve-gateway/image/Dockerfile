# The gateway is part of the claude binary. There is no published gateway image, so you
# build this one around a binary you downloaded yourself:
#
#   1. Download the Linux build for your architecture from a pinned Claude Code release
#      (https://code.claude.com/docs/en/setup#install-a-specific-version).
#   2. Verify it against the release's GPG-signed manifest.json
#      (https://code.claude.com/docs/en/setup#binary-integrity-and-code-signing).
#   3. Put it beside this file as ./claude, then:
#
#        docker build -t registry.internal/claude-gateway:<version> .
#
# Deliberately no download step here. A Dockerfile that fetched the binary would bake
# in whatever the release host served on the day, unverified, and would put Anthropic's
# binary into an image this project does not and must not publish.

# glibc, which the native build needs; nonroot, with nothing else in it.
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --chmod=0555 claude /usr/local/bin/claude

# Minimal images have no writable home; the chart mounts an emptyDir here.
ENV CLAUDE_CONFIG_DIR=/tmp/.claude

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/claude"]
CMD ["gateway", "--config", "/etc/claude/gateway.yaml"]
