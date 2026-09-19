# Build the collector as a static binary and ship it on a base with no shell.
#
# The image exists only so `reeve collect` can run in a cluster. Everything else
# Reeve does runs on a developer's machine or a CI runner, where the single binary
# is the point and a container would be in the way.

FROM golang:1.25-alpine AS build

WORKDIR /src

# Dependencies first, so a source-only change does not re-download them.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev

# CGO_ENABLED=0 is what makes the result runnable on a base with no libc.
# -trimpath keeps the build machine's paths out of the binary, so the same source
# produces the same bytes wherever it is built.
RUN CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/reeve ./cmd/reeve

# Prove the binary runs before it is copied into an image with no shell to debug in.
RUN /out/reeve version

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/reeve /usr/local/bin/reeve

# The collector writes an append-only audit file. Nothing else in the image is
# written to, so the root filesystem can be mounted read-only.
VOLUME ["/var/lib/reeve"]

# 4318 is the OTLP over HTTP port, and it is deliberately not moved. An agent's
# exporter looks there by default, so keeping it is what lets an agent find this
# collector without being configured to. Inside a container it can never clash: the
# namespace holds nothing else. On a host that already runs a collector, remap it
# rather than changing it, with -p 14318:4318.
EXPOSE 4318

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/reeve"]
CMD ["collect", "--addr=0.0.0.0:4318", "--store=/var/lib/reeve/events.jsonl"]
