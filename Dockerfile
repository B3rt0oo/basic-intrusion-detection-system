ARG GO_VERSION=1.22
FROM golang:${GO_VERSION}-bookworm AS build

ARG BUILD_TAGS=""
WORKDIR /src
COPY . .
# Optional native deps for pcap builds
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/* || true
RUN cd cmd/ids && \
    CGO_ENABLED=1 GOFLAGS="-trimpath" go build -tags="${BUILD_TAGS}" -o /out/ids

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ids /usr/local/bin/ids
ENTRYPOINT ["/usr/local/bin/ids"]
CMD ["-config", "/etc/ids/config.json"]

