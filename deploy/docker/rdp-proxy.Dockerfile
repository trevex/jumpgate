# syntax=docker/dockerfile:1
FROM rust:1 AS build

# The mesh crate's build.rs generates gRPC stubs: it runs `buf export` (to
# materialize the proto closure incl. the protovalidate BSR dep) and then
# tonic-build/protoc to compile them. Both `buf` and `protoc` must be present.
# The well-known-type .proto files (google/protobuf/*) ship in libprotobuf-dev
# under /usr/include; PROTOC_INCLUDE points prost-build's protoc invocation at
# them since the build.rs only passes the buf-exported closure as an include.
RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler libprotobuf-dev ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
ENV PROTOC_INCLUDE=/usr/include
ARG BUF_VERSION=1.50.0
RUN curl -fsSL "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-$(uname -s)-$(uname -m)" \
      -o /usr/local/bin/buf \
 && chmod +x /usr/local/bin/buf

WORKDIR /src
COPY . .
# rdp-proxy is its own cargo workspace (excluded from the root workspace; see
# workers/rdp-proxy/Cargo.toml), so it can't be built with `-p rdp-proxy` from
# the root manifest — it needs its own manifest path and lands in its own
# target dir, not /src/target.
RUN cargo build --release --manifest-path workers/rdp-proxy/Cargo.toml

FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/workers/rdp-proxy/target/release/rdp-proxy /usr/local/bin/rdp-proxy
ENTRYPOINT ["/usr/local/bin/rdp-proxy"]
