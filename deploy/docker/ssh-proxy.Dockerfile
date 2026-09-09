# syntax=docker/dockerfile:1
FROM rust:1@sha256:bf5a9aa29062a6cb03c49bd59a46eb55e3cc770caf598a221a7866e500be3082 AS build

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
RUN cargo build --release -p ssh-proxy

# distroless/cc ships glibc + libgcc + ca-certificates and runs as uid 65532
# (the :nonroot tag), so no apt step and no explicit USER are needed.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/ssh-proxy /usr/local/bin/ssh-proxy
ENTRYPOINT ["/usr/local/bin/ssh-proxy"]
